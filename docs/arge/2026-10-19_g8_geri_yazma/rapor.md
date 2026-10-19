# G8 geri yazma prototipi: sonuç raporu

- **Tarih:** 2026-10-19
- **Plan kalemi:** plan v2 §5 G8, "G8 karar kuralları"; §2 madde 4.
- **Ön kayıt:** `onkayit.md`, ölçümden önce 12:05'te yazıldı ve mühürlendi (SHA-256 `0e472e23…305a2f42`). Sapmalar `onkayit_notlari.md`'de; hiçbiri seçimi, ölçütü ya da eşiği değiştirmedi.
- **Künye:**
  - Ghidra 12.1.2 PUBLIC (`application.revision.ghidra` c0f584bf229f…), `~/Library/BlackWidowBuild/ghidra_12.1.2_PUBLIC`
  - pyghidra 3.0.0, Python 3.12.7, JVM yığını 6144 MB
  - depo 62ad154 (taban ve seçim) ve f530685 (ölçüm); arada deneyin kullandığı kod değişmedi
  - analiz girdisi `apple_strip/tmux`, sha256 `10fa0411…c9997b7`
  - gerçek isimler `orig/tmux` (Homebrew tmux 3.8 şişesi), sha256 `dfbb8c54…c629998b`
  - yalnız geliştirme setindeki tmux kullanıldı; test seti (`test_seti_kilidi.md`) ve stres alt kümesindeki programlara dokunulmadı

## Özet

- **Soru.** Gerçek kaynaktan alınan ad, prototip ve tek bir yapının yerleşimi Ghidra'ya geri yazılıp yeniden decompile edilirse okunurluk ölçütleri ne kadar iyileşir? Bilgi kaynaktan geldiği için ölçülen değer bir **üst sınırdır**, Karadul'un bugünkü başarısı değildir.
- **Karar (ön kayıtlı kural).** Ana koşulda (C3: ad + prototip + `struct window_pane`) 20 hedef fonksiyonda 5 birincil ölçütün **3'ünde** anlamlı kazanç var: `undefined*`, ham işaretçi aritmetiği ve `->` erişimi. Kural en az 2 istiyor; planın adıyla andığı iki ölçüt (U ve P1) de birlikte tuttu. **Sonuç: "geri yazma kazancı var".**
- **Etki büyüklüğü (hedefler, havuzlanmış 100 satır oranı).**
  - `undefined*`: 12,5 → 6,1 (−%52).
  - Ham işaretçi aritmetiği: 19,0 → 9,4 (−%50); 20 fonksiyonun 19'unda azaldı.
  - `->` erişimi: 0 → 11,0.
  - Tip dönüşümü −%8 ve varsayılan ad −%24 eşiği (%25) geçemedi. Varsayılan adın güven aralığı sıfırı dışlıyor ama göreli değişim eşiğin 0,8 puan altında kaldı.
- **Kazanç yerleşimden geliyor, prototipten değil.**
  - Yalnız ad (C1) ölçütleri değiştirmiyor; yalnız `FUN_` yoğunluğu düşüyor.
  - Yerleşimsiz prototip (C2: yapılar opak) ham aritmetiği düşürmüyor (+%4). Tip dönüşümünü ise **%27 artırıyor** (20 fonksiyonun 14'ünde arttı).
  - Yerleşim eklenince (C3) ham aritmetik yarıya iniyor.
  - Erişilebilir bütün yapılar tam olunca (C4) ham aritmetik −%85.
- **Etki çağıranlara yayılıyor.** Yalnız 20 prototip ve 1 yapı yazıldı. Buna rağmen 49 doğrudan çağıranın 34'ünde `->` belirdi (toplam 605 erişim) ve ham aritmetik −%24 azaldı. Decompiler, hedefin prototipindeki tipi çağıranın kendi değişkenlerine ve parametresine taşıyor.
- **Maliyet küçük.**
  - Bütün geri yazma 0,04 sn sürdü. Başlık ayrıştırma 0,6 sn, ön işleme 0,1 sn.
  - Yeniden decompile, sırası dengelenmiş ek ölçümle hedeflerde 1,68 kat (20 fonksiyon: 50 ms → 84 ms), çağıranlarda 1,08 kat sürüyor.
- **Yerleşim doğrulandı.**
  - Ghidra'nın C ayrıştırıcısıyla elde edilen `window_pane` yerleşimi (1760 bayt, 75 alan) ve değerle gömdüğü 16 adlı yapı, `-g` derlemenin DWARF'ıyla birebir aynı.
  - İkilide `xcalloc(1, 0x6e0)` var.
  - 20 fonksiyonun bellek erişim ofsetleri şişe ile kendi derlememizde aynı.

## 1. Yöntem

### 1.1 Seçim

- **Yapı.** Kural: derlenen 144 `.c` dosyasında `struct X *` en çok geçen yapı. Seçilen: `struct window_pane` (594 geçiş; ikinci `client`, 560). Gerekçe ve şeffaflık notu `onkayit.md` §2'de.
- **Aday havuzu.** İlk parametresi `struct window_pane *` olan 125 tanım vardı. Ön kayıt §3 (a)-(d) sonrası 108 aday kaldı: 17'si şişede `T`/`t` sembolü olarak yok (büyük olasılıkla satır içine gömülmüş ya da bağlayıcı tarafından atılmış).
- **Sıra.** Adaylar adrese göre sıralandı, sonra tohumla karıştırıldı (`789d46a7d25a80c2`). Karışık sıradaki ilk 20'nin hepsi (e) ve (f)'yi sağladı; elenen olmadı.
- **Hedeflerin dosya dağılımı:** window.c 11, layout.c 4, window-copy.c 2, cmd-swap-pane.c, cmd.c ve screen-write.c birer.
- **Çağıranlar.** Taban programda 20 hedefe CALL başvurusu olan, hedef olmayan 49 fonksiyon.

### 1.2 Taban

Strip'li tmux yeni bir Ghidra projesine alındı ve varsayılan analizörlerle analiz edildi. Bu, Karadul'un `pyghidra.open_program(analyze=True)` yoluyla aynıdır.
- Dil `AARCH64:LE:64:AppleSilicon`, derleyici tanımı `default`.
- Analiz 16 sn sürdü.
- 3043 fonksiyon çıktı: 2587'si `FUN_`, 233'ü thunk.

### 1.3 Koşullar

Her koşul taban projenin ayrı bir kopyasında koşuldu (`workspaces/2026-10-19_g8/projeler/C0…C4`). Yeniden analiz yapılmadı.

| Koşul | Yazılan |
|---|---|
| C0 | hiçbir şey |
| C1 | 20 fonksiyona `Function.setName` (USER_DEFINED) |
| C2 | C1 + `ApplyFunctionSignatureCmd` ile gerçek prototip; erişilebilir bütün struct/union tipleri içi boş yer tutucu |
| **C3** | C2 + `window_pane` ve değerle gömdüğü yapılar tam yerleşimle (kapanış: `window_pane` dahil 30 bileşik tip); yalnız işaretçiyle erişilen yapılar boş |
| C4 | C2 + erişilebilir bütün yapılar tam (kaynakta da opak olan 27'si hariç) |

**Tiplerin programa yazılışı.**
1. Bu koşulda içi boş kalacak her yapı için, programın tip yöneticisine aynı yol ve adla bir yer tutucu yazılır.
2. Tam tipler `DataTypeConflictHandler.KEEP_HANDLER` ile çözülür. Böylece tam bir yapının işaretçi alanları var olan yer tutucuya bağlanır.
3. Prototipler aynı işleyiciyle çözülür ve `ApplyFunctionSignatureCmd(..., preserveCallingConvention=true, FunctionRenameOption.NO_CHANGE)` ile uygulanır.

**Denetim (her koşulda `tip_denetimi`).**
- 20/20 prototip uygulandı; imza kaynağı `USER_DEFINED`.
- Beklenmeyen tip yok; yeni `.conflict` tipi oluşmadı.
- `timeval` ve `termios` tabanda zaten vardı. Analiz bunları Ghidra'nın `mac_osx.gdt` arşivinden getirmiş; boyutları ayrıştırılanla aynı (16, 72).

`HighFunctionDBUtil` gerekmedi: decompiler uygulanan prototipi kullandı.

### 1.4 Tip ve prototip kaynağı

**Yol 1 başarılı oldu; DWARF yerleşimi yalnız doğrulamada kullanıldı.**

1. tmux 3.8, Homebrew formülünün seçenekleriyle yapılandırıldı: `--enable-sixel --enable-utf8proc`, jemalloc otomatik. Bağımlılıklar şişeyle aynı sürümde: libevent 2.1.13, ncurses 6.6, utf8proc 2.12.0, jemalloc 5.4.0.
2. `tmux.h` ve hedeflerin kaynaktaki tanım imzaları tek bir çeviri biriminde, gerçek derlemenin `window.c` komut satırındaki bütün `-D`/`-I` bayraklarıyla `clang -E` ile ön işlendi. SDK `MacOSX.sdk` 27.0 (şişe SDK 26.5 ile derlenmiş; ilgili tiplerin yerleşimi aşağıda doğrulandı).
3. Metin Ghidra'nın `CParser`'ıyla, hedef programın veri düzeniyle kurulan bir `StandAloneDataTypeManager`'a ayrıştırıldı (0,6 sn).
4. Ayrıştırıcının tanımadığı ama yerleşimi etkilemeyen sözdizimi için şu uyarlamalar gerekti (`onkayit_notlari.md` #3):
   - ön işlemede `-fno-blocks`; boşluk niteleyicileri (`_Nullable` vb.) boş tanımlandı
   - `__builtin_va_list` → `char *`
   - `restrict` silindi
   - 410 `__attribute__` silindi; aralarındaki `packed` ve `aligned` ayrıştırmadan sonra tipe yeniden uygulandı
   - 128 bitlik iki tip önceden tanımlandı
5. tmux.h aynı fonksiyonları parametre adı olmadan bildirdiği için tanım imzaları `g8__` önekiyle ayrıştırılıp gerçek ada çevrildi.

**Ghidra'nın C ayrıştırıcısı `__attribute__((packed))`'ı okuyup atıyor, yapıya uygulamıyor.** Ghidra 12.1.2 kaynağında (`CParser.java`, `StructOrUnionSpecifier`) paketleme yalnız `#pragma pack`'ten geliyor. `packed_sinama.py` bunu doğrudan ölçüyor:
- `grid_extd_entry` 23 bayt yerine 24 çıkıyor.
- `grid_cell_entry` 5 yerine 8 çıkıyor.
- Aynı alanlar `#pragma pack(1)` ile sarılınca 23 çıkıyor.

Bu deneyde öznitelikler ayrıca uygulandı. Ürün hattında bu ayrı ele alınmazsa paketli yapılar sessizce yanlış yerleşir.

### 1.5 Ölçüm

- **Ölçütler.** Ön kayıt §5 ve `olcut.py`: U, P1, P2, C, A, D, G, F, satır, süre.
- **Decompile ayarları.** Karadul'unkiyle aynı: `DecompileOptions()` varsayılanı, fonksiyon başına 30 sn.
- **Düzen.** Her koşulda yeni bir `DecompInterface` açıldı, 5 fonksiyonla ısınıldı. Her fonksiyon iki kez decompile edildi.
- **Belirlenimcilik.** 345 fonksiyon-koşul çiftinin hepsinde iki metin aynı. Başarısız decompile yok.

## 2. Yerleşim doğrulaması

| Denetim | Sonuç |
|---|---|
| `window_pane` boyutu ve 75 alanın ofseti ↔ DWARF (kendi `-g -Os` derlememizin dSYM'i) | birebir eşit (1760 bayt) |
| Kapanış (değerle gömülen 30 bileşik tip) | 16 adlı yapının hepsi eşit. Bunlar: `event`, `event_callback`, `timeval`, `grid_cell`, `utf8_data`, `screen`, `style`, `colour_palette` ve öbürleri. 14 adsız yapı/birlik (TAILQ/RB girdileri, libevent'in adsız birlikleri) adla eşlenemedi; üst yapıdaki ofsetleri ve üst yapının boyutu eşit, iç yerleşimleri ayrıca denetlenmedi |
| tmux.h'deki 164 bileşik tip | Tanımlı 83'ün hepsi eşit, farklı 0. 43'ü tmux.h'de yalnız ileri bildirim (tanımı .c dosyasında); 38'i adsız ya da DWARF'ta yok |
| İkilide boyut | Şişedeki `window_add_pane` içinde `mov w1, #0x6e0` + `bl _xcalloc` (oluşturucu satır içine gömülmüş) |
| 20 hedefin ikilideki bellek erişim ofsetleri ↔ kendi derlememiz | 20/20 fonksiyonda ofset kümeleri aynı (Jaccard 1,0; yığın ve çerçeve erişimleri hariç) |

Ayrıntı: `yerlesim_dogrulama.json`, `workspaces/2026-10-19_g8/veri/ikili_kanit.json`.

## 3. Sonuçlar

**Anlamlı kazanç** iki koşulu birlikte ister:
- Eşli farkın ortalamasının %95 bootstrap güven aralığı (10 000 yeniden örnekleme) sıfırı iyileşme yönünde dışlar.
- Havuzlanmış oran (toplam sayı / toplam satır × 100) en az %25 iyileşir.

Ham değerler `sonuc.json`'da.

### 3.1 Ana karşılaştırma: C3 ↔ C0

**20 hedef fonksiyon**

| Ölçüt | Ort. önce | Ort. sonra | Eşli fark [%95 GA] | Havuz önce → sonra (göreli) | İyi / kötü / aynı | Anlamlı kazanç |
|---|---|---|---|---|---|---|
| U/100 | 10,1 | 2,5 | −7,6 [−12,0; −3,7] | 12,5 → 6,1 (−52%) | 13/2/5 | **evet** |
| P1/100 | 27,1 | 12,0 | −15,2 [−20,9; −10,1] | 19,0 → 9,4 (−50%) | 19/0/1 | **evet** |
| C/100 | 31,0 | 24,4 | −6,6 [−11,1; −2,4] | 24,6 → 22,6 (−8%) | 13/5/2 | hayır |
| A/100 | 0,0 | 17,1 | +17,1 [+11,6; +23,3] | 0,0 → 11,0 (taban 0) | 20/0/0 | **evet** |
| D/100 | 107,1 | 70,0 | −37,1 [−46,0; −28,6] | 115,8 → 87,8 (−24%) | 20/0/0 | hayır |
| P2/100 | 27,1 | 12,0 | −15,2 [−20,9; −10,1] | 19,0 → 9,4 (−50%) | 19/0/1 | (ikincil) |
| G/100 | 17,0 | 11,1 | −5,9 [−7,6; −4,2] | 13,3 → 10,1 (−24%) | 20/0/0 | (ikincil) |
| F/100 | 15,4 | 9,4 | −5,9 [−7,6; −4,3] | 11,1 → 7,8 (−29%) | 20/0/0 | (ikincil) |

**49 doğrudan çağıran** (ikincil sonuç; karar buna dayanmaz)

| Ölçüt | Ort. önce | Ort. sonra | Eşli fark [%95 GA] | Havuz önce → sonra (göreli) | İyi / kötü / aynı | Anlamlı kazanç |
|---|---|---|---|---|---|---|
| U/100 | 10,3 | 7,3 | −3,0 [−4,1; −2,0] | 8,3 → 6,8 (−19%) | 38/3/8 | hayır |
| P1/100 | 23,7 | 18,1 | −5,6 [−7,6; −3,8] | 22,4 → 16,9 (−24%) | 38/1/10 | hayır |
| C/100 | 29,2 | 27,4 | −1,8 [−4,0; +0,2] | 31,1 → 28,1 (−10%) | 24/21/4 | hayır |
| A/100 | 0,0 | 6,8 | +6,8 [+4,4; +9,5] | 0,0 → 7,1 (taban 0) | 34/0/15 | **evet** |
| D/100 | 117,4 | 108,1 | −9,3 [−13,0; −5,9] | 121,3 → 115,7 (−5%) | 33/7/9 | hayır |
| P2/100 | 24,2 | 18,5 | −5,7 [−7,8; −3,8] | 22,9 → 17,3 (−25%) | 38/1/10 | (ikincil) |
| G/100 | 22,1 | 20,2 | −1,8 [−2,4; −1,3] | 21,4 → 20,6 (−4%) | 48/1/0 | (ikincil) |
| F/100 | 17,1 | 15,2 | −1,8 [−2,3; −1,4] | 15,0 → 14,2 (−5%) | 48/1/0 | (ikincil) |

Çağıranların toplamları (C0 → C3 → C4):
- satır 8468 → 8513 → 8518
- U 706 → 577 → 542
- P1 1898 → 1441 → 1286
- C 2631 → 2389 → 2325
- A 0 → 605 → 804
- D 10274 → 9853 → 9851
- `FUN_` 1272 → 1209 → 1209

### 3.2 Ablasyon

**20 hedef fonksiyon, havuzlanmış 100 satır oranı**

| Koşul | U | P1 | C | A | D | F | Satır (toplam) | Decompile medyanı (ms)¹ | Anlamlı kazanç (5'te) |
|---|---|---|---|---|---|---|---|---|---|
| C0 taban | 12,5 | 19,0 | 24,6 | 0,0 | 115,8 | 11,1 | 622 | 2,5 | — |
| C1 ad | 12,5 | 18,9 | 24,5 | 0,0 | 115,4 | 7,9 | 624 | 1,9 | 0 |
| C2 ad + prototip | 9,6 | 19,8 | **31,3** | 0,0 | 86,9 | 7,8 | 626 | 1,9 | 0 |
| C3 ad + prototip + yapı | 6,1 | 9,4 | 22,6 | 11,0 | 87,8 | 7,8 | 625 | 3,4 | 3 |
| C4 ad + prototip + bütün yapılar | 4,9 | 2,8 | 17,0 | 18,1 | 88,3 | 7,7 | 634 | 6,0 | 4 |

**49 doğrudan çağıran, havuzlanmış 100 satır oranı**

| Koşul | U | P1 | C | A | D | F | Satır (toplam) | Decompile medyanı (ms)¹ | Anlamlı kazanç (5'te) |
|---|---|---|---|---|---|---|---|---|---|
| C0 taban | 8,3 | 22,4 | 31,1 | 0,0 | 121,3 | 15,0 | 8468 | 9,2 | — |
| C1 ad | 8,3 | 22,4 | 31,1 | 0,0 | 121,3 | 14,3 | 8471 | 8,3 | 0 |
| C2 ad + prototip | 8,2 | 22,8 | 32,5 | 0,0 | 116,0 | 14,3 | 8480 | 8,1 | 0 |
| C3 ad + prototip + yapı | 6,8 | 16,9 | 28,1 | 7,1 | 115,7 | 14,2 | 8513 | 9,8 | 1 |
| C4 ad + prototip + bütün yapılar | 6,4 | 15,1 | 27,3 | 9,4 | 115,6 | 14,2 | 8518 | 12,4 | 2 |

¹ Ön kayıtlı süre ölçümü. Koşullar aynı süreçte C0 → C4 sırasıyla ölçüldü. Tip yazılmayan C1'in C0'dan hızlı çıkması ilk koşulun ısınmadan etkilendiğini gösteriyor.

Sırası dengelenmiş ek ölçüm (`sure_ek.py`; iki blok, ters sıra, fonksiyon başına 6 ölçümün medyanı) sonuçları:

| Küme | C0 | C1 | C3 | C4 |
|---|---|---|---|---|
| 20 hedef | 50 ms | 50 ms | 84 ms (1,68 kat) | 143 ms (2,85 kat) |
| 49 çağıran | 1150 ms | 1155 ms | 1237 ms (1,08 kat) | 1391 ms (1,21 kat) |

Maliyet hesabında bu sayılar esas alınmalı.

### 3.3 Dağılım (hedefler, fonksiyon başına 100 satır oranı)

| Ölçüt | C0 medyan [Ç1; Ç3] | C3 medyan [Ç1; Ç3] | C0 en az–en çok | C3 en az–en çok |
|---|---|---|---|---|
| U/100 | 8,8 [1,1; 11,5] | 0,0 [0,0; 4,5] | 0,0–46,5 | 0,0–24,5 |
| P1/100 | 27,4 [11,7; 35,2] | 5,2 [0,0; 14,9] | 0,0–66,7 | 0,0–50,0 |
| C/100 | 30,4 [17,7; 36,6] | 23,3 [15,6; 30,2] | 11,1–66,7 | 0,0–60,0 |
| A/100 | 0,0 [0,0; 0,0] | 12,1 [7,1; 20,5] | 0,0–0,0 | 4,5–44,4 |
| D/100 | 110,8 [82,4; 132,1] | 60,3 [44,0; 94,4] | 50,0–164,3 | 0,0–139,3 |

**Hedef başına ham sayılar (C0 → C3)**

| # | Gerçek ad | Satır | U | P1 | C | A | D |
|---|---|---|---|---|---|---|---|
| 1 | `layout_resize_floating_pane_to` | 39 → 38 | 4 → 0 | 7 → 4 | 7 → 6 | 0 → 2 | 36 → 24 |
| 2 | `layout_resize_floating_pane` | 42 → 40 | 4 → 0 | 11 → 10 | 11 → 12 | 0 → 2 | 44 → 23 |
| 3 | `window_pane_set_event` | 15 → 15 | 5 → 0 | 5 → 0 | 5 → 3 | 0 → 6 | 17 → 8 |
| 4 | `window_pane_send_resize` | 12 → 12 | 0 → 0 | 2 → 0 | 2 → 0 | 0 → 2 | 6 → 3 |
| 5 | `window_copy_get_word` | 9 → 10 | 1 → 0 | 6 → 5 | 6 → 6 | 0 → 1 | 14 → 11 |
| 6 | `window_pane_cmp` | 9 → 9 | 0 → 0 | 0 → 0 | 1 → 1 | 0 → 4 | 10 → 4 |
| 7 | `cmd_swap_pane_prev_tiled_pane` | 8 → 8 | 1 → 0 | 3 → 0 | 3 → 2 | 0 → 2 | 9 → 3 |
| 8 | `window_pane_floating_overlaps` | 28 → 28 | 1 → 0 | 3 → 0 | 9 → 9 | 0 → 2 | 46 → 39 |
| 9 | `layout_spread_out` | 23 → 23 | 1 → 1 | 8 → 6 | 8 → 6 | 0 → 2 | 19 → 16 |
| 10 | `window_pane_find_up` | 88 → 89 | 1 → 5 | 8 → 4 | 15 → 19 | 0 → 4 | 117 → 113 |
| 11 | `window_pane_index` | 19 → 20 | 2 → 1 | 4 → 2 | 4 → 3 | 0 → 2 | 21 → 16 |
| 12 | `layout_close_pane` | 21 → 21 | 2 → 1 | 7 → 3 | 7 → 5 | 0 → 4 | 17 → 12 |
| 13 | `window_pane_scrollbar_show` | 22 → 22 | 3 → 0 | 8 → 1 | 8 → 1 | 0 → 8 | 18 → 6 |
| 14 | `window_pane_set_prompt` | 99 → 102 | 46 → 25 | 7 → 6 | 14 → 18 | 0 → 5 | 115 → 91 |
| 15 | `window_pane_get_bg_control_client` | 14 → 14 | 0 → 0 | 4 → 2 | 4 → 2 | 0 → 2 | 9 → 6 |
| 16 | `window_pane_find_down` | 87 → 88 | 1 → 5 | 9 → 3 | 18 → 20 | 0 → 6 | 122 → 116 |
| 17 | `screen_write_clear_dirty` | 9 → 9 | 2 → 0 | 4 → 0 | 5 → 3 | 0 → 4 | 6 → 0 |
| 18 | `cmd_mouse_at` | 44 → 42 | 2 → 0 | 13 → 7 | 17 → 13 | 0 → 6 | 58 → 33 |
| 19 | `window_pane_status_get_range` | 25 → 25 | 2 → 0 | 3 → 1 | 3 → 6 | 0 → 4 | 24 → 14 |
| 20 | `window_copy_get_line` | 9 → 10 | 0 → 0 | 6 → 5 | 6 → 6 | 0 → 1 | 12 → 11 |
| | **toplam** | 622 → 625 | 78 → 38 | 118 → 59 | 153 → 141 | 0 → 69 | 720 → 549 |

### 3.4 G8 kararı

Ön kayıtlı kural: 5 birincil ölçütün en az ikisinde anlamlı kazanç. C3 ↔ C0'da hedeflerde U, P1 ve A tuttu: **3/5, geri yazma kazancı var.** U ile P1 birlikte tuttuğu için ön kayda göre kanıt "güçlü" sayılır.

Tutmayan iki ölçüt de iyileşme yönünde ama eşiğin altında:
- D: −%24, güven aralığı sıfırı dışlıyor.
- C: −%8, güven aralığı sıfırı dışlıyor.

Eşikler sonradan değiştirilmedi.

## 4. Örnek: `layout_close_pane` önce ve sonra

Örnek seçim kuralı: C0'daki satır sayısı hedeflerin medyanına (21,5) en yakın fonksiyon.

**C0 (taban):**

```c
void FUN_10004bc58(long param_1)

{
  long lVar1;
  long lVar2;
  
  if (*(long *)(param_1 + 0x20) != 0) {
    lVar2 = *(long *)(param_1 + 0x10);
    FUN_10004a8e0(lVar2,*(long *)(param_1 + 0x20),lVar2 + 0x220);
    *(undefined8 *)(param_1 + 0x20) = 0;
    lVar1 = *(long *)(lVar2 + 0x220);
    if (lVar1 != 0) {
      if ((*(byte *)(lVar1 + 4) & 1) == 0) {
        *(undefined8 *)(lVar1 + 0x18) = 0;
        FUN_10004a138();
      }
      FUN_10004a308(lVar2,0);
    }
    FUN_1000263e4("window-layout-changed",lVar2);
    return;
  }
  return;
}
```

**C3 (ad + prototip + `struct window_pane`):**

```c
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

void layout_close_pane(window_pane *wp)

{
  long lVar1;
  window *pwVar2;
  
  if (wp->layout_cell != (layout_cell *)0x0) {
    pwVar2 = wp->window;
    FUN_10004a8e0(pwVar2,wp->layout_cell,pwVar2 + 0x220);
    wp->layout_cell = (layout_cell *)0x0;
    lVar1 = *(long *)(pwVar2 + 0x220);
    if (lVar1 != 0) {
      if ((*(byte *)(lVar1 + 4) & 1) == 0) {
        *(undefined8 *)(lVar1 + 0x18) = 0;
        FUN_10004a138();
      }
      FUN_10004a308(pwVar2,0);
    }
    FUN_1000263e4("window-layout-changed",pwVar2);
    return;
  }
  return;
}
```

Kaynaktaki karşılığı `wp->layout_cell` ve `w = wp->window`; bu iki erişim tam çıkıyor. `struct window` bu koşulda opak olduğu için `pwVar2 + 0x220` (kaynakta `&w->layout_root`) ham kalıyor; tek yapının sınırı budur. C4'te aynı satırlar `&pwVar2->layout_root`, `plVar1->flags` ve `(plVar1->g).xoff = 0` olarak çıkıyor. Uyarı yorumu ölçüte girmiyor. Çağrı kuralı `__cdecl` yapılınca yorum kalkıyor, kod aynı kalıyor (`saglamlik_cc.py`, 69/69).

**Çağırana yayılma örneği.** `window_pane_destroy` (0x10009eea8) hedef değil; deneyde ona ad ya da tip yazılmadı. Gerçek adı burada yalnız açıklama için kullanılıyor. Hedeflerden `screen_write_clear_dirty(wp)`'yi çağırıyor. Decompiler, bu çağrıdaki parametre tipinden yola çıkıp çağıranın kendi parametresini `window_pane *` yapıyor (seçilmiş satırlar):

```c
// C0
  *(uint *)(param_1 + 0x40) = *(uint *)(param_1 + 0x40) | 0x10000;
  *(long *)(param_1 + 0x378) = param_1 + 0x380;
  if (*(int *)(param_1 + 0x17c) != -1) {
    _bufferevent_free(*(undefined8 *)(param_1 + 0x180));
// C3
  param_1->flags = param_1->flags | 0x10000;
  param_1->screen = &param_1->base;
  if (param_1->fd != -1) {
    _bufferevent_free(param_1->event);
```

## 5. Gözlemler

1. **Yalnız ad, gövdeyi değiştirmiyor.** C1'de değişen tek şey `FUN_` yoğunluğu: hedeflerde −%29, çağıranlarda −%5. Öbür ölçütlerdeki küçük oynama satır kırılmasından geliyor: uzun gerçek ad imza satırını ikiye bölüyor (2 hedef).
2. **Yerleşimsiz prototip zararlı olabilir.** C2'de parametreler `window_pane *` oldu ama yapı boştu.
   - Decompiler alan erişimlerini `*(long *)(wp + 0x20)` biçiminde, boyu 1 olan bir tip üzerinden yazdı.
   - Ham aritmetik azalmadı (+%4); tip dönüşümü %27 arttı.
   - D'deki düşüş (−%25) yalnız parametre adlarından geliyor.
3. **Asıl kazanç yerleşimden ve onun yayılmasından geliyor.**
   - Tek yapıyla (C3) ham aritmetik yarıya indi; bütün yapılarla (C4) −%85.
   - Tek yapı, C4'ün P1 kazancının hedeflerde %59'unu, çağıranlarda %75'ini sağlıyor.
4. **Tiplemenin yan etkileri.** C sayısı yalnız azalmıyor, yer de değiştiriyor:
   - Yeni dönüşümler çıkıyor: tipli alana atanan tipsiz dönüş değerleri (`(bufferevent *)_bufferevent_new(...)`) ve tipli NULL karşılaştırmaları (`(layout_cell *)0x0`).
   - `window_pane_find_up/down`'da yerel dizi `long *` yerine `undefined8 *` oldu; U 1'den 5'e çıktı.
   - Bunlar okunurluk kaybı değil, sözdizimsel ölçütlerin sınırıdır. Ama ölçütle "okunurluk" arasındaki farkı gösterir.
5. **Maliyet.**
   - Geri yazma milisaniyeler sürüyor (20 fonksiyon + 115 tip: 0,04 sn).
   - Yeniden decompile, tipli hedeflerde 1,7 kat, çağıranlarda 1,1 kat daha uzun. Mutlak değer 20 hedef için 84 ms.
   - Ayrıştırma ve ön işleme bir kez yapılır (0,7 sn).

## 6. Sınırlamalar

- **Üst sınır.** Ad, prototip ve yerleşim gerçek kaynaktan geldi. Karadul'un kendi kurtardığı bilgi daha az ve kısmen yanlış olacak. Yanlış yerleşim, yanlış alan adını "güvenle" basar; plan v2 §0'daki uyarı burada da geçerli.
- **Örneklem.**
  - n = 20 hedef, 49 çağıran; tek program (tmux 3.8), tek yapı, tek derleyici ve SDK, tek Ghidra sürümü.
  - Hedeflerin 11'i window.c'den. Aday havuzunun da 64/108'i window.c'den.
  - Sonuç başka yapılara (ör. `client`) ve programlara genellenmemeli.
- **Ölçütler sözdizimsel vekildir**, insan okunurluğu değildir.
  - C ve U, tipleme sonrası yer değiştiriyor (bkz. §5.4).
  - D'deki düşüşün çoğu parametre adlarından geliyor (C2 ≈ C3).
  - `param_1[3]` biçimindeki sabit dizinli erişim P1'e girmiyor.
  - Satır sayısı Ghidra'nın satır kırmasından etkileniyor.
- **Opaklık.** 115 erişilebilir bileşik tipin 27'si kaynakta da opak. C4 bu yüzden "bütün yapılar" değil, "kaynakta tanımlı bütün yapılar"dır.
- **Doğrulama boşlukları.**
  - Kapanıştaki 14 adsız tipin iç yerleşimi DWARF'la ayrıca karşılaştırılmadı. Konumları üst yapıyla, kod ofsetleri ikiliyle uyumlu.
  - Prototiplerin doğruluğu kaynaktan alındığı için ayrıca ölçülmedi. Uygulanan imza, ayrıştırılan imzayla birebir aynı.
- **Süre ölçümleri** makinede başka 5 ajan çalışırken alındı. Ön kayıtlı süre ilk koşulun ısınmasından etkilendi; ek ölçüm sırası dengelenerek yapıldı.

## 7. Faz 1 G14-G15 için öneriler

1. **Karar kuralına göre geri yazma hattı Faz 1'in kritik yolu olabilir.** Ama bu bir üst sınır. Hattı öne almadan önce aynı 20 fonksiyonda **"Karadul'un kendi tipleri"** koşulunu ölçün. Bu, `struct_recovered` çıktısındaki yapıların geri yazılmasıdır; ölçütler ve kod bu deneydeki gibi kalır, yarım gün sürer. Böylece tavanın ne kadarının bugün erişilebilir olduğu görülür. Yanına alan ofseti doğruluğu da konmalı: Debian dbgsym'de DWARF'a karşı (G8'in kapsam dışı kalemi) ve G19'daki MaxSMT ofset düzeltmesinden sonra.
2. **Boş yapıya işaretçi yazmayın.** C2'nin sonucu açık: yerleşimi bilinmeyen bir yapıya işaretçi tipi tip dönüşümünü artırıyor, ham aritmetiği azaltmıyor. Ürün kuralı önerisi: bir parametreye `struct X *` ancak X'in yerleşimi (en azından kullanılan alanları) varsa yazılır. Yoksa parametre tipi değiştirilmez ya da `void *` kalır. `void *` seçeneği ayrıca ölçülmeli; bu deneyde ölçülmedi.
3. **"Etkilenen fonksiyonlar" çağıranları da kapsamalı.** Tipin yayılması çağıranlara ulaşıyor: 49'un 34'ünde `->` belirdi. Yeniden decompile kümesi en az doğrudan çağıranlar olmalı.
   - Çağıranın decompiler'ın çıkardığı parametre tipini (`window_pane_destroy` örneği) `HighFunctionDBUtil.commitParamsToDatabase` ile kaydedip bir sonraki halkaya taşımak bir sabit nokta döngüsü açar.
   - Bu, yanlış tipi de yayabilir. Derinlik sınırı ve durdurma kuralı ön kayıtla denenmeli.
4. **Tip yazma mekaniği bu deneydeki gibi olsun.**
   - Önce boş yer tutucular, sonra `KEEP_HANDLER` ile tam tipler. Böylece hangi yapının tam yazılacağı denetlenir ve `.conflict` tipi oluşmaz.
   - `ApplyFunctionSignatureCmd`'ye derleyici tanımının varsayılan çağrı kuralı verilsin. Bu tmux'ta `__cdecl`; uyarı yorumunu kaldırır, kodu değiştirmez.
   - Tabanda `mac_osx.gdt`'den gelen tipler (bu deneyde `timeval`, `termios`) yerinde kalır. Boyutları kontrol edilmeli; bu arşiv 10.9 SDK'sından.
5. **Paketli yapılar.** Ghidra'nın C ayrıştırıcısı `__attribute__((packed))`'ı uygulamıyor. Başlıktan tip üreten her hat (SDK GDT dahil) bunu ayrıca ele almalı ve DWARF'a karşı sınamalı.
6. **Ölçüm aleti.** `olcut.py` ve `ozet.py`'deki karar kuralı G14-G15'te aynı cetvel olarak kullanılabilir. Depoya alınacaksa `scripts/measurement/` altına konur. Bunun için ÖL-2 işini yapan ajanla dosya çakışması önce kontrol edilmeli.
7. **Süre bütçesi.** Ürün hattında geri yazma + yeniden decompile tmux ölçeğinde saniyeler mertebesinde kalır. Tipli fonksiyonlarda decompile 1,7-2,9 kat uzuyor; yalnız etkilenen küme yeniden decompile edilmeli (plan §12'deki risk).

## 8. Gözlem notu (kapsam dışı)

Ghidra 12.1.2'de macOS için tek tip arşivi `Ghidra/Features/Base/data/typeinfo/mac_10.9/mac_osx.gdt`. Ayrıştırıcı profilleri de `MacOSX_10.5/10.9/Cocoa.prf`. Bu deneydeki yol (`clang -E` + `CParser` + §1.4'teki uyarlamalar + packed düzeltmesi) tmux.h'nin içerdiği güncel SDK 27.0 başlıklarını 0,6 saniyede hatasız ayrıştırdı (SDK'nın tamamı denenmedi). SDK GDT üretimi için aday bir yöntem olabilir; o iş bu deneyin kapsamı dışında.

## 9. Dosyalar

Bu klasör (`docs/arge/2026-10-19_g8_geri_yazma/`):

| Dosya | İçerik |
|---|---|
| `onkayit.md`, `onkayit_notlari.md` | ön kayıt ve sapma notları |
| `olcut.py` | ölçüt tanımları (ön kayıtla dondurulmuş; `--test`) |
| `ortak.py` | yollar, künye, JVM başlatma (Karadul'un `_ensure_pyghidra_started`'ı), decompile |
| `kaynak.py` | yapı seçimi sayımları, aday havuzu (a)-(d) |
| `taban.py` | `analiz`: taban projesi; `secim`: (e)-(f), tohumlu sıra, çağıranlar |
| `tipler.py` | ön işleme, uyarlama, `CParser`, DWARF karşılaştırması → `yerlesim_dogrulama.json` |
| `ikili_kanit.py` | ikilide sizeof ve hedef ofsetleri |
| `deney.py` | koşullar C0-C4: geri yazma, yeniden decompile, ölçüm |
| `ozet.py` | eşli istatistik, karar kuralı → `sonuc.json` |
| `tablolar.py` | bu rapordaki tablolar |
| `saglamlik_cc.py`, `sure_ek.py`, `packed_sinama.py` | ön kayıt dışı denetimler: çağrı kuralı, dengeli süre, ayrıştırıcının `packed` davranışı |
| `sonuc.json` | künye, seçim, koşul başına uygulama denetimi, karşılaştırmalar, fonksiyon başına önce/sonra ham sayılar (5 koşul) |
| `yerlesim_dogrulama.json` | yerleşim ve DWARF ayrıntısı |

Depo dışı (`workspaces/2026-10-19_g8/`, git'e girmez):
- `src/tmux-3.8` ve `build_g/`: yapılandırma, `-g -Os` derleme, dSYM
- `projeler/{taban,C0..C4}`: Ghidra projeleri
- `ciktilar/{C0..C4,C3_cdecl}`: her fonksiyonun C metni
- `veri/`: aday, seçim, ölçüm, ikili kanıt, süre ve ön kayıt mührü
- `log/`

Yeniden üretim:

```bash
P="/opt/anaconda3/bin/python3 -I -B"; D=docs/arge/2026-10-19_g8_geri_yazma
$P $D/kaynak.py && $P $D/taban.py analiz && $P $D/taban.py secim
$P $D/tipler.py && $P $D/ikili_kanit.py
$P $D/deney.py C0 C1 C2 C3 C4 && $P $D/ozet.py
```

`taban.py analiz` ve `deney.py`, var olan proje klasörünün üstüne yazmaz; yeniden koşmadan önce o klasör elle kaldırılmalıdır.

## 10. Ek koşullar: Karadul bugün, `void *`, `struct client`

- **Ön kayıt:** `onkayit_ek.md`, mühür 2026-10-19 12:53:43, SHA-256 `ab5e1bf8…f03dd6d`. Sapmalar `onkayit_ek_notlari.md`'de.
- **Sıra:** İlk yeni Ghidra koşusu (K3 seçimi) 12:54:32'de, bütün koşullar 13:00'te koşuldu.
- **Değişmeyenler:** ölçütler (`olcut.py`), eşli analiz (`ozet.py`), eşikler, Ghidra 12.1.2, taban projesi ve decompile ayarları.
- **Karadul çıktısı:** `workspaces/olcum_mac/runs/taban-v2-62ad154/tmux/` (Karadul 62ad154, aynı strip'li ikili).
- **Ayrıntılı sonuçlar:** `sonuc_ek.json`.

### 10.1 Koşullar ve Karadul'un kapsamı

| Koşul | Yazılan |
|---|---|
| K0 | C0'ın tekrarı (belirlenimcilik ve süre tabanı). 69 metnin 69'u G8'in C0'ıyla birebir aynı |
| K1 "Karadul bugün" | Karadul'un açık çıktısı: `naming_map` adı ve son çıktıdaki imza (parametre adları ve tipleri). Yapı yok, çünkü Karadul hiçbir yapıyı bir fonksiyona bağlamıyor |
| K1y "bağlansaydı" | K1 + Karadul'un ilk parametre değişkeni için ürettiği yapı. Bağ, Karadul'un kendi işlevleriyle yeniden üretildi; `types.h`'deki 1398 yapının 1391'i birebir tuttu |
| K2 "`void *`" | C2 ile aynı, ama yapı işaretçileri `void` işaretçisi. 25 parametre ve 4 dönüş tipi değişti; programa tmux yapısı yazılmadı |
| K3-C0 / K3-C3 | `struct client` ile C0 ve C3'ün eşdeğeri. Seçim kuralı ve tohum aynı; 170 adaydan sıradaki ilk 20 seçildi (1'i thunk olduğu için elendi); 37 çağıran |

**Karadul'un 20 hedefe verdiği bilgi:**
- **Ad:** 10/20.
- **Prototip:** 20/20 yazıldı.
  - 20'sinde parametre adı değişiyor.
  - 5'inde tip yazımı değişiyor: `undefined8` → `uint64_t`, `undefined4 *` → `int32_t *`.
  - Parametre tipleri başka bakımdan Ghidra'nınkiyle aynı.
- **Yapı:** Karadul'un çıktısında 0 bağlı yapı var. `types.h`'deki 1398 `recovered_struct` yapısının hiçbiri hiçbir `.c` dosyasında geçmiyor.
- **K1y bağları:** 5 hedefe bağ çıktı. Her biri yalnız o fonksiyonun kendi erişimlerinden üretilmiş 2-3 alanlık bir parça. c_namer değişken adlarına sayı eki koyduğu (`ctx_610`, `buf_1750`) için Karadul'un "değişken adıyla birleştirme" anahtarı pratikte tek fonksiyona iniyor.

| Gerçek ad | Karadul adı | Karadul imzası | K1y yapısı |
|---|---|---|---|
| `layout_resize_floating_pane_to` | `pane_floating` | `uint64_t pane_floating(long buf_796,int param_2,uint len_153,uint64_t *buf_797)` | — |
| `layout_resize_floating_pane` | `change_big_small` | `uint64_t change_big_small(long buf_798,int param_2,int param_3,int param_4,uint64_t *buf_799)` | — |
| `window_pane_set_event` | `out_memory_11` | `void out_memory_11(long ctx_610)` | recovered_struct_1330 |
| `window_pane_send_resize` | `window_pane_send` | `void window_pane_send(long buf_1750)` | — |
| `window_copy_get_word` | — | `void FUN_100087768(long buf_1423,uint64_t param_2,int enabled)` | — |
| `window_pane_cmp` | — | `uint FUN_10009c80c(uint *buf_1707,uint *buf_1708)` | — |
| `cmd_swap_pane_prev_tiled_pane` | — | `long FUN_10001cc8c(long buf_179)` | — |
| `window_pane_floating_overlaps` | — | `bool FUN_10009d984(long buf_1764,uint64_t ctx_697)` | — |
| `layout_spread_out` | — | `void FUN_10004be58(long buf_803)` | — |
| `window_pane_find_up` | `pane_border_status_4` | `long pane_border_status_4(long buf_1810)` | — |
| `window_pane_index` | `pane_base_index_2` | `uint64_t pane_base_index(long buf_1772,int *buf_1773)` | — |
| `layout_close_pane` | `window_layout_changed_11` | `void window_layout_changed_11(long buf_801)` | recovered_struct_564 |
| `window_pane_scrollbar_show` | — | `void FUN_1000a14e0(long ctx_619,int count)` | recovered_struct_1356 |
| `window_pane_set_prompt` | `pane_prompt_opened` | `void pane_prompt_opened(int32_t *param_1,long struct_ptr ,uint64_t param_3, …, uint64_t param_9)` | — |
| `window_pane_get_bg_control_client` | — | `int FUN_1000a167c(long buf_1813)` | — |
| `window_pane_find_down` | `pane_border_status_5` | `long pane_border_status_5(long ctx_623)` | recovered_struct_1351 |
| `screen_write_clear_dirty` | — | `void FUN_100062c94(long buf_1020)` | recovered_struct_735 |
| `cmd_mouse_at` | `cmd_mouse` | `uint64_t cmd_mouse(long ctx_53,long ctx_54,int *buf_231,int *buf_232,int param_5)` | — |
| `window_pane_status_get_range` | — | `uint64_t FUN_1000a19c8(long ctx_626,int param_2,int param_3)` | — |
| `window_copy_get_line` | — | `void FUN_10008778c(long buf_1422,int enabled)` | — |

### 10.2 Sonuçlar

**Hedefler: havuzlanmış 100 satır oranının göreli değişimi** (anlamlı kazanç kalın; A için önce → sonra)

| Karşılaştırma | n | U | P1 | C | A | D | Anlamlı (5'te) |
|---|---|---|---|---|---|---|---|
| (G8) C3 ↔ C0 | 20 | **−52%** | **−50%** | −8% | **0,0 → 11,0** | −24% | 3 |
| K1 ↔ C0 | 20 | **−41%** | +0% | +0% | 0,0 → 0,0 | −18% | 1 |
| K1y ↔ C0 | 20 | **−49%** | −21% | −7% | **0,0 → 3,7** | −18% | 2 |
| K2 ↔ C0 | 20 | −24% | +1% | +70% | 0,0 → 0,0 | −24% | 0 |
| K2 ↔ C2 | 20 | +0% | −3% | +34% | 0,0 → 0,0 | +1% | 0 |
| K3-C3 ↔ K3-C0 (client) | 20 | −22% | −19% | −2% | **0,0 → 6,6** | −14% | 1 |

**Doğrudan çağıranlar**

| Karşılaştırma | n | U | P1 | C | A | D | Anlamlı (5'te) |
|---|---|---|---|---|---|---|---|
| K1 ↔ C0 | 49 | −6% | −1% | +2% | 0,0 → 0,0 | −2% | 0 |
| K1y ↔ C0 | 49 | −3% | −10% | +2% | **0,0 → 1,1** | −4% | 1 |
| K2 ↔ C0 | 49 | −1% | −0% | +18% | 0,0 → 0,0 | −4% | 0 |
| K2 ↔ C2 | 49 | +0% | −2% | +13% | 0,0 → 0,0 | +0% | 0 |
| K3-C3 ↔ K3-C0 (client) | 37 | −18% | −21% | −11% | **0,0 → 7,5** | −7% | 1 |

**K1 ↔ C0, hedefler**

| Ölçüt | Ort. önce | Ort. sonra | Eşli fark [%95 GA] | Havuz önce → sonra (göreli) | İyi / kötü / aynı | Anlamlı kazanç |
|---|---|---|---|---|---|---|
| U/100 | 10,1 | 6,8 | −3,3 [−5,7; −1,3] | 12,5 → 7,4 (−41%) | 8/0/12 | **evet** |
| P1/100 | 27,1 | 27,1 | +0,0 [+0,0; +0,0] | 19,0 → 19,0 (+0%) | 0/0/20 | hayır |
| C/100 | 31,0 | 31,0 | +0,0 [+0,0; +0,0] | 24,6 → 24,6 (+0%) | 0/0/20 | hayır |
| A/100 | 0,0 | 0,0 | +0,0 [+0,0; +0,0] | 0,0 → 0,0 (+0%) | 0/0/20 | hayır |
| D/100 | 107,1 | 73,3 | −33,8 [−43,3; −24,6] | 115,8 → 94,7 (−18%) | 20/0/0 | hayır |

**K1y ↔ C0, hedefler**

| Ölçüt | Ort. önce | Ort. sonra | Eşli fark [%95 GA] | Havuz önce → sonra (göreli) | İyi / kötü / aynı | Anlamlı kazanç |
|---|---|---|---|---|---|---|
| U/100 | 10,1 | 4,5 | −5,6 [−8,6; −3,0] | 12,5 → 6,4 (−49%) | 13/0/7 | **evet** |
| P1/100 | 27,1 | 20,4 | −6,7 [−13,2; −1,7] | 19,0 → 15,1 (−21%) | 5/0/15 | hayır |
| C/100 | 31,0 | 27,6 | −3,4 [−6,8; −0,6] | 24,6 → 22,8 (−7%) | 4/1/15 | hayır |
| A/100 | 0,0 | 6,5 | +6,5 [+1,6; +12,9] | 0,0 → 3,7 (taban 0) | 5/0/15 | **evet** |
| D/100 | 107,1 | 73,1 | −34,0 [−43,5; −24,7] | 115,8 → 94,6 (−18%) | 20/0/0 | hayır |

**K2 ↔ C0, hedefler**

| Ölçüt | Ort. önce | Ort. sonra | Eşli fark [%95 GA] | Havuz önce → sonra (göreli) | İyi / kötü / aynı | Anlamlı kazanç |
|---|---|---|---|---|---|---|
| U/100 | 10,1 | 7,4 | −2,7 [−4,8; −0,7] | 12,5 → 9,6 (−24%) | 9/2/9 | hayır |
| P1/100 | 27,1 | 26,4 | −0,8 [−1,8; +0,1] | 19,0 → 19,2 (+1%) | 6/4/10 | hayır |
| C/100 | 31,0 | 53,2 | +22,2 [+16,4; +28,6] | 24,6 → 41,9 (+70%) | 0/20/0 | hayır |
| A/100 | 0,0 | 0,0 | +0,0 [+0,0; +0,0] | 0,0 → 0,0 (+0%) | 0/0/20 | hayır |
| D/100 | 107,1 | 70,1 | −36,9 [−46,0; −28,3] | 115,8 → 88,2 (−24%) | 20/0/0 | hayır |

**K3-C3 ↔ K3-C0 (`struct client`), hedefler**

| Ölçüt | Ort. önce | Ort. sonra | Eşli fark [%95 GA] | Havuz önce → sonra (göreli) | İyi / kötü / aynı | Anlamlı kazanç |
|---|---|---|---|---|---|---|
| U/100 | 12,3 | 6,3 | −6,1 [−12,0; −1,3] | 6,2 → 4,9 (−22%) | 13/3/4 | hayır |
| P1/100 | 20,1 | 12,5 | −7,6 [−14,5; −2,1] | 17,8 → 14,4 (−19%) | 14/2/4 | hayır |
| C/100 | 26,6 | 24,5 | −2,2 [−9,6; +5,2] | 32,3 → 31,8 (−2%) | 8/8/4 | hayır |
| A/100 | 0,0 | 10,0 | +10,0 [+4,5; +17,0] | 0,0 → 6,6 (taban 0) | 15/0/5 | **evet** |
| D/100 | 108,3 | 74,6 | −33,7 [−43,2; −24,9] | 128,1 → 109,6 (−14%) | 20/0/0 | hayır |

**K1'in C3 tavanındaki payı** (havuz oranı, (K1 − C0) / (C3 − C0), tanımlayıcı):
- Hedeflerde U %80, D %75, P1 %0, C %0, A %0.
- Çağıranlarda U %34, D %48, P1 %3.

### 10.3 Karadul yerleşiminin doğruluğu (DWARF'la doğrulanmış `window_pane`'e karşı)

| Yapı | Boyut (gerçek 1760) | Kaynak | Doğru | Ofset doğru, boyut yanlış | Yanlış |
|---|---|---|---|---|---|
| recovered_struct_1330 | 688 | out_memory_11 | 2 | 0 | 0 |
| recovered_struct_564 | 40 | window_layout_changed_11 | 2 | 0 | 0 |
| recovered_struct_1356 | 96 | FUN_1000a14e0 | 2 | 0 | 0 |
| recovered_struct_1351 | 64 | pane_border_status_5 | 3 | 0 | 0 |
| recovered_struct_735 | 88 | FUN_100062c94 | 2 | 0 | 0 |

**Bağlanan 5 yapının 11 alanının 11'i doğru** (ofset ve boyut gerçek bir alana denk). Ama:
- **Kapsam küçük.** 11 alan 10 ayrı gerçek alana denk geliyor (`window` (0x10) iki ayrı yapıda tekrarlanıyor); bu, `window_pane`'in 566 yaprak alanının 10'u. Bu 5 fonksiyonun gövdesindeki öbür erişimler yapıya girmemiş; örneğin `window_pane_set_event`'teki `fd` (0x17c) yok.
- **Boyutlar yanlış.** 40-688 bayt; gerçek 1760. Yalnız görülen en büyük ofsete göre hesaplanıyor.
- **Tek tip yok.** Aynı `struct window_pane`, 5 hedefte 5 ayrı tip olarak çıkıyor.
- **Alan adları anlamsız.** `field_0x10`, `window` değil.

Hedefleri kaynak listesinde taşıyan bütün 11 yapı sayılırsa sonuç 17 doğru, 6 ofset doğru boyut yanlış, 9 yanlış. Bu yapıların bir kısmı başka değişkenlerden (ör. `struct window` işaretçisi) üretildiği için bu sayı yalnız bağlam verir.

### 10.4 `struct client` yerleşim doğrulaması (K3'ün ön koşulu, tuttu)

- `client` 3240 bayt ve 76 alan. Kapanıştaki 28 bileşik tipin 18 adlısının hepsi DWARF'la eşit; 10'u adsız TAILQ/RB/libevent parçası.
- Şişedeki `server_client_create` içinde `mov w1, #0xca8` (3240) + `bl _xcalloc` var.
- 20 hedefin ofset kümeleri şişe ile kendi derlememizde aynı (Jaccard 1,0). Komut sayıları da birebir aynı.
- Ayrıntı: `k3_yerlesim_dogrulama.json`.

### 10.5 Ön kayıtlı karar okuması

| Koşul | Sonuç | Ön kayıttaki okuma |
|---|---|---|
| K1 | 1/5 | **Kazanç bugün erişilebilir değil.** Önce tip ve yapı kurtarma gelir (G16-G17, G19); geri yazma hattı öne alınmaz. Tek anlamlı ölçüt U ve o da yalnız yazım değişikliğinden geliyor (§10.6 madde 1) |
| K1y | 2/5 (U, A); bağlı yapı alan doğruluğu 11/11 | Ön kayıtlı uyarı koşulu (anlamlı kazanç ve doğruluk < %50) oluşmadı. Ama doğruluk küçük kapsamın doğruluğudur (§10.3) |
| K2 | C/100 24,6 → 41,9 (C2'de 31,3) | **Artışın kaynağı opak yapı işaretçisi değil.** `void *` dönüşümü daha da artırıyor. Kural yeniden düşünülmeli (§10.6 madde 2) |
| K3 | 1/5 (A) | **Tek yapı bulgusu `client`'ta tekrarlanmadı**; genellenmez. Etkiler aynı yönde ama eşiğin altında (§10.6 madde 3) |

### 10.6 Gözlemler

1. **U ölçütü yazımla oynanabiliyor.** K1'deki −%41 tamamen `undefined8` → `uint64_t` gibi tip adı değişikliğinden geliyor. P1, C ve A hiç değişmiyor. G8'deki C3 sonucunda U'nun düşüşü gerçek tiplerden geliyordu; bu ayrım ölçütte görünmüyor. Bundan sonraki kararlarda U tek başına kanıt sayılmamalı, P1 ve A ile birlikte okunmalı.
2. **Yerleşimsiz işaretçi tipi her durumda dönüşüm ekliyor.**
   - C2'de eklenenler yapı tipine dönüşümler: `(window_pane *)` +21, `(window_pane **)` +6.
   - K2'de eklenenler aritmetik dönüşümleri: `(long)` +72, `(void *)` +24. Örnek: `*(long *)(wp + 0x20)` (C2) → `*(long *)((long)wp + 0x20)` (K2).
   - Sonuç: yerleşim bilinmiyorsa en az dönüşümü Ghidra'nın kendi tamsayı tipi veriyor. Ürün kuralı önerisi "`void *`" değil, **"parametre tipini değiştirme, yalnız adı yaz"** olmalı. Bu öneri ölçülmedi (C1'e parametre adı eklenmiş bir koşul); ölçülmeden kural yapılmamalı.
3. **`client` tekrarında etkiyi tek bir büyük fonksiyon bastırıyor.**
   - Hedef satırlarının %55'i `redraw_draw`'dan (1071/1961) geliyor. Bu fonksiyondaki ham erişimler çoğunlukla `client` dışı yapılarda (P1 195 → 188).
   - Fonksiyon başına eşli farkların güven aralıkları U, P1, D ve A'da sıfırı dışlıyor. Göreli eşik ise havuz oranıyla ölçüldüğü için bu fonksiyonun ağırlığı altında kalıyor.
   - Ön kayıt dışı duyarlılık bakışı (karar değişmez): `redraw_draw` çıkarılınca U −%33, P1 −%36, D −%27.
   - Sonuç: tek yapının kazancı, fonksiyonların o yapıya ne kadar dokunduğuna bağlı. "Tek yapı + 20 prototip yeter" genellemesi yapılamaz.
4. **Karadul'un yapı kurtarma aşaması fiilen yerel.** Parçalar doğru ama küçük, adsız ve birleştirilmemiş. Ürüne geri yazılacak bir tip için en az şunlar gerekiyor: aynı alıcı tipteki fonksiyonların parçalarını birleştirme (G7/G16-G17'nin alıcı tip kümeleri), boyut kestirimi ve alan adı.
5. **Karadul adları.** 10 addan çoğu gerçek adla ilgisiz ya da amaçtan uzak (`out_memory_11` → `window_pane_set_event`, `change_big_small` → `layout_resize_floating_pane`). Ad yalnız `FUN_` yoğunluğunu etkiliyor; okunurluk ölçütlerine katkısı yok.

### 10.7 Sınırlamalar

- K1, Karadul'un tek bir koşusu (62ad154).
- K1y'deki bağ Karadul'un yapmadığı bir işlemdir, yeniden üretilmiştir.
- K3 de tek program ve tek derleme; iki yapı genelleme için az.
- "Aynı süreç" süre karşılaştırmalarında süreçteki ilk koşul (K0) ısınma yüzünden yavaş (`onkayit_ek_notlari.md` #5). Maliyet için G8'in sırası dengelenmiş ölçümü esas.
- K3'teki `redraw_draw` bakışı ve dönüşüm kaynağı dökümü ön kayıt dışı, tanımlayıcıdır.

### 10.8 Ana oturumun vermesi gereken kararlar

1. **G14-G15 öne alınmasın.** K1'in ön kayıtlı okuması bunu söylüyor; K3 de tek yapı genellemesini desteklemiyor. Önce tip ve yapı kurtarma gelir:
   - parçaları alıcı tipe göre birleştirme (G16-G17)
   - ofset düzeltmesi (G19)
   - boyut ve alan adı
   
   Geri yazma mekaniği hazır ve ucuz; tip bilgisi gelince aynı cetvelle yeniden ölçülür.
2. **U ölçütü.** Kapılarda U tek başına sayılmasın; P1 ve A ile birlikte okunsun. Gerekirse U için "tip adı değişikliği" ayıklayan bir sürüm yazılsın. Bu, ölçüm aleti kararıdır.
3. **Ürün kuralı adayı.** "Yerleşim yoksa parametre tipini değiştirme." Ölçmek için yeni bir koşul gerekir: C1 + kaynaktan parametre adları, tipler Ghidra'nınki. Ucuz, aynı altyapıyla yarım saatten az sürer.
4. **"Tek yapı" sorusu.** Kapı ölçütü havuz oranı mı kalsın, yoksa büyük fonksiyonların ağırlığını sınırlayan bir ölçü mü eklensin (ör. fonksiyon başına ortalamanın göreli değişimi)? Bu yalnız gelecek ön kayıtlar için bir yöntem kararıdır, bugünkü sonucu değiştirmez.

### 10.9 Yeni dosyalar

Bu klasör:

| Dosya | İçerik |
|---|---|
| `onkayit_ek.md`, `onkayit_ek_notlari.md` | ek ön kayıt ve notlar |
| `ek_kaynak.py`, `ek_secim.py` | K3 aday havuzu ve seçim |
| `ek_yerlesim.py` → `k3_yerlesim_dogrulama.json` | `client` yerleşim doğrulaması |
| `ek_karadul.py` | Karadul adı, imzası ve yapı bağı |
| `ek_deney.py` | K0, K1, K1y, K2, K3_C0, K3_C3 koşulları; `yerlesim` komutuyla Karadul alan doğruluğu |
| `ozet_ek.py` → `sonuc_ek.json` | karşılaştırmalar, karar okuması, fonksiyon başına ham sayılar |
| `tablolar_ek.py` | bu bölümdeki tablolar |

Depo dışı (`workspaces/2026-10-19_g8/`):
- `projeler/{K0,K1,K1y,K2,K3_C0,K3_C3}`
- `ciktilar/{K0,K1,K1y,K2,K3_C0,K3_C3}`
- `veri/{k1_karadul,k1_ayristirma,k1_yerlesim_dogrulugu,k3_kaynak_adaylar,k3_secim,olcum_K*}.json`
- `veri/onkayit_ek_muhur.txt`
