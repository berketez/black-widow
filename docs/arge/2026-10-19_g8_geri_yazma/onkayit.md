# G8 geri yazma prototipi: ön kayıt

- **Yazıldığı an:** 2026-10-19 12:05 (+0300). Strip'li tmux henüz Ghidra'da analiz edilmedi; hiçbir fonksiyon decompile edilmedi; hiçbir sonuç ölçütü görülmedi.
- **Plan kalemi:** plan v2 §5 G8 ("Geri yazma prototipi") ve "G8 karar kuralları"; §2 madde 4; §3 madde 1.
- **Değişiklik kuralı:** Bu belge ölçümden sonra değiştirilmez. Sapma gerekirse gerekçesiyle `onkayit_notlari.md`'ye yazılır.
- **Künye:** depo `62ad154`; Ghidra 12.1.2 PUBLIC (`application.revision.ghidra` c0f584bf229f…, `~/Library/BlackWidowBuild/ghidra_12.1.2_PUBLIC`); pyghidra 3.0.0; Python 3.12.7 (`/opt/anaconda3`); JVM yığını 6144 MB.
- **Girdiler (sha256):**
  - analiz: `workspaces/2026-10-15_oturum_scratchpad/macho/apple_strip/tmux` — `10fa0411…c9997b7`
  - gerçek isimler: `…/macho/orig/tmux` — `dfbb8c54…c629998b` (Homebrew tmux 3.8 şişesiyle aynı dosya)
  - kaynak: `tmux-3.8.tar.gz` — `e79c699c…3966d82e` (Homebrew formülündeki sha256 ile aynı)

## 1. Soru ve hipotezler

**Soru.** Karadul'un bilebileceği isim, prototip ve yapı bilgisi Ghidra'ya geri yazılır ve fonksiyonlar yeniden decompile edilirse, okunurluk ölçütleri ne kadar iyileşir?

Bu deney bir **üst sınır** ölçer: bilgi Karadul'dan değil, tmux 3.8'in gerçek kaynağından alınır. Sonuç, Karadul'un kendi kurtardığı bilgiyle ulaşabileceği kazancın tavanıdır, Karadul'un bugünkü başarısı değildir.

- **H1 (hedef fonksiyonlar, C3 ↔ C0).** 100 satırdaki `undefined*` belirteci, ham işaretçi aritmetiği ve varsayılan ad sayısı düşer; 100 satırdaki `->` erişimi artar.
- **H2 (doğrudan çağıranlar, C3 ↔ C0).** Etki aynı yöndedir ama daha küçüktür. `FUN_` yoğunluğu ad geri yazmasıyla düşer.
- **H3 (ablasyon).** Yapı yerleşimi olmadan yalnız prototip (C2), ham işaretçi aritmetiğini anlamlı düşürmez. Bu ölçütteki kazancın çoğu yerleşimden gelir (C3 − C2).
- **H0.** Anlamlı fark yoktur.

## 2. Yapı seçimi

**Kural.** Derlenen tmux 3.8 `.c` dosyalarında (144 dosya: darwin dışındaki `osdep-*` ve `compat/` hariç) `struct X *` biçimi en çok geçen yapı seçilir.

| Yapı | `struct X *` geçişi | İlk parametresi `X *` olan fonksiyon tanımı | Dosya sayısı |
|---|---|---|---|
| **window_pane** | **594** | 125 | 18 |
| client | 560 | 189 | 32 |
| window_mode_entry | 369 | 127 | 8 |
| format_tree (format.c'ye özel) | 366 | 225 | 3 |

**Seçilen:** `struct window_pane`.

**Şeffaflık notu.** Kural yazılmadan önce iki sayım da görüldü. İkinci sayıma (ilk parametre sayısı) göre seçilseydi, tmux.h'de tanımlı yapılar arasında `client` çıkardı. Kural (i), sonuç ölçütleri görülmeden seçildi. Ek gerekçeler:
- `window_pane` 18 dosyada alıcı tiptir.
- libevent'in `struct event`'ini (3 kez), SDK'nın `struct timeval`'ını ve `char[TTY_NAME_MAX]` dizisini değerle gömer. Bu, yerleşim kurtarma için zor ve doğrulanabilir bir durumdur.
- Boyutu ikilide doğrulanabilir: şişedeki `window_add_pane` içinde `xcalloc(1, 0x6e0)` var (pencere bölmesi oluşturucusu oraya gömülmüş).

`client` aynı yöntemle yapılacak bir tekrar deneyi için aday olarak kalır.

## 3. Fonksiyon seçimi

**Aday havuzu.** Bir fonksiyon, şu koşulların hepsini sağlıyorsa adaydır:
- (a) Derlenen 144 dosyadan birinde tanımlıdır ve ilk parametresi `struct window_pane *` (isteğe bağlı `const`) olarak bildirilmiştir.
- (b) Adı, havuzdaki tanımlar arasında tektir (aynı adlı iki `static` fonksiyon dışlanır).
- (c) `/usr/bin/nm -n -U orig/tmux` çıktısında `_<ad>` tam bir kez, `T` ya da `t` türüyle geçer. Bu, satır içine gömülmüş fonksiyonları dışlar.
- (d) O adreste başka `T`/`t` sembolü yoktur (bağlayıcının özdeş kod katlaması dışlanır).
- (e) Taban projede (strip'li ikili, Ghidra otomatik analizi) bu adreste giriş noktası olan, adı `FUN_` ile başlayan ve thunk olmayan bir fonksiyon vardır.
- (f) Bu fonksiyonun taban decompile'ı 30 saniye içinde tamamlanır.

**Sıra (belirlenimci).**
1. (a)-(d)'yi sağlayan adaylar gerçek adrese göre sıralanır.
2. Liste `random.Random(8691180542497554626).shuffle` ile karıştırılır. Tohum, SHA-256(`karadul-g8-geri-yazma-2026-10-19`) değerinin ilk 16 onaltılık basamağıdır (`789d46a7d25a80c2`); Python 3.12'nin Mersenne Twister'ı kullanılır.
3. Karışık sırada (e) ve (f)'yi sağlayan ilk 20 fonksiyon alınır.

**Doğrudan çağıranlar.** Taban programda, 20 hedefin giriş adresine CALL türünde başvurusu olan fonksiyonlardır (`getFunctionContaining`). Hedeflerin kendisi bu kümeden çıkarılır. Küme tabanda bir kez belirlenir ve bütün koşullarda sabit kalır.

## 4. Koşullar

Her koşul, taban projenin ayrı bir kopyasında koşulur. Yeniden analiz yapılmaz. Programa yalnız ad, prototip ve tip yazılır.

| Koşul | Geri yazılan |
|---|---|
| C0 taban | hiçbir şey |
| C1 ad | 20 fonksiyona `Function.setName` ile gerçek ad |
| C2 ad + prototip | C1'e ek olarak `ApplyFunctionSignatureCmd` ile gerçek prototip (dönüş tipi, parametre tipleri ve adları). Bütün `struct`/`union` tipleri **içi boş** (opak) yer tutucudur; typedef'ler ve enum'lar tamdır |
| **C3 ad + prototip + yapı** (ana koşul) | C2'ye ek olarak `struct window_pane` doğru yerleşimiyle. Değerle gömdüğü yapılar (kapanışı) da tamdır, çünkü yerleşim onlara bağlıdır. Yalnız işaretçiyle erişilen öteki yapılar opak kalır |
| C4 ad + prototip + bütün tmux yapıları (ek) | C3'e ek olarak ayrıştırılan bütün yapılar tam. Ucuzsa koşulur |

**Yerleşim kaynağı.**
- Birinci yol: tmux başlıkları gerçek derlemenin bayraklarıyla `clang -E` ile ön işlenir. Bayraklar, tmux 3.8'in Homebrew formülündeki seçeneklerle (`--enable-sixel --enable-utf8proc`, jemalloc otomatik) yapılan `configure`'dan gelir; SDK ve Homebrew bağımlılık başlıkları kullanılır. Sonra Ghidra'nın C ayrıştırıcısıyla (`CParser`), hedef programın veri düzeniyle ayrıştırılır.
- Yerleşimi etkilemeyen ve ayrıştırıcının tanımadığı sözdizimi metinden çıkarılır; her uyarlama sayısıyla kayda geçer.
- Bu yol olmazsa ikinci yol: aynı seçeneklerle `-g` derleme ve DWARF.

**Prototip kaynağı.**
- Hedef fonksiyonların kaynaktaki tanım imzaları (`static` atılarak) aynı çeviri birimine bildirim olarak eklenir.
- Bildirimler aynı bayraklarla ön işlenir ve aynı ayrıştırıcıyla `FunctionDefinition`'a çevrilir.

**Yerleşim doğrulaması (ön kayıtlı ölçüt).**
1. `window_pane` ve kapanışındaki her adlı yapının boyutu ve her adlı alanının ofseti, aynı seçeneklerle `-g` derlenen tmux'un DWARF'ıyla (dSYM) birebir eşit olmalı.
2. İkilide `sizeof(struct window_pane)` = 0x6e0 olmalı (`xcalloc` argümanı).
3. 20 fonksiyonun ikilideki bellek erişim ofsetleri, kendi `-g` derlememizdeki aynı fonksiyonlarla karşılaştırılır ve raporlanır.

(1) tutmazsa C3 koşulmaz. Önce yerleşim düzeltilir, düzeltme kayda geçer.

**`HighFunctionDBUtil`.** Decompiler uygulanan prototipi kullanırsa gerekmez. Gerekirse (parametre ya da yerel kaydı için) kullanılır ve notta belirtilir.

## 5. Ölçütler

Tanımların tamamı `olcut.py`'dedir (SHA-256 `67afd3ddd2c2cad3f09754e17038ddaf0fba1945701b6d0aba245b1eede2005c`; `--test` ile sentetik öz-sınama). Girdi, `DecompiledFunction.getC()` metnidir.

**Ön temizlik.** Yorumlar silinir; dize ve karakter sabitlerinin içi boşaltılır. **Satır (L)** = boş olmayan satır sayısı. "100 satırda" = 100 × sayı / L.

| Kısaltma | Ölçüt | Tanım |
|---|---|---|
| U | `undefined*` belirteci | `\bundefined\d*\b` |
| P1 | ham işaretçi aritmetiği (birincil) | `*(T *)(E)` biçimi: önce `\(\s*(?:(?:const\|volatile\|unsigned\|signed\|struct\|union\|enum)\s+)*[A-Za-z_]\w*\s*\*+\s*\)\s*\(` başı aranır. Sonra eşleşen kapanış parantezine kadar E alınır. E'nin en üst düzeyinde ikili `+` ya da `-` varsa (`->`, `++` ve `--` hariç) ve dönüşümün hemen önünde `*` varsa sayılır |
| P2 | ham işaretçi aritmetiği (geniş, ikincil) | P1 ile aynı, ama önünde `*` şartı yok: `(T *)(x + 0x10)` de sayılır |
| C | tip dönüşümü | `(?<![\w\]])(?<!\bif )(?<!\bfor )(?<!\bwhile )(?<!\bswitch )\(\s*(?:niteleyici\s+)*[A-Za-z_]\w*(?:\s+(?:long\|int\|short\|char))*\s*\**\s*\)(?=\s*(?:[\w(*!~\-'"]\|&(?!&)))`. Önünde `)` olan aday yalnız bir dönüşüm zincirinin devamıysa sayılır. Yıldızsız adaylarda parantez içindeki ad Ghidra'nın varsayılan değişken adıysa ya da imzadaki bir parametre adıysa sayılmaz |
| A | `->` alan erişimi | `->` geçişi; hem ham sayı hem 100 satırda |
| D | varsayılan yerel ve parametre adı | `\b(?:param_\d+\|local_[0-9a-fA-F]+(?:_[0-9a-fA-F]+)?\|local_res\w+\|[a-z]{1,8}Var\d+\|[a-z]{1,8}Stack_\w+\|in_\w+\|extraout_\w+\|unaff_\w+)\b` |
| G, F | varsayılan genel adlar (ikincil) | G: `FUN_/DAT_/LAB_/SUB_<hex>`, `PTR_…`, `switchD_…`, `caseD_…`. F: yalnız `FUN_<hex>` |
| T | yeniden decompile süresi | `decompileFunction` çağrısının duvar saati süresi. Ayarlar Karadul'unkiyle aynı: `DecompileOptions()` varsayılanı, fonksiyon başına 30 sn |

**Decompile düzeni.**
- Her koşulda yeni bir `DecompInterface` açılır ve ölçülen kümede olmayan 5 fonksiyonla ısınma yapılır (sonuçları atılır).
- Her fonksiyon iki kez decompile edilir. Ölçüt metni ilk koşudandır; T iki koşunun ortalamasıdır.
- İki metin farklıysa belirlenimcilik ihlali olarak raporlanır.

## 6. Analiz ve karar eşiği

**Birincil karşılaştırma.** C3 ↔ C0, 20 hedef fonksiyon, eşli.

**Birincil ölçütler (5).** U/100, P1/100, C/100, A/100, D/100.

**"Anlamlı kazanç"** iki koşulun ikisini de ister:
1. Eşli farkların (sonra − önce, fonksiyon başına 100 satır oranı) ortalamasının %95 güven aralığı sıfırı iyileşme yönünde dışarıda bırakır. Güven aralığı yüzdelik bootstrap'tır: 10 000 yeniden örnekleme, tohum `18419053266058711754` (SHA-256(`karadul-g8-bootstrap-2026-10-19`) ilk 16 basamak).
2. Havuzlanmış oran (toplam sayı / toplam satır × 100) iyileşme yönünde en az %25 göreli değişir. A için taban 0 ise sonradaki oranın 0'dan büyük olması yeter.

İyileşme yönü A için artış, öbür dört ölçüt için azalıştır.

**G8 kararı için önerilen eşik.** 5 birincil ölçütün en az ikisinde anlamlı kazanç varsa "geri yazma kazancı var" denir (plan v2 G8 kuralı: "ölçütlerin en az ikisinde anlamlı kazanç"). Planın adıyla andığı iki ölçüt U ve P1'dir; ikisi birlikte tutarsa kanıt güçlü sayılır.

**Öbür sonuçlar.**
- **Çağıranlar:** aynı analiz yapılır, ikincil sonuçtur; karar ona dayanmaz.
- **T ve L:** tanımlayıcıdır. T için medyan ve C3/C0 oranı verilir.
- **Ablasyonlar (C1, C2, C4):** tanımlayıcıdır, karar ölçütü değildir.
- **Eksik veri:** Bir koşulda decompile 30 saniyede bitmezse, o fonksiyon o koşulun eşli analizinden çıkar. Bu başarısızlık ayrıca sayılır ve raporlanır.

## 7. Bilinen sınırlamalar

- n = 20, tek program, tek yapı, tek derleyici ve SDK.
- Sonuç bir **üst sınırdır**. Bilgi kaynaktan gelir; Karadul'un kurtarabileceği bilgi daha azdır ve hatalı olabilir.
- Ölçütler metin üzerinde sözdizimsel vekillerdir, insan değerlendirmesi değildir. Düzenli ifadelerin bilinen sınırları `olcut.py`'de yazılıdır; örneğin `param_1[3]` biçimindeki sabit dizinli erişim P1'e girmez.
- Tek bir Ghidra sürümü (12.1.2) ve Karadul'un decompile ayarları kullanılır.

## 8. Kapsam dışı

MaxSMT ofset doğrulaması, Debian coreutils'te alan ofseti P/R ve SDK GDT üretimi bu deneye girmez (plan v2 G8'in öbür kalemleri; başka ajan ya da sonraki iş).
