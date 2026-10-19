# G7 alıcı tip kümesi saflığı: ön kayıt

- **Yazıldığı an:** 2026-10-19 13:35 (+0300). Hiçbir kenar, küme, çapa sayısı, saflık ya da kapsam hesaplanmadı. Ölçümden önce görülenler §11'de.
- **Plan kalemi:** plan v2 §5 G7 ("alıcı tip kümesi saflık deneyi"), "G8 karar kuralları" 3. satır ("Alıcı tip kümeleri saf (≥ %90) ve kapsamlı → Faz 1'de tarifin nesne kaynağı bu kümelerdir"), §2 madde 5, §3 madde 1 ve 4, §5 G16-G17; Onuncu Adam İ7 yöntem 1.
- **Değişiklik kuralı:** Bu belge ve mühürlenen betikler (§13) ölçümden sonra değiştirilmez. Sapma ya da hata düzeltmesi gerekirse gerekçesiyle `onkayit_notlari.md`'ye yazılır; düzeltmeden önceki ve sonraki sonuç ikisi birden raporlanır.
- **Künye:** taban v2 koşusu `taban-v2-62ad154` (Karadul `62ad154`, Ghidra 12.1.2 PUBLIC, Python 3.12.7). Ön kayıt yazılırken depo `c52db1a`. Ghidra yeniden çalıştırılmaz.
- **Girdiler (sha256'nın ilk 16 hanesi; tamamı `sonuc.json` künyesinde):**

| Program | functions.json | pcode.jsonl | naming_map.json | macho_score.json | strip'li ikili |
|---|---|---|---|---|---|
| tmux | `850acc8ef0f21a59` | `c18f887a43b6e1ea` | `e200874f5d169abf` | `28733b8e03198f06` | `10fa041195a82395` |
| htop | `eb09a314f1d8d7e0` | `a4550b03d9c9ba8d` | `75888a1fb6642e46` | `0fe94c036e224555` | `50d172cee23cb6f5` |

`scripts/measurement/tarif_olc.py` `e9747d77c35e68f1` (Karadul çapası buradan import edilir).

## 1. Soru, hipotezler ve beklentiler

**Soru.** İsim bekleyen fonksiyonlar, ilk parametrelerinin taşıdığı nesne tipine göre Steensgaard tarzı birleştirmeyle kümelenirse (a) kümeler GT ad öneklerine göre ne kadar saftır, (b) isim bekleyenlerin yüzde kaçı adı güvenilir biçimde bilinen bir fonksiyonla (çapa) aynı kümeye düşer? Bu, G16-G17'de tarifin "nesne" kaynağı olacak yöntemin bilgi tavanını ve saflığını ölçer.

- **H1 (saflık).** Birincil kümeleme (V1) GT önekine göre rastgele bölümlemeden belirgin biçimde saftır (§7).
- **H2 (eşik).** V1'in ağırlıklı saflığı ≥ %90'dır (plan eşiği; §8'deki iki düzeyle okunur).
- **H3 (kapsam).** İsim bekleyenlerin kayda değer bir kısmı çapalı bir kümeye düşer. Planda sayısal eşik yok; bu ön kayıt da koymaz (§8).
- **H0.** Kümeler rastgele bölümlemeden belirgin biçimde saf değildir.

**Beklentiler (karar etkisi yok; yalnız tahminin kaydı).** tmux V1 ağırlıklı saflık Ö1'de %85-95, Ö2'de %60-75 (üç parçalı adlarda ikinci parça çoğu zaman fiil: `window_set_name` → `window_set`). htop Ö1'de %60-80 (alt sınıf yöntemi taban sınıf yöntemini çağırır: `CPUMeter_*` → `Meter_*`). Kümeye düşme: tmux %40-60, htop %30-50. Ç-O çapalı kapsam: tmux %20-40, htop %10'un altında. Ç-K çapalı kapsam: tmux %10-25, htop ~%0 (Karadul çapası ikilide aynen geçen, küçük harfli ve alt çizgili bir ad istiyor; htop'un kendi tanımlayıcıları büyük-küçük harf karışık).

## 2. Veri, evren ve popülasyon

- **Programlar:** yalnız geliştirme setinden tmux ve htop, ayrı ayrı. Test ve doğrulama seti programlarına dokunulmaz.
- **Evren (U):** taban v2 `functions.json`'ındaki iç (`is_external` yanlış), thunk olmayan fonksiyonlar: tmux 2588, htop 597. Evren kümelerin köprü düğümlerini de içerir (`.cold`/`OUTLINED` parçaları, GT'de satırı olmayan 27 tmux fonksiyonu).
- **Popülasyon (P, isim bekleyen):** `macho_score.json` `rows` içinde `sinif == "program"`: tmux 2545, htop 597. Bütün oranların paydası P'dir (p1'i olmayan ve tek parçalı adlı fonksiyonlar dahil).
- **GT:** satırın `gt` listesi; Mach-O'nun baştaki tek `_` öneki atılır.
- **Kaynak seçimi: decompile C** (`static/ghidra_output/decompiled/<ad>.c`). p-code (`pcode.jsonl`) birleştirme için kullanılmaz:
  - varnode'lar yalnız (uzay, ofset, boyut) olarak yazılmış, SSA kimliği yok;
  - MULTIEQUAL, INDIRECT ve CAST seçici listede yok (`config.py` `pcode_selective_ops`);
  - bu yüzden x0'dan okunan değerin giriş parametresi mi, bir çağrının dönüş değeri mi olduğu ayırt edilemiyor. Örnek: `FUN_1000a4ee8`'de aynı `[register, 0x4000, 8]` varnode'u hem `___error()` dönüşü hem `param_1`.
  - Ghidra C'de giriş parametresini `param_1` adlı yüksek değişken olarak yazar; değişip değişmediği metinden denetlenebilir.
  - p-code yalnız tanı için kullanılır (§9).

## 3. Birleştirme kuralı

### 3.1 V1 (birincil): doğrudan çağrı, p1 → p1

Her A ∈ U için decompile C metni üzerinde (`cikar.py`):

1. **Hazırlık:** Ayrıştırma `// --- DISASSEMBLY` satırından önceki metinde yapılır. Yorumlar silinir; dize ve karakter sabitlerinin içi maskelenir (`"S"`), böylece sabitlerdeki ayraç ve virgüller çözümlemeyi bozmaz.
2. **İmza:** A'nın adının ilk geçtiği `ad(` konumundan dengeli ayraçla parametre listesi alınır; üst düzey virgüllerle bölünür. Parametre adı, bildirimin son tanımlayıcısıdır. `void` ya da boş liste: parametre yok. **p1** = ilk parametrenin adı.
3. **"p1 değişti" (A için):** A'nın gövdesinde şunlardan biri varsa p1 değişmiş sayılır ve A **hiç V1 kenarı üretmez**:
   - `p1 =` ya da bileşik atama (`+=`, `-=`, `<<=` …). Yalnız p1'in kendisi sol taraftaysa sayılır: kendinden önceki boşluk dışı karakter `; { } ( , = : ?` ya da `else`/`do` sözcüğü olmalıdır. `*p1 = …` ve `*(T *)p1 = …` işaretçi üstünden yazmadır, sayılmaz.
   - `p1++`, `p1--`, `++p1`, `--p1`.
   - tekli `&p1` (adres alınması).
4. **Çağrılar:** gövdedeki her `tanımlayıcı(` (önünde `.`, `->` ya da harf/rakam yok; C anahtar sözcüğü değil) için, tanımlayıcı `functions.json`'da bir fonksiyon adıysa:
   - iç ve thunk olmayan fonksiyon → kendisi;
   - Ghidra'nın `thunk_FUN_<adres>` iç thunk'ı (`source == DEFAULT`) → hedefine çözülür (zincir izlenir);
   - içe aktarma, dış fonksiyon ve öteki thunk'lar → kenar üretmez.
5. **Argümanlar:** dengeli ayraçla alınır, üst düzey virgüllerle bölünür. Baştaki dönüşümler (`(long)`, `(undefined8 *)` …) ve dış ayraçlar soyulur. İçinde ayraç olan dönüşümler (işlev işaretçisi tipi) soyulmaz.
6. **Kenar:** B ≠ A, B iç fonksiyon, A'nın p1'i değişmemiş ve soyulmuş **1. argüman tam olarak p1'in adı** ise A.p1 ≡ B.p1 (birleştirme bul-birleştir ile).
   - **Alan yükleme** (`*(T *)(p1 + c)`, `p1[i]`), **ofsetli adres** (`p1 + c`) ve öteki her ifade aynı tipe katılmaz.
   - Dolaylı çağrılar (`(*(code *)…)(…)`) V1'e girmez.
7. **Küme:** (f, 1) düğümlerinin denklik sınıfları. küme(f) = {g ∈ U : (g,1) ~ (f,1)}; düğümü olmayan fonksiyon tekildir. Küme boyutu evrendeki üye sayısıdır.

### 3.2 Değişkenler (ikincil; G8 okuması yalnız V1 ile)

- **V1-N (nesne korumalı):** V1 kenarı A → B yalnız B'nin p1'inde alan kanıtı varsa sayılır. Alan kanıtı B'nin gövdesinde şunlardan biridir:
  - `*(T *)(p1 + c)`, c ≥ 1 ve T karakter benzeri değil (`char`, `uchar`, `byte`, `undefined1`, `undefined`, `bool` …);
  - `p1[c]`, c ≥ 1, p1'in bildirilen tipi karakter benzeri olmayan bir işaretçi;
  - `p1->`.
  - Amaç: GT'siz bir korumayla çok biçimli çağrılanların (`xstrdup`, `xreallocarray`, log sarmalayıcıları gibi genel işaretçi alanlar) bütün tipleri tek kümede birleştirmesini önlemek (TK-13'teki nesne fabrikası sorunu).
- **V2 (bütün konumlar):** A'nın değişmemiş k. parametresi B'nin j. argümanı olarak aynen geçiyorsa A.pk ≡ B.pj. Küme yine (f,1) sınıfıdır. V1'in bütün kenarlarını içerir.
- **V1+T (tablo yuvası kardeşliği, yan sınama):**
  - V1'e ek olarak `/usr/bin/dyld_info -fixups <strip'li ikili>` çıktısındaki `rebase` yuvaları kullanılır. Bunlar Ghidra'nın relocation tablosuna yazdığı chained fixup'larla aynı veridir; Ghidra yeniden çalıştırılmadığı için ikiliden okunur.
  - Yuvalar (segment, bölüm) başına adrese göre sıralanır. Ardışık iki yuva arası tam 8 bayt olan en uzun diziler "koşu"dur.
  - Koşudaki hedeflerden iç fonksiyon girişi olanlar alınır (thunk'lar çözülür). İmzasında en az bir parametre olanlar ayıklanır. Koşuda böyle en az iki ayrı fonksiyon varsa (f,1) düğümleri birleştirilir.
  - Gerekçe: nesne yönelimli C'nin işlem tabloları (tmux `window_mode`, htop `MeterClass`) aynı alıcının geri çağrılarını bitişik yuvalarda tutar.
  - Bilinen riskler: bitişik iki yapı örneği tek koşuya birleşebilir; taban sınıfın ortak yöntemi (paylaşılan `delete` gibi) alt sınıf ailelerini köprüler.
  - Bu bir çağrı hedefi çözümü değildir; dolaylı çağrı yerleri çözülmez. Ucuz olduğu için ayrı satırda raporlanır.

## 4. Çapalar

Çapa, adı güvenilir biçimde bilinen fonksiyondur. Dört tür ayrı raporlanır:

| Tür | Tanım | GT kullanır mı |
|---|---|---|
| **Ç-G** (Ghidra/export) | Evrende, P dışında, adı `FUN_`/`thunk_` ile başlamayan ve `source != DEFAULT` olan iç fonksiyonlar. Ghidra'nın kendisinin bildiği adlardır. `macho_score` özeti iki programda da `ghidra_known_from_exports = 0` diyor; bu kümenin boş çıkması bekleniyor | Hayır |
| **Ç-O** (kâhin) | P'deki fonksiyonun GT adlarından biri strip'li ikilinin `strings -n 4` satırlarında aynen (tam satır) geçiyor; `__func__`, assert ve log dizeleri gibi. `strings` PATH'teki araçtır, çağrı `tarif_olc` ile aynıdır. Kusursuz bir "kendi adı" tespitçisinin (KS-1) tavanıdır. Çapanın adı o GT adıdır. Ç-G ile birleşimi raporlanır | Evet |
| **Ç-K** (Karadul) | `tarif_olc.reliable_names(koşu, ikili)`: Karadul'un bugünkü adlarından ikilide aynen geçen, `[a-z][a-z0-9]*(_[a-z0-9]+)+` biçiminde, en az 8 karakterli, `_N` soneksiz olanlar. Çapanın adı Karadul'un adıdır. Ç-G ile birleşimi | Hayır |
| **Ç-K+** (doğru Karadul) | Ç-K'nin, Karadul adı GT adlarından birine aynen eşit olan alt kümesi. Çapa hatalarının etkisini ayırmak içindir | Evet (yalnız süzgeç) |

Ç-K'nin kesinliği (|Ç-K+ ∩ P| / |Ç-K ∩ P|) ayrıca raporlanır.

## 5. Önek ve saflık

- **Parçalar:** ad `_` ile bölünür, boş parçalar atılır (`__x_y` → `x`, `y`).
- **Ö1 (modül düzeyi):** ilk parça. `window_pane_resize` → `window`; `CPUMeter_init` → `CPUMeter`.
- **Ö2 (nesne düzeyi):** son parça hariç, en çok iki parça. Üç ve daha çok parçalı adda ilk iki parça (`window_pane_resize` → `window_pane`; `server_client_lost` → `server_client`). İki parçalı adda ilk parça (`window_resize` → `window`). Yalın "ilk iki parça" tanımı iki parçalı adda adın kendisini verirdi; onu önlemek için.
- **Tek parçalı adlar** (`xmalloc`, `main`): öneki yok. Saflığa girmez; düzey başına sayısı ayrı raporlanır.
- **Çok adlı GT** (tmux'ta 8 satır, katlanmış RB ağacı fonksiyonları): üyenin önek kümesi, adlarının öneklerinin kümesidir. Bir önekin sayımına, önek kümesinde o önek bulunan her üye 1 katar.
- **Değerlendirilen küme:** en az 2 öneki olan P üyesi bulunan küme. Değerlendirilen üyeler yalnız bunlardır.
- **Küme saflığı:** en sık önekin sayımı / değerlendirilen üye sayısı.
- **Özetler (program ve düzey başına):**
  - **ağırlıklı (mikro) saflık** = Σ en sık önek sayımı / Σ değerlendirilen üye. Karar ölçüsü budur.
  - makro ortalama, medyan, çeyrekler, eşik (%90) üstü küme payı;
  - üye sayısına göre dilimler: 2, 3-5, 6-10, 11-50, 51-200, 201+;
  - ağırlıklı saflığın %95 aralığı: kümeler yerine konarak yeniden örneklenir, B = 1000.
- Programlar birleştirilmez; her biri ayrı raporlanır (plan §3.4, program türü başına).

## 6. Kapsam

Payda her zaman P'dir. Oranlar Wilson %95 aralığıyla verilir. Ayrıca talimat ağırlıklı verilir; talimat sayısı decompile dosyasının `DISASSEMBLY (N instructions)` satırından alınır.

- **K0, kümeye düşme:** |küme(f)| ≥ 2 olan f ∈ P. **Tekil** = 1 − K0.
- **K1, çapalı kümeye düşme:** f'nin kümesinde f'den başka en az bir çapa var. Çapa türü başına ayrı (Ç-G, Ç-O, Ç-K, Ç-K+). Kendisi çapa olan f, ancak kümesinde başka bir çapa varsa sayılır. P içindeki çapa sayısı ayrıca verilir.
- **Saf ve çapalı (kâhin niceliği):** f'nin kümesi o düzeyde saflığı ≥ %90 olan değerlendirilen bir küme ve kümede f'den başka bir çapa var. Saflık GT'ye dayandığı için bu bir tavandır.
- **Yayılım benzetimi:** G16-G17'deki "çelişkide isim verilmez" kuralının sınaması. Her düzey ve çapa türü için, çapa olmayan her f ∈ P'ye şu uygulanır:
  1. Kümesindeki öteki çapaların adlarının o düzeydeki önekleri toplanır. Öneksiz çapalar yok sayılır.
  2. Tek bir önek kalıyorsa (oybirliği) o önek önerilir. Birden çok önek varsa "çelişki"dir, öneri yapılmaz.
  3. Öneri, f'nin GT önek kümesinde o önek varsa doğrudur.
  - Raporlananlar: öneri oranı (payda P), kesinlik (payda: GT'si önekli öneriler), doğru öneri kapsamı (payda P), çelişkiden susan sayısı.
  - Ç-O'da çapanın öneki GT'den, Ç-K'de Karadul adından gelir. GT öneriyi etkilemez, yalnız puanlar.
- **Kıyas çizgisi (bilgi için):** Karadul'un taban v2'de isim verdiği oran (`macho_score` `siniflar.program.named / population`).

## 7. Negatif kontrol

- Değişken ve düzey başına, değerlendirilen üyelerin önek kümeleri havuzlanır.
- Havuz rastgele karıştırılır ve gerçek kümelerin boyutlarıyla aynı sırada parçalara bölünür. Böylece küme boyutu dağılımı korunur.
- Ağırlıklı saflık yeniden hesaplanır. R = 1000 kez.
- Tohum: SHA-256(`karadul-g7-alici-tip-2026-10-19-<program>-<değişken>-<düzey>-k`) değerinin ilk 16 onaltılık hanesi; Python 3.12 `random.Random`. Bootstrap tohumu aynı biçimde, sonek `-b`.
- p = (1 + gerçek değere eşit ya da büyük karışık değer sayısı) / (R + 1).
- **Geçerlilik:** p < 0,01 **ve** gerçek − karışık ortalama ≥ 10 puan. Koşul tutmazsa o düzeyin saflık sonucu "negatif kontrolü geçmedi" diye kaydedilir.

## 8. G8 karar kuralının okunuşu (ön kayıtlı, mekanik)

Okuma birincil değişken V1 ile, program başına yapılır (`deney.py` `reading`):

| Koşul (V1, ağırlıklı saflık) | Okuma |
|---|---|
| Ö1 < %90 | **saf değil** |
| Ö1 ≥ %90 ama Ö1 negatif kontrolü geçmedi | **geçersiz** (saflık rastgele bölümlemeden belirgin değil) |
| Ö1 ≥ %90, kontrol geçti; Ö2 ≥ %90 ve Ö2 kontrolü geçti | **saf** |
| Ö1 ≥ %90, kontrol geçti; Ö2 < %90 ya da Ö2 kontrolü geçmedi | **yalnız Ö1 düzeyinde saf.** Kümeler modül önekini taşır, nesne önekini değil |

- **Genel okuma:** iki programda da "saf" ise "saf". Okumalar farklıysa "programa bağlı". İkisi aynıysa o okuma.
- **"Kapsamlı":** planda sayısal eşik yok, bu ön kayıt da koymaz. Kapsam §6'daki biçimlerle raporlanır; "kapsamlı mı" kararını ana oturum verir. Rapor, G8 satırının kapsam yarısı için bir okuma yazmaz, yalnız sayıları ve kıyas çizgisini verir.
- Değişkenler (V1-N, V2, V1+T) G8 okumasını değiştirmez. Yalnız G16-G17 tasarımı için bilgi verir.

## 9. Tanılar (kuralı değiştirmez)

- **p-code uyumu:** V1 çağrı yerlerinin, A'nın p-code'unda aynı hedef adrese giden ve ilk veri girdisi x0 (`[register, 0x4000, *]`) olan bir CALL bulunan payı.
  - %90'ın altındaysa uyumsuz çağrı yerlerinden 20'si elle incelenir. Seçim: adres sırasındaki uyumsuz yerlerden `random.Random(olcut.seed_for(<program>, "pcode")).sample(…, 20)`.
  - Her biri şöyle sınıflandırılır: C çözümleme hatası / p-code biçim sınırı (CAST, SSA yokluğu) / öteki.
- **Çözümleme durumu:** imzası bulunamayan dosya sayısı, çözülemeyen `FUN_` çağrısı sayısı. Ayrıca p1'i olmayan ve p1'i değişen (V1'de kenar üretmeyen) isim bekleyen sayısı.

## 10. Raporlanacaklar (program × değişken)

- küme sayısı ve boyut dağılımı, en büyük küme, en büyük kümedeki isim bekleyen payı;
- saflık: Ö1 ve Ö2'de ağırlıklı, makro, medyan, çeyrekler, dilimler, bootstrap aralığı;
- negatif kontrol;
- K0, tekil, K1 (dört çapa türü), talimat ağırlıklı kapsam;
- saf ve çapalı kapsam, yayılım benzetimi;
- saflığı %90'ın altındaki en büyük 5 kümenin önek dağılımı ve örnek adları (adlar geliştirme setinden, rapora yazılabilir).

Küme üyelikleri `workspaces/2026-10-19_g7/veri/`'de (git dışı) durur.

## 11. Ölçümden önce görülenler (şeffaflık)

- **Veri biçimleri:** decompile C dosyaları, `pcode.jsonl` (ilk satırlar), `functions.json`, `xrefs.json`, `decompiled.json`; `macho_score.json` özeti ve ilk satırları. Özetten görülenler: P boyutları, `ghidra_known_from_exports = 0`, Karadul'un isim verdiği sayılar (tmux 857/2545, htop 101/597).
- **Fonksiyon dökümü:** `functions.json`'da thunk, dış ve satırsız fonksiyon sayıları. `FUN_` ile başlamayan, thunk olmayan tek iç fonksiyon tmux'ta `entry`'dir ve P'dedir; htop'ta böyle fonksiyon yok.
- **GT adları:** program başına tohumlu rastgele 25 GT adı ve parça sayısı dağılımı (tmux 1/2/3/4/5+ parça: 44/379/934/791/397; htop: 76/509/12/0/0). Ö2'deki fiil parçası sorunu bu örnekte görüldü.
- **G8 ön kaydındaki kaynak sayımları:** ilk parametresi `window_pane` olan 125, `client` 189, `window_mode_entry` 127, `format_tree` 225 tanım.
- **Çözümleyici sınaması:** 4 gerçek tmux fonksiyonu elle okundu (`FUN_100001f98`, `FUN_1000a4ee8`, tohumlu rastgele `FUN_10007073c`, `FUN_1000040f4`). Sonuncusunun C'sinde `"args_make_commands"` dizesi geçiyor.
- **Çözümlenebilirlik:** tmux 2588 ve htop 597 dosyanın hepsi "tamam" çözümlendi.
- **grep taraması:** tmux C'sinde `param_1` geçen argüman biçimleri (ör. `X(param_1,` 1565 kez); `param_1`'e atama içeren dosya sayısı (tmux 218); dolaylı çağrı biçimleri.
- **dyld_info:** satır biçimi ve satır türü sayıları (tmux 5993 rebase / 232 bind; htop 1250 / 220).
- **Hesaplanmayanlar:** kenar, küme, çapa sayısı, saflık, kapsam, negatif kontrol, p-code uyumu.

## 12. Önceden bilinen sınırlamalar

1. Yalnız iki program, ikisi de geliştirme setinden. Sonuç yöntemin tasarımı içindir; doğrulama setinde yeniden ölçülmeden makale iddiası olmaz.
2. GT ad öneki tipin vekilidir, tipin kendisi değildir.
   - Aynı tipi alan fonksiyonlar farklı öneklerle adlandırılabilir: tmux'ta `cmd_*_exec` hepsi `struct cmd *` alır; htop'ta alt sınıflar taban sınıf işaretçisi alır.
   - Farklı tipler aynı ilk parçayı paylaşabilir (`window` ile `window_pane`).
   - Ö1 birinci durumda saflığı olduğundan yüksek, Ö2 ikinci durumda olduğundan düşük gösterebilir.
3. Çözümleyici metin tabanlıdır. Kopyalanan yerel takma adlar (`lVar1 = param_1; B(lVar1)`) kaçırılır; p1'i bir kez bile atanan fonksiyonun bütün kenarları atılır (tutucu).
4. Darwin'de değişken argümanlar yığından geçtiği için Ghidra log çağrılarının `__func__` argümanını göstermiyor. Bu birleştirmeyi etkilemez, Ç-O'yu etkilemez (dize ikilide).
5. Ghidra'nın çözemediği atlama tabloları gövdeleri eksik bırakabilir ("Could not recover jumptable", tmux'ta 240 uyarı).
6. Dolaylı çağrılar çözülmez. V1+T yalnız tablo kardeşliğidir.
7. Ç-O bir tavandır: kendi adını içeren dizenin hangi fonksiyona ait olduğunu bilmek bugün Karadul'da yok (KS-1, G11-G12).

## 13. Dosyalar ve mühür

Mühürlenenler (bu dizin): `onkayit.md`, `cikar.py` (çıkarım), `olcut.py` (ölçüt tanımları), `deney.py` (kümeler, ölçüm, okuma), `sinama_cikar.py`, `sinama_olcut.py` (sınamalar).

- Mühür dosyası: `workspaces/2026-10-19_g7/veri/onkayit_muhur.txt` (zaman damgası ve sha256'lar).
- Ölçüm sırası: `cikar.py tmux`, `cikar.py htop`, `deney.py`. Günlükleri `workspaces/2026-10-19_g7/log/`.
- Çıktılar: `sonuc.json` ve `rapor.md` (bu dizin).
