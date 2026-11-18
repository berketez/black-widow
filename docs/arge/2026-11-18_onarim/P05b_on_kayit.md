# P05b — ön kayıt (anlamsal parametre adları: işaretçi tipi, kanıtsız `str`, kaybolan doğru adlar)

Bu belge `karadul/` kodu değişmeden ÖNCE yazıldı ve commit'lendi. Taban sayıları ölçüm betiğinin değişmemiş kodla (`ff4776a`, P05 sonrası `main`) ürettiği değerlerdir. "Sonra" sayıları her kalemden sonra aynı betikle, aynı girdilerle alınır. Bir beklenti tutmazsa "tutmadı" yazılır; kural ya da eşik sonradan değiştirilmez. Aşağıdaki kurallar (§3) sayılar görülmeden önce değil, taban sayıları görüldükten SONRA ama onarım kodu yazılmadan ÖNCE sabitlendi (bkz. "Önceden görülen").

**Önceden görülen (gizli değil):** P05'in bütün kaydı (`P05.md`: 29 kayıp, sınıflaması ve dört öneri), bu paketin taban koşusu (`once-ff4776a`; aşağıda §4'te sayılar) ve tabandaki ad × tip dağılımı (`count` 406 / `enabled` 241 işaretçi parametrede; `str` / `text` tip sezgisi adlarının 725'i kanıtsız, 712'si `long` / `ulong` parametrede). D setinde kuralların tek tek ne vereceği önceden denenmedi.

## 1. Araç ve girdiler
- Betik: `scripts/measurement/p05_olc.py` (`p05_olc/2`; P05'in betiği, ek ölçüler §2). Alt komutlar: `kos` (Ghidra'sız yeniden oynatma), `karsilastir`.
- **Set Y:** `~/karadul_olcum/runs/urun-yeni2-f30ac9a` (119 ikili). **Set D (DWARF):** T0b hizalaması olan 22 ikili (`~/karadul_olcum/runs/t0b-1acba60/hizalama`; sha256 koşulu P05'teki gibi).
- Taban kol: etiket `once-ff4776a` (değişmemiş kod). P05'in `k2` koluyla aynı hüküm sayılarını verdi (tam 57, yakın 67, yanlış 5 287): betik genişletmesi ölçüyü değiştirmedi.
- Çıktı: `~/karadul_olcum/runs/onarim-2026-11-18/P05b/yeniden/<etiket>/`.
- Gerekirse uçtan uca en çok 5 ikili (`urun_kos.py --paralel 1`, `PYTHONHASHSEED=0`).

## 2. Ölçüler
P05'in ölçüleri aynen (`ad_sinifi`: geçersiz / anahtar / tip / Ghidra adı / gövde çakışması; `matris_vektor`; DWARF hükmü `tam` / `yakin` / `yanlis`). Ek olarak (tanımlar betiğin başında):
- **Bildirilen tip:** betiğin KENDİ imza ayrıştırıcısı (`imza_tipleri`; ürünün `_PARAM_PARSE_RE`'sinden bağımsız). DWARF hükmünde parametre sayısı da buradan alınır (ürünün ayrıştırıcısı bu pakette değişiyor).
- **`isaretciye_skaler`:** `type_heuristic` adı skaler şablondan (`count`, `value`, `status`, `counter`, `n_size`, `enabled`, `threshold`, `scalar`, `factor`, `flags`, `buffer_size`, `handle`) ve bildirilen tip işaretçi.
- **`str_ailesi`:** ad tabanı `str` / `text` / `name` / `string`; sınıf `char_isaretci` (bildirilen `char *` / `const char *`), `kanitli` (betiğin bağımsız dizgi kanıtı: dizgi işlevinin dizgi konumunda argüman, `*(char *)` erişimi, karakter sabitiyle karşılaştırma), `kanitsiz`. Kaynak başına (`type_heuristic|kanitsiz` …).
- **`ipucu`:** gerekçesi `Caller hint` olan ad sayısı.
- **Kural payı (Kalem 3):** yeni kuralların adları gerekçe etiketiyle ayrılır; D'de kuralın adını verdiği parametrelerde bir önceki kolun hükmüyle karşılaştırma: Δdoğru, Δyanlış.

## 3. Onarımın ilkesi (kod yazılmadan önce sabit)

**K1 — imza ayrıştırma (Kalem 1).** Parametre bildirimi tek ayrıştırıcıdan geçer (dizisel ve paralel yol aynı işlevi kullanır):
- Ad, bildirimin sonundaki tanımlayıcıdır; tip, bildirimden ad çıkarılınca kalan metindir. İşaretçi derinliği korunur (`double *param_1` → `double *`, `char **argv` → `char **`). `const` / `volatile` / `restrict` tip eşleşmesinde atılır. Dizi parametresi işaretçiye iner (`char buf[16]` → `char *`). İşlev göstericisi (`void (*cb)(int)`) `code *` olur (Ghidra'nın yazımı). Ad ya da tip bulunamayan bildirim (`void`, `...`, yalnız ad) parametre sayılmaz.
- İmza deseni bir düzey iç içe ayraca izin verir (işlev göstericili parametre fonksiyonu düşürmez). Parametreler ayraç dengeli bölünür.
- **Tip uyumu:** bildirilen tip gerçek işaretçiyse (`*` içeriyor) skaler şablon (`int`, `long`, `bool`, `double` …) uygulanmaz; eski "şablon `long` / `ulong`, gerçek tip işaretçi → uyumlu" ters istisnası kalkar. İşaretçi derinliği farklıysa (`char **` ↔ `char *`) uyumsuz (bugünkü grup tablosu zaten böyle). Ghidra'nın işaretçi istisnası (tamsayı tipli `long` / `ulong` / `undefined8` parametreye işaretçi şablonu) kalır ama K2'nin kanıt şartına bağlanır.

**K2 — işaretçi şablonuna kanıt (Kalem 2).**
- `char *` şablonları (`str`, `text`, `name`): bildirilen tip `char *` (const dahil; Ghidra'nın tip çıkarımı dizgi işlevinin prototipinden yayılır) YA DA koddaki dizgi kanıtı: (E1) parametre, çıplak ya da tek cast'le, bir dizgi işlevinin dizgi konumunda argüman (C / POSIX prototipleri: `strlen`, `strcmp`, `strcpy`, `strchr`, `strstr`, `strdup`, `strtol`, `atoi`, `puts`, `fputs`, `getenv`, `fopen`, `open`, `printf` ailesi biçim konumu …; `_` önekli Mach-O ve `__X_chk` biçimleri); (E2) `*(char *)` ile erişim; (E3) `*p` / `p[i]` bir karakter sabitiyle (`'x'`) karşılaştırılıyor.
- Ghidra'nın işaretçi istisnasıyla tamsayı parametreye işaretçi şablonu ancak öğe erişimi kanıtıyla: `double *` / `float *` → kayan noktalı cast (P05, değişmez); `char *` → dizgi kanıtı; `unsigned char *` → bayt cast'li erişim (`byte`, `uchar`, `uint8_t`, `unsigned char`, `undefined1`); `int *` → 4 baytlık tamsayı cast'li erişim (`int`, `uint`, `int32_t`, `uint32_t`, `undefined4`); `void *` → herhangi bir cast'li erişim (`*(T *)p` / `*(T *)(p + …)`).
- Kanıtsız aday düşer; parametre sıradaki uygun şablonu alır ya da adsız kalır. Kanal susturulmaz (K-2).

**K3 — kaybolan doğru adlar (Kalem 3).** Yayılım kanalına (`call_graph_propagation`) dört kanıt türü; her birinin gerekçe etiketi ayrı:
- (a) **dizgideki çağrı metni** (`string_call`): çağıranın bir dizgi sabitinin içinde `<callee>(` geçiyor (ör. `_serverAssert("lpRandomPairsUnique(lp, count, keys, vals, tuple_len) == count", …)`). Dizgideki argüman sayısı callee'nin imzasındaki parametre sayısına eşit olmalı; argüman düz tanımlayıcı, tamamı büyük harf değil (makro / sabit), `NULL` / `true` / `false` değil. Güven 0,75 (yayılım tabanı; azaltma yok: kaynak metin). Çağıranın bildirdiği değişken olma şartı aranmaz (kaynak koddaki ad).
- (b) **adlı küresel / fonksiyon argümanı** (`named_symbol`): argüman düz tanımlayıcı, çağıranda bildirilmemiş, Ghidra biçimli değil, `_` ile başlamıyor (C'de ayrılmış ad), tamamı büyük harf değil. Güven 0,75 × 0,9² = 0,6075 (iki adımlı yayılımla aynı).
- (c) **dereferans** (`deref`): argüman `*x`, `x` çağıranda bildirilmiş değişken (P05 kuralıyla aynı şartlar); ad `x`. Güven P05'in değişken yayılımıyla aynı (0,675).
- (d) **çağrı yerleri oylaması** (`vote`): aynı katmandaki (değişken + dereferans) adaylar bütün çağıranların bütün çağrı yerlerinden toplanır, ad tabanına (sondaki `_N` eki atılmış) göre sayılır; en çok çağrı yerinin verdiği taban kazanır, eşitlikte ilk görülen (çağıran sırası, sonra kod sırası); yazılan ad o tabanın ilk görülen biçimi. Katman sırası: (a) > değişken / dereferans > (b) > iki adımlı bilinen ad.
- Bütün adlar P05'in tek ad kapısından geçer (geçersiz ad 0 kalmalı).
- **Kural kalma ölçütü (D, kural başına, Kalem 3 kolu ↔ Kalem 2 kolu):** kuralın adını verdiği parametrelerde Δdoğru ≥ 1 VE Δyanlış ≤ 0 ise kural kalır; değilse kural koddan çıkarılır, kayıtta "tutmadı" yazılır. (Gerekçe: "yanlış ad artmasın" beklentisi kural başına uygulanır; aynı veriyle eşik seçilmez, yalnız kalır / çıkar kararı verilir.)

**K4 — `CALLER_NAME_HINTS` (Kalem 4).** Çağıranın adı belirteçlere bölünür (`_` ve küçük → büyük harf geçişi; küçük harfe indirilir; baştaki `_` atılır). İpucu adının belirteç dizisi, çağıranın belirteç dizisinde ardışık alt dizi olarak geçmeli (`assemble_global` ↔ `my_assemble_global_v2` evet; `g` ↔ `assemble_global` hayır; `FUN_00101000` hiçbir ipucunu almaz). Eski iki yönlü alt dizgi kuralı kalkar.

**K5 — `p09_olc.py` `_YEREL` (Kalem 5).** Tip ile ad arasında boşluk ya da `*` zorunlu; `return` / `goto` / `break` gibi deyimler bildirim sayılmaz. P09 ölçümüne etkisi aynı girdilerle önce / sonra sayılır.

## 4. Beklentiler
Taban (`once-ff4776a`, Y 119 ikili / D 22 ikili):

| Ölçü | Taban |
|---|---|
| Toplam ad | 13 830 |
| Kusurlu ad (geçersiz + anahtar + tip + Ghidra adı + gövde çakışması) | 0 |
| `isaretciye_skaler` | 656 (`count` 406, `enabled` 241, `threshold` 6, `handle` 2, `value` 1) |
| `str_ailesi` `type_heuristic\|kanitsiz` | 725 (`long` 437, `ulong` 275, `long *` 11, `ulong *` 2) |
| `str_ailesi` `call_graph_propagation\|kanitsiz` | 122 (kapsam dışı: çağıranın değişken adından yayılım) |
| `ipucu` | 0 |
| D: tam / yakın / yanlış | 57 / 67 / 5 287 (doğru 124) |

- **Kalem 1:** `isaretciye_skaler` = 0. Tutmadı: > 0. Kusurlu ad 0 kalır. D'de yanlış ≤ 5 287.
- **Kalem 2:** `type_heuristic|kanitsiz` ≤ 36 (tabanın %5'i; betiğin bağımsız kanıt denetimi ürününkinden dar olduğu için sıfır beklenmez; kalanlar tek tek okunur). Tutmadı: > 36. D'de yanlış ≤ Kalem 1 kolu.
- **Kalem 3:** (birincil) D'de doğru (tam + yakın) ≥ 141; (ikincil, birincil tutmazsa) P05'in 17 gerçek kaybının (aşağıda) en az 9'unda yeniden doğru ad. İkisi de tutmazsa "tutmadı". Kural payı K3 ölçütüyle. Kusurlu ad 0. D'de yanlış ≤ 5 287 (taban).
- **Kalem 4:** Y'de `ipucu` taban 0 → etkisi birim testinde görünür (kısa adlı çağıran ipucu almaz; tam belirteçli çağıran alır). Y'de ad değişimi beklenmez.
- **Kalem 5:** sayı yön beklentisi yok; P09'un `p09_olc.py` sayıları önce / sonra yazılır.

**P05'in 17 gerçek kaybı** (`fark_once_k2.json`; ikili / fonksiyon / parametre / P05 öncesi ad):
- dizgi çağrı (5): redis-check-aof `lpRandomPairsUnique` param_2 `count`, param_3 `keys`, param_4 `vals`, param_5 `tuple_len`; `rdbSaveObject` param_4 `dbid`.
- adlı küresel / fonksiyon (6): chgrp `FUN_00107780` param_5 `free`; htop `CRT_setColors` param_1 `CRT_colorScheme`; redis-check-aof `bioCreateLazyFreeJob` param_1 `lazyFreeErrors`, `mstrFree` / `mstrGetAllocPtr` / `mstrNewWithMeta` param_1 `mstrFieldKind`.
- dereferans (4): sqlite3 `FUN_0012a324` / `FUN_0012a5c0` / `FUN_0012a6c0` param_1 `ppDb_2`; zstd `FUN_0010c400` param_1 `ctx_458`.
- çağıran sırası (2): redis-check-aof `genericZpopCommand` param_6 `count_252`; `sdscatrepr` param_3 `len_365`.

## 5. Kapsam dışı (bilerek)
- Skaler şablonların skaler parametrelerdeki genel adları (`count` 5 199 `long` / `int`, `enabled` 1 165 `int` / `uint`): kanalın kesinlik sorunu; ayrı ön kayıtla kanal başına eşik (P05 §Riskler).
- `_FUNC_SIG_RE`'nin tanımadığı dönüş tipleri (`uint64_t`, `int32_t`, `__off_t`: cat'te 296 fonksiyonun 11'i adlandırıcıya hiç girmiyor). Düzeltmek ad sayısını artırır (kanal %0,5 kesinlikte); sayısı kayda geçer.
- Yayılımın çağıran değişken adından getirdiği `str` (122): kanıt türü değişken adıdır, şablon değil.
- `api_param_db`, `c_namer.py` (P12), `name_validity` (kendi dosyası).
- `masum_kapi_esik.json`'a yazılmaz.
