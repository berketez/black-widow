# HZ-4a — döküm adımlarında tek başvuru geçişi ve yineleyiciler (ilerleme)

İş emri: `docs/arge/2026-11-23_dalga1/gonderim/HZ4a.md`. Dal `worktree-agent-aafb4378ffb9a2eb9`, taban main `2263c887` (ürün kodu `534e252b` ile aynı; aradaki commit'ler belge). Başlangıç 2026-11-24 13:56; sert son 16:10. Koşu kökü `~/karadul_olcum/runs/dalga1-2026-11-23/HZ4a/`.

## Durum

| # | Kalem | Durum | Commit |
|---|---|---|---|
| 1 | Profil betiği (`scripts/arge/hiz/hz4a_profil.py`) | yazıldı; vekil Ghidra'sız (yalın JPype) sınandı | `5a570ee5` + ek |
| 2 | Profil (H0), Ollama dilimi | **bitti** (14:25–14:31): baskın maliyet çağrı sayısı (CFG sınırda), oran 0,111 | bu commit |
| 3 | Ön kayıt | commit'lendi (profilden sonra, koddan ve sonra ölçümlerinden önce) | `9e9b2400` |
| 4 | Kod + testler + mutasyon | kod `0f2fefc0`, testler `fb1f2142` (30 test; commit iletisindeki "31" yanlış sayım), mutasyon `d8d0d2b7` (30 / 30; eski sekiz tanım 170 / 170), yama `f144b9c9` | → |
| 5 | H5 (sqlite3, 1 sn bütçe) | bekliyor | |
| 6 | H1 / H4 (S8) | bekliyor | |
| 7 | H2 / H3 / H6 (T25) | bekliyor | |
| 8 | Tam takım | bekliyor | |

## Doğrulanan API imzaları (Ghidra 12.1.2, yerel `javap`; `SoftwareModeling.jar`)

- `ReferenceManager.getReferenceSourceIterator(AddressSetView, boolean) → AddressIterator`
- `ReferenceManager.getReferencesFrom(Address) → Reference[]`, `getReferencesTo(Address) → ReferenceIterator`
- `ReferenceManager.hasReferencesTo(Address) → boolean`
- `Listing.getInstructions(AddressSetView, boolean) → InstructionIterator`
- `AddressIterator extends Iterator<Address>, Iterable<Address>`; `Address.compareTo`, `Address.getOffset() → long`
- `SymbolType.getID() → byte`; `SymbolType.equals` ad + ad alanı bayrağını karşılaştırıyor (bayt kodu okundu)
- `Program.getModificationNumber()` (aşağıda yeniden denetlenecek)

**Sıra güvencesi:** yerel belge (`docs/GhidraAPI_javadoc.zip`) `getReferenceSourceIterator` için yalnız "forward - true means to iterate in the forward direction" diyor; "artan adres" sözü YOK. Bu yüzden sıra kodda denetlenir (ardışık adreslerde `Address.compareTo`) ve bozuksa o fonksiyon eski yürüyüşe düşer; sınaması yazılacak. Gerçek veride sıranın bozulup bozulmadığı profilde sayılıyor.

## Profil yöntemi (hüküm 2)

Ürün kodu değişmeden, `hz4a_profil.py --kip profil`: ikili ürünle aynı yoldan açılır ve çözümlenir (`pyghidra.open_program` + `GhidraHeadless._run_auto_analysis`; ayar OL2'nin T25 YAML'ı: ObjC ileti çözümleyicisi kapalı), decompile / BSim koşmaz. Üç döküm işlevi bir **sayaç vekili** üstünden çağrılır: her Java çağrısı sınıf.yöntem başına sayılır, süresi (yalnız Java çağrısının çevresi) toplanır. Ayrıca: gövde adresi ↔ başvurusu olan adres sayısı, genel simge döngüsü tek başına (eski ↔ `hasReferencesTo`), yalın geçiş tabanı (önemsiz çağrı başına µs), adım başına GC süresi. Decompile koşmadığı için JVM yığını ürün koşusundakinden boştur: GC payı alt sınırdır (yazıldı).

**14:18 — bekliyorum (profil):** `HZ4a profil:ollama` 14:08:43'ten beri kuyrukta (yuva 1'de PUV6b'nin S8'i, yuva 2'de HZ2'nin S8'i; ikisi de ikili başına yeniden sıraya giriyor). TAHMİNİ başlangıç 14:20–14:30; koşu süresi TAHMİN 12–18 dk (otomatik analiz ~2 dk + sayımlar + üç adım vekille); bitiş 14:35–14:50. Bu sırada kod, testler ve mutasyon tanımı çalışma ağacında yazılıyor (commit'i ön kayıttan SONRA). sqlite3 duman sınaması kuyrukta 3,5 dk bekledikten sonra koşmadan geri çekildi (yerine vekil yalın JPype ile sınandı); geri çekildiği kuyruk kaydına elle bir satır olarak yazıldı (`ghidra_kuyruk.log`, 14:07:13).

## Profil betiğine ekler (profilden önce)

- Bölüm başına hata toleransı ve ara yazım (bir bölüm düşerse öbürleri koşar).
- (f) CFG'nin parçaları, her 8. fonksiyonda yalın süreyle: blok yinelemesi / blok başına komut yineleyicisi (bugünkü) / fonksiyon başına tek komut yineleyicisi + komut adresi (planın adım 4'ü) / hedef kenarları.
- (g) Blok modeli önbelleği denemesi: program boyunca tek `BasicBlockModel` (bugünkü; bulunan bloklar `SimpleBlockModel.foundBlockMap`'te birikir — alan `javap -p` ile görüldü) ↔ fonksiyon başına taze model; süre ve çıktı eşitliği. Gerekçe: planın adım 4'ü (tek komut yineleyicisi) komut başına bir Java çağrısı EKLER (komutun adresi gerekir), blok başına yalnız bir çağrı düşürür; CFG'nin doğrusal üstü büyümesinin (BULGULAR §4.3: ~53 µs / geçiş) adayı geçiş sayısı değil, program boyunca büyüyen blok önbelleği.

## Kalem 2 — profil (H0): Ollama dilimi, 14:25:41–14:31:06 (yük altında)

Koşu: kuyruk `HZ4a profil:ollama`, yuva 1, 325 sn; `uptime` başta 21,92 / 19,25 / 15,92, sonda 11,06 / 14,47 / 14,81. Ağaç: çalışma ağacının dondurulmuş kopyası (`…/HZ4a/agac_profil`; taban `1e5c2410` + o anki çalışma ağacı; eski döngüler değişmemiş). Ayar: OL2'nin T25 YAML'ı (ObjC ileti çözümleyicisi kapalı). Çıktı `…/HZ4a/ozet/profil_t25.json`. Otomatik analiz 144,5 sn. **Decompile ve BSim koşmadı:** JVM taze; aşağıdaki süreler "taze süreç" süreleridir.

### Sayılar

| Nicelik | Değer |
|---|---|
| Fonksiyon (`getFunctions(True)`) | 13 308 |
| Gövde adresi (toplam) | 5 972 683 |
| Başvurusu olan gövde adresi (`getReferenceSourceIterator`) | 665 483 |
| **Oran** | **0,1114** |
| Çok aralıklı gövde | 3 096 fonksiyon |
| Yineleyicide sıra bozukluğu (`compareTo`) | 0 adım / 0 fonksiyon |
| Örneklemde (her 25. fonksiyon, 533 fonksiyon, 212 567 adres) "başvurusu olan adres" kümesi eski yürüyüşle aynı | 533 / 533 |
| Genel simge | 182 444 (süzgeçten geçen 168 863; başvurulu 168 567) |
| Simge döngüsü eski ↔ `hasReferencesTo` + `getID` | 2,71 sn ↔ 1,38 sn; tür süzgeci farkı 0, başvuru hükmü farkı 0 |

### Sayaç vekiliyle üç adım (vekilin yükü dahil; yalın süreler kıyas koşusunda)

Yalın geçiş tabanı (aynı JVM, 300 000 çağrı): ilkel dönüşlü 0,53 µs, nesne dönüşlü 1,42 µs (sonda 1,20), `str()` 0,56 µs.

| Adım | Vekilli süre (sn) | Java çağrısı | Java çağrılarının süresi (sn) | Çağrı başına (µs) | GC (ms) | Çağrı sayısı payı (0,53 – 1,42 µs ile) |
|---|---|---|---|---|---|---|
| çağrı grafiği | 58,4 | 27 734 873 | 27,9 | 1,01 | 48 | %25 – %68 |
| xref | 67,0 | 30 793 556 | 32,1 | 1,04 | 83 | %24 – %66 |
| CFG | 29,7 | 10 503 322 | 18,7 | 1,78 | 228 | %19 – %50 |
| toplam | 155,1 | 69 031 751 | 78,8 | 1,14 | 359 | %24 – %64 |

- **Çağrı grafiği ve xref:** çağrıların %86'sı / %78'i gövde adresi yürüyüşü (`getReferencesFrom` 5 972 683 + adres yineleyicisi `hasNext` / `next` 11 958 674 + dizi uzunluğu 5 972 683 = 23,9 M). Çağrı başına ortalama süre (1,0 µs) yalın geçiş tabanının içinde: bu iki adımda Java işi tabanın üstüne çıkmıyor. İstisna `getFunctionContaining` 16–17 µs (86 656 çağrı, 1,4–1,5 sn).
- **CFG:** çağrı başına 1,78 µs; tabanın üstündeki kalemler Java işi: `getDestinationBlock` 8,96 µs × 423 963 = 3,8 sn, `getMnemonicString` 2,74 µs × 1 378 236 = 3,8 sn, `getDestinations` 6,49 µs × 247 249 = 1,6 sn, blok yineleyicisi ~2 µs.
- **GC:** üç adımda toplam 0,36 sn (%0,2). Taze JVM'de alt sınır; ürün koşusundaki pay T25 koşularında GC günlüğüyle ölçülüyor.

### H0 hükmü (ön kayıttaki tanımla; üst sınır tabanı 1,42 µs)

- Çağrı grafiği %68, xref %66, CFG %50,4, toplam %64: **üç adımda da baskın maliyet Python ↔ Java çağrı sayısı** (≥ %50). CFG sınırda: alt sınır tabanıyla (0,53 µs) pay %19'a iner ve Java işi %13–44 aralığındadır; CFG için dürüst hüküm "çağrı sayısı + Java işi karışık".
- GC baskın değil (taze JVM'de %0,2).
- Başvurusu olan adres / gövde adresi = **0,111**.

### Beklenmeyen bulgu: adımların kendi işi T25'teki süreyi açıklamıyor

Taze süreçte CFG'nin tamamı (vekille bile) 29,7 sn, xref 67,0 sn. Aynı dilimde ürün koşusunda (OL2 T25, decompile'dan SONRA): xref 132,6 sn, CFG 267,4 sn; decompile'dan ÖNCE koşan çağrı grafiği 26,0 sn (vekilli 58,4 sn'nin yalın karşılığıyla uyumlu). Yani xref ve özellikle CFG'nin T25'teki süresinin büyük kısmı adımın kendi Java çağrıları değil, **decompile'dan sonraki süreç durumu** (aday nedenler: JVM yığın baskısı / GC, bellek baskısı — makinede aynı anda birkaç 14 GB yığınlı JVM —, Python yığını). Ayrım: T25 kapalı / açık koşularına `-Xlog:gc` günlüğü eklendi (`JAVA_TOOL_OPTIONS`; ürün kodu değişmez), adım başına GC duraklaması yazılacak. Sonuç ne çıkarsa çıksın H3'ün eşiği (≤ 0,5) değişmez.

### CFG'de planın adım 4'ü (tek komut yineleyicisi) ve blok modeli denemesi

Her 8. fonksiyonda (1 664 fonksiyon, 31 914 blok, 175 617 komut, 43 652 kenar), yalın süre:

| Parça | sn |
|---|---|
| A blok yinelemesi + adres / boyut metni | 0,579 |
| B blok başına `getInstructions(blok)` + komut adı (bugünkü) | 0,907 |
| C fonksiyon başına tek `getInstructions(gövde)` + komut adı + komut adresi | 0,880 |
| D hedef kenarları | 0,741 |

- B ↔ C komut sayısı her fonksiyonda eşit; gövde dışına taşan blok 0, çok aralıklı blok 0, blok sırası bozukluğu 0.
- **C, B'den yalnız %3 hızlı** (komutu bloğa dağıtmak için komut başına adres gerekir: +2 çağrı; blok başına yalnız 1 çağrı düşer). Planın adım 4'ü bu ölçümle **uygulanmadı** (kazanç gürültü düzeyinde, eşitlik riski var).
- Blok modeli: program boyunca tek model 1,315 sn ↔ fonksiyon başına taze model 1,272 sn (kurucu toplamı 0,004 sn); çıktı 1 664 / 1 664 fonksiyonda eşit. Örneklem ortak modelde 8 kat daha az blok biriktirir; tam ölçek kıyas koşusunda (yeni yol = taze model) ölçülüyor. Kazanç çıkmazsa CFG'deki değişiklik geri alınır.

## Kalem 4 — kod (`0f2fefc0`), testler (`fb1f2142`), mutasyon (`d8d0d2b7`), yama (`f144b9c9`)

### `karadul/ghidra/headless.py`

- **`_BasvuruTablosu`** (modül düzeyi, `caller_sort_key`'in altında) + `_BasvuruKaydi`: fonksiyon başına tek başvuru geçişi. `kayit(func, func_addr)` kaydı ilk isteyen adımda hesaplar (`_hesapla`), ikinci adım hazır bulur. Giden başvurular: `ref_mgr.getReferenceSourceIterator(gövde, True)` ile yalnız başvurusu olan adresler, her adreste `getReferencesFrom` bir kez; çağrı başvuruları `cagrilanlar`'a (hedef → fonksiyon çözümlemesi `_cagri_hedefi`, program boyunca hedef adresi başına bir kez), veri başvuruları `dizgiler`'e (`_dizgi_degeri`, veri adresi başına bir kez). Gelen başvurular: `getReferencesTo(giriş)` bir kez; çağrılar `cagiranlar`'a (tekil + `caller_sort_key`, P16e), öbürleri `giris_cagri_disi`'na (PK-8).
- **Sıra güvencesi:** `_kaynak_adresleri` ardışık kaynak adreslerini `Address.compareTo` ile denetler; artan değilse (ya da adres yinelenirse) o fonksiyon eski yürüyüşle (gövdenin bütün adresleri) hesaplanır ve `eski_yuruyus` sayacı artar. Profilde Ollama diliminde bozukluk 0.
- **Bayatlama:** `tazele()` her iki adımın başında `Program.getModificationNumber()`'ı tablo kurulurkenki değerle karşılaştırır; değiştiyse kayıtlar ve iki çözümleme önbelleği atılır (`bosaltma` sayacı). Çağrı grafiği decompile'dan önce, xref sonra koştuğu için gerekli.
- **`_extract_call_graph(program, denetci=None, tablo=None)`** ve **`_extract_xrefs(program, denetci=None, tablo=None, tek_gecis=False)`**: `tablo` verilirse fonksiyon döngüsünün başındaki (denetçi denetimi, `islenen`, ad, adres aynen) tek dal kaydı tablodan kurar ve `continue` eder; eski gövde satırı satırına duruyor (girinti değişmedi: eski mutasyon tanımlarının metinleri yerinde). Kenar tekilleştirmesi ve çıktı sözlükleri eski kodla ortak.
- **Genel simge sayımı** (`tek_gecis` ya da `tablo`): tür süzgeci `SymbolType.getID()` ile (üç `equals` çağrısı yerine bir çağrı), başvuru hükmü `ref_mgr.hasReferencesTo(adres)` ile (yineleyici kurmadan). Denetim eskisi gibi 1 024 simgede bir.
- **`_extract_cfg(program, denetci=None, tek_gecis=False)`**: `tek_gecis` iken her fonksiyonda taze `BasicBlockModel` (tek satır). Planın "fonksiyon başına tek komut yineleyicisi" adımı ölçülüp uygulanmadı (yukarıda).
- **`_analyze_pyghidra`**: `analysis.dokum_tek_gecis` açıksa `_BasvuruTablosu.kur(program)`; `None` dönerse (başvuru yöneticisinde gereken dört yöntemden biri yoksa) uyarı günlüğü ve eski döngüler. İşlevlere ek argüman YALNIZ tek geçiş etkinken verilir: bayrak kapalıyken çağrı imzası bugünküyle aynı (`denetci=`), HZ-1 / ÖL-2'nin sahte köprüleri (yalnız `getName`'i olan sahte program; `f(program, denetci=None)` sahteleri) yama uygulandıktan sonra da çalışır. Tablo xref adımından sonra bırakılır. `ghidra_log`'a satır eklenmedi (`static/ghidra_log.txt` aynı kalsın); kip `logger.info("Döküm kipi: …")` ile günlükte.

### Testler — `tests/test_hz4_dokum.py` (30 test; Ghidra yok)

Sahte program: 5 fonksiyon (biri boş gövdeli, biri iki aralıklı gövdeli), dış fonksiyon, fonksiyonun içine çağrı, özyineleme, fonksiyonsuz hedef, aynı callee'ye iki çağrı yeri, tekrar eden / tırnaklı / tırnaksız / `None` değerli dizgi, dizgi olmayan veri, dizgiye veri olmayan başvuru, başvurusuz adresler, aralıkların arasındaki yabancı adres; 9 simge; 7 blok. Sınananlar: üç dökümün eski ↔ yeni `json.dumps` eşitliği; elle beklenen içerik; çıktıların tablo kaydıyla ortak nesne olmaması; çağrı sayıları (eski 2 × 224 `getReferencesFrom` → yeni 20; iki adımda 5 yineleyici); çözümleme önbellekleri; xref'in tabloyu tek başına doldurması; bozuk / yinelenen sırada eski yürüyüş; `getReferencesTo` ters sırada aynı çıktı; bayatlama (iki yönde); API yokken `kur` → `None`; PK-8 iç tablosu ve JSON'a sızmaması; simge sayımı; CFG'de model sayısı ve birikim; ÖL-2: bütçe dolunca kısmi çıktı iki yolda aynı (üç adım), dolmayınca alan yok, çağrı grafiği kesilince xref'in tamamlaması, simge sayımında kesilme nedeni, `suruyor` olayı gerçek sayaçla (üç adım); köprü: bayrak kapalı → ek argüman yok, açık → iki adım aynı tablo + kaydedilen üç JSON eskiyle aynı, açık ama API yok → eski döngüler + uyarı.

### Mutasyon

- `scripts/measurement/mutation_specs_hz4.json`: **30 / 30 öldü** (ilk koşuda 2 mutant yaşadı: veri olmayan başvurunun dizgi sayılması ve xref çıktısının tablo nesnesini paylaşması; iki test güçlendirildi, yeniden 30 / 30). Günlük `…/HZ4a/mutasyon_hz4_2.log`.
- `headless.py`'ye bakan eski sekiz tanım değişiklikten sonra yeniden koşuldu: hz1 13 / 13, ol1 29 / 29, p13a 22 / 22, p16a 33 / 33, p16c 16 / 16, p16d 11 / 11, p16e 13 / 13, ol2 33 / 33 = **170 / 170 öldü** (`…/HZ4a/mutasyon_eski_1/OZET.txt`).
- **Taşınan tanım (1):** `mutation_specs_ol2.json` `ol2_cagri_grafigi_denetimsiz` — çağrı iki satıra bölündüğü için `find` / `replace` metni yeni satırlara taşındı (anlam aynı: denetçi verilmez); taşındıktan sonra öldü. `mutation_specs_p16e.json`'a dokunmak gerekmedi (iki `seen_callers` tanımı `occurrence` ile eski gövdeye bakıyor; yeni kod başka ad kullanıyor, eşleşme sayısı değişmedi).

### Yama — `docs/arge/2026-11-23_dalga1/yamalar/HZ4a__config.py.patch`

`analysis.dokum_tek_gecis` alanı vardı (öntanım kapalı, ETKİSİZ). Yama: öntanım `True`, satır sonu yorumu `# okuyan: ghidra/headless.py _analyze_pyghidra (HZ-4a)`, `INERT_SETTINGS`'teki iki satır silinir. Ağaca uygulanmadı; `git apply --check` uygun. Yamasız ağaçta beklenen tek kırmızı: `tests/test_p15a_etkisiz.py::test_inert_registry_is_accurate` — `AssertionError: kayıtta ama okunuyor: {'analysis.dokum_tek_gecis': ['karadul/ghidra/headless.py']}`. Yamanın etkisi ayrı bir kopyada (`…/HZ4a/yamali_kopya`: `git archive HEAD` + `patch -p1`) tam takımla sınanıyor.

## Sonraki paketlere notlar

### PK-8 (`address_taken_by`)

- Veri hazır: `_BasvuruKaydi.giris_cagri_disi` — fonksiyonun giriş adresine gelen ve `isCall()` olmayan başvuruların Java `Reference` nesneleri, `getReferencesTo` yineleme sırasıyla (sıra Ghidra'ya bağlı: P16e'deki gibi yazmadan önce sıralanmalı). Ek Java geçişi yok: nesneler çağıran listesi kurulurken zaten elde ediliyor.
- Kullanım: `_BasvuruTablosu.xref_kaydi` içinde `k.giris_cagri_disi` üstünden (`ref.getFromAddress()`, `ref.getReferenceType()`; veri başvurusu süzgeci `isData()`), kaynağı içeren fonksiyon için `self.fm.getFunctionContaining(...)`. Alan eski döngüde de üretilecekse (bayrak kapalı kol) eski gövdedeki `for ref in ref_mgr.getReferencesTo(...)` döngüsüne `else` dalı eklenir; iki kolun eşitlik testi `tests/test_hz4_dokum.py::test_uc_dokum_eski_ve_yeni_yolda_bayt_bayt_ayni` kalıbıyla yazılır.
- Ömür: tablo `_analyze_pyghidra`'da xref adımından hemen sonra bırakılıyor; PK-8 alanı xref adımının içinde üretilmeli.

### ÖL-3 (akış biçimli yazım; A-38 dizgi başvuru sırası)

- A-38: dizgi başvurularının sırası tabloda **`_BasvuruKaydi.dizgiler`** listesinin sırasıdır: kaynak adresi artan, aynı adreste `getReferencesFrom` dizisinin sırası (bugünkü `strings_used` sırasıyla aynı; eşitlik testleri bunu kilitliyor). Komut içi sıra numarası ayrıca saklanmıyor: gerekiyorsa `_hesapla`'daki `for ref in ref_mgr.getReferencesFrom(addr)` döngüsüne `enumerate` eklenir ve `dizgiler` üçlüye (adres, değer, komut içi sıra) genişletilir; kaynak komutun adresi aynı döngüde `addr`'dir. `_extract_strings`'e ve şemaya dokunulmadı.
- Tablo bellekte fonksiyon başına üç küçük liste tutar (çıktıdaki listelerin kaynağı); çıktı sözlükleri ayrı kopyadır. Akış biçimli yazımda `cagri_dugumu` / `xref_kaydi` fonksiyon başına tek sözlük döndürdüğü için doğrudan yazıcıya verilebilir; kenar listesi `edges` hâlâ adımın sonunda tekilleştiriliyor (tablo yolunda fonksiyon içi tekillik zaten sağlanmış; program düzeyindeki tekilleştirme eski kodla ortak bırakıldı).
- Denetim noktaları değişmedi: fonksiyon sınırında `denetci.denetle(islenen)`, simge sayımında 1 024'te bir; kısmi alanlar çıktının sonunda.
- Çağrı grafiği adımı artık xref'in de işini yapıyor (kayıt orada hesaplanıyor): `adim_sureleri`'nde yük çağrı grafiğine kayar, xref kısalır. Çağrı grafiği bütçeyle kesilirse xref kalan fonksiyonları kendi bütçesiyle hesaplar.

### HZ-3 (decompile hattı; `_extract_func_xrefs`)

- `_extract_func_xrefs` (decompile içi, fonksiyon başına üçüncü başvuru yürüyüşü; `call_site` da üretir) bu pakette DEĞİŞMEDİ. Tablo çağrı grafiği adımında (decompile'dan önce) dolduğu için HZ-3 aynı kaydı kullanabilir; eksik olan `call_site` (ilk çağrı yeri adresi): `_hesapla`'da çağrı başvurusunun `addr`'i elde, `cagrilanlar` kaydına üçüncü öğe olarak eklenebilir. Decompile işçileri ayrı iş parçacıklarında koşuyorsa tablo yalnız okunmalı (kayıtlar çağrı grafiği adımında önceden hesaplanmış olur; çağrı grafiği kesildiyse eksik kayıt `kayit()` ile hesaplanır — o yol iş parçacığı güvenli değil).

### HZ-4b

- Koşul sayısı (T25'te üç adımın köprü içindeki payı) aşağıda, T25 açık koşusundan.
- Profil: CFG'de tabanın üstündeki maliyet Java tarafında (`getDestinationBlock`, `getMnemonicString`, `getDestinations`); Python tarafında çıktıyı değiştirmeden ölçülebilir kazanç yolu bulunamadı. CFG için kalan yol Java yardımcısı ya da adımın sırası / süreç durumu (aşağıdaki GC ölçümü).

**14:37 — bekliyorum (T25, kıyas, S8):** T25 kapalı kol 14:36:35'te yuva 1'de başladı (1 dk yük 23,13; ürün ağacı `~/karadul_olcum/urun-f144b9c9`, `--stage static`, GC günlüğü açık); TAHMİNİ bitiş 15:03–15:10. Açık kol aynı sürücüyle hemen ardından: TAHMİNİ 15:05–15:40. İkinci hat (yuva 2, HZ2 ile sırayla): aynı süreçte kıyas (Ollama, TAHMİN 6–8 dk) → H5 (sqlite3) → kıyas (sqlite3) → S8 (8 ikili, TAHMİN 15–25 dk); TAHMİNİ bitiş 15:15–15:35. Tam takım (yamasız, worktree) ve yamalı kopyada tam takım 14:35'ten beri arka planda (TAHMİN 12–20 dk). 16:10'da bitmeyen "kalan" yazılır.

## Ayrı bulgu — T25'te xref / CFG süresinin kök nedeni: JPype'ın tetiklediği tam Python çöp toplaması

(Ön kayıt dışı; H3'ün eşiği ve hükmü bundan etkilenmez. Karar ana oturumda.)

**Gözlem.** T25 kapalı kolunda (ürün ağacı `urun-f144b9c9`, bayrak kapalı = bugünkü döngüler; 14:36:35'te başladı) çağrı grafiği (decompile'dan önce) 28,5 sn, xref (decompile'dan sonra) 130,9 sn. Aynı ikilide taze süreçte (profil) xref'in tamamı vekille bile 67 sn, CFG 30 sn.

**Ölçüm.** Koşan ürün sürecinden `/usr/bin/sample` ile yığın örneği (yalnız okur; xref adımında 4 sn, CFG adımında 3 sn; dosyalar `…/HZ4a/ozet/ornek_kapali_{xref,cfg}.txt`):

| Adım | Ana iş parçacığı | "Python Reference Queue" iş parçacığı |
|---|---|---|
| xref | 2 838 / 2 844 örnek `take_gil`'de bekliyor (Java çağrısından dönüp GIL'i alamıyor) | 2 844 / 2 844 örnek `Java_org_jpype_ref_JPypeReferenceNative_wake → JPGarbageCollection::triggered() → PyGC_Collect → gc_collect_main` |
| CFG | 2 221 / 2 228 örnek `take_gil`'de | aynı zincir |

Yani JPype her Java çöp toplamasından sonra **tam** bir Python toplaması (`PyGC_Collect`) koşuyor; toplama GIL'i tutuyor ve decompile adımından kalan Python yığınının tamamını geziyor (bir toplama 4 sn'lik örneğin tamamını kaplıyor). Döküm döngüsü Java nesnesi ayırdıkça Java genç toplaması, o da Python toplamasını tetikliyor.

**JVM tarafı masum.** `-Xlog:gc` günlüğü (kapalı kol): xref penceresinde yığın 880 MB (canlı ~265 MB), genç toplama ~7 sn'de bir, duraklama 1–3 ms; decompile penceresinde (696 sn) toplam GC duraklaması 2,5 sn. xref'in 131 sn'si ≈ 20 Java toplaması × ~6,5 sn Python toplaması.

**Sonuçlar.**

1. Adım süresi = (adımdaki Java toplaması sayısı) × (Python yığınının büyüklüğü). Bu, BULGULAR'daki "doğrusal üstü büyüme"yi (büyük ikilide hem daha çok Java ayırma hem daha büyük Python yığını) ve "Python Reference Queue iş parçacığının işlemcisi"ni açıklıyor; yalın JPype mikro deneyinde görülmemesinin nedeni orada Java toplamasının tetiklenmemesi.
2. HZ-4a'nın çağrı sayısı indirimi çağrı grafiği + xref'te işe yarar (daha az Java çağrısı → daha az Java ayırma → daha az tetiklenen toplama; ayrıca xref'in işi decompile ÖNCESİNE, çağrı grafiği adımına kayıyor). CFG'de Java ayırma hızı değişmediği için kazanç beklenmez.
3. Çıktıyı değiştirmeyen aday çareler (bu pakette YOK): (a) decompile'dan sonra / xref'ten önce `gc.collect(); gc.freeze()`, CFG ya da BSim'den sonra `gc.unfreeze()` — sonraki toplamalar yalnız yeni nesneleri gezer; (b) Python yığınını küçültmek (decompile sonuçlarını bellekte tutmamak: ÖL-3'ün akış biçimli yazımı aynı yöne bakar); (c) Java genç kuşağını büyütmek (daha seyrek Java toplaması; HZ-5).
4. Aynı mekanizma decompile'dan sonraki öbür köprü adımlarını (P-code, FunctionID, BSim ingest / sorgu) ve decompile'ın kendisini de etkiliyor olabilir: ölçülmedi.

**Ek koşu (ön kayıt dışı; hüküm yok):** çareyi (a) ölçmek için ürün kodunu değiştirmeyen bir sarmalayıcı (`…/HZ4a/betik/dondur_kos.py`: `_extract_xrefs` çağrılmadan önce `gc.collect(); gc.freeze()`), bayrak KAPALI, BSim kapalı, aynı ürün ağacı; T25 açık kolundan sonra koşacak.

## Kalem 4b — CFG'deki değişiklik geri alındı (kıyasta kazanç ölçülmedi)

İlk kod commit'inde (`0f2fefc0`) `_extract_cfg` tek geçişte fonksiyon başına taze `BasicBlockModel` kuruyordu. Tam ölçekli kıyasta (aşağıda) CFG: eski 17,4 sn ↔ yeni 17,7 / 19,7 sn — **kazanç yok**. Profilde yazılan kurala göre değişiklik geri alındı (bu commit): `_extract_cfg` imzası ve gövdesi main'dekiyle aynı, köprü CFG'ye ek argüman vermiyor; ilgili test `test_cfg_dokumu_degismedi_tek_blok_modeli` oldu, iki mutant tanımdan çıktı (30 → **28**; 28 / 28 öldü, `…/HZ4a/mutasyon_hz4_3.log`). Sekiz eski tanım geri alıştan sonra yeniden koşuldu (aşağıda). Test sayısı 30.

**Ölçümlerin ağacı:** kıyas, H5, S8 ve T25 koşuları ürün ağacı `~/karadul_olcum/urun-f144b9c9`'da (taze model DAHİL) alındı. Son commit'te açık kolun CFG yolu kapalı kolun yoluyla aynı koddur (main'deki gövde); çağrı grafiği / xref kodu ölçülen ağaçtakiyle bayt bayt aynı. CFG'nin "açık" süreleri taze modelle ölçüldü; son koddaki karşılığı "kapalı" kolun CFG süresidir.

## Kalem 5a — aynı süreçte kıyas (Ollama dilimi; 15:08:37–15:13:20, yük altında)

`hz4a_profil.py --kip kiyas`, kuyruk `HZ4a kiyas:ollama` (yuva 2), ürün ağacı `urun-f144b9c9`, ayar T25 (ObjC ileti çözümleyicisi kapalı); `uptime` 5,14 / 5,87 / 8,57 → 7,60 / 6,68 / 8,15. Taze JVM, decompile / BSim yok; aynı program nesnesinde yeni → eski → yeni. Çıktı `…/HZ4a/ozet/kiyas_t25.json`; eski dökümler `…/HZ4a/kiyas_t25/dokum/`.

| Adım | eski (sn) | yeni 1, soğuk (sn) | yeni 2 (sn) |
|---|---|---|---|
| çağrı grafiği | 27,54 | 9,35 | 9,53 |
| xref | 30,85 | 1,47 | 1,47 |
| CFG (taze model; geri alındı) | 17,38 | 17,69 | 19,71 |
| toplam | 75,77 | 28,51 | 30,71 |
| **oran (yeni / eski)** | | **0,376** | **0,405** |
| çağrı grafiği + xref oranı | | 0,185 | 0,188 |

- **Eşitlik: 3 / 3** — `json.dumps(indent=2, ensure_ascii=False)` metni iki yeni koşuda da eskiyle aynı (çağrı grafiği 18 978 176 bayt, xref 12 072 909 bayt, CFG 124 801 871 bayt).
- Çağrı grafiği adımı yeni yolda xref'in kaydını da hesaplıyor (9,4 sn); xref hazır kayıttan + simge sayımından 1,5 sn.
- GC (JVM): adım başına 0–235 ms.
- **Bütçe denemesi (gerçek Ghidra, yeni yol, ürünün `_AdimDenetcisi`'yle; tam sürenin ~%40'ı bütçe):** çağrı grafiği 3,81 sn'de 1 924 / 13 308 fonksiyonda, xref 0,59 sn'de 376 / 13 308'de (neden "…; genel sembol sayımı yapılmadı", `total_globals_with_xrefs` 0), CFG 7,88 sn'de 4 962 / 13 308'de kesildi. Üçünde de çıktı geçerli JSON, `kismi: true`, `islenen` ≤ `toplam`, işlenen fonksiyonların kayıtları tam çıktıdakilerle aynı.

## Kalem 5 — H5 (sqlite3, `timeouts.ghidra_adim: 1`, bayrak açık; ürün koşusu 15:13:20–15:13:53)

Kuyruk `HZ4a H5:sqlite3` (yuva 2), `--stage static`, ayar `…/HZ4a/ozet/ayar/h5_acik.yaml`, çıkış 3 (kısmi). Ölçüm `…/HZ4a/ozet/h5_sqlite3.json`; `uptime` 7,60 / 6,68 / 8,15.

- Adım süreleri: çağrı grafiği 0,353 sn, **xref 0,084 sn** (OL2'nin aynı koşusunda bayrak kapalıyken 1,023 sn ve kesilmişti), CFG 0,961 sn. **Üç adımdan hiçbiri 1 sn'lik bütçeye takılmadı;** kesilen tek adım BSim ingest (86 / 429, `kismi`).
- `call_graph.json`, `xrefs.json`, `cfg.json` geçerli JSON, kısmi alan yok ve S8 tabanındaki tam sqlite3 çıktısıyla (bayrak kapalı, main `534e252b`) **JSON-eşit 3 / 3** (`total_globals_with_xrefs` 7 591 = 7 591).
- **H5 hükmü:** ön kayıttaki koşul ("xref ya da CFG kesildiğinde") ürün koşusunda OLUŞMADI (adımlar bütçeden kısa; `ghidra_adim` tam sayı olduğu için 1 sn'nin altı verilemiyor). Kesilme yolu gerçek Ghidra'da aynı süreçte kıyasın bütçe denemesiyle (yukarıda, Ollama; üç adım) ve sahte programla testlerde sınandı: geçerli JSON, `kismi: true`, `islenen` ≤ `toplam`, kesilmeyen kayıtlar tam çıktıyla aynı. Ürün koşusu hükmü: "koşul oluşmadı"; kıyas kolu: tuttu.

### Sekiz eski tanım, geri alıştan sonra (ikinci koşu)

hz1 13 / 13, ol1 29 / 29, p13a 22 / 22, p16a 33 / 33, p16c 16 / 16, p16d 11 / 11, p16e 13 / 13, ol2 33 / 33 = **170 / 170 öldü** (`…/HZ4a/mutasyon_eski_2/OZET.txt`). Geri alıştan sonra `headless` köprüsüne değinen 37 test dosyası + `test_p15a_etkisiz` + `test_bayrak_on_paketi`: 849 geçti / 12 atlandı / 1 kaldı (beklenen `test_inert_registry_is_accurate`); günlük `…/HZ4a/tam_takim/pytest_ilgili_geri_alis_sonrasi.log`.

## Kalem 6 — S8 (H1, H4): 15:14:15–15:32:30, yük altında

Tek kök `…/HZ4a/s8_acik`, ORTAK_D0 §6 sırası, ikili başına ayrı kuyruk çağrısı (yuva 2), ürün ağacı `urun-f144b9c9` + kökte `karadul.yaml` (`analysis.dokum_tek_gecis: true`; koşu günlüklerinde "Döküm kipi: tek geçiş"). Taban `…/ANA/s8_taban_534e252b`. Kıyas `scripts/arge/hiz/s8_esitlik.py` (ham): `…/HZ4a/ozet/s8_ham.{json,md}`.

**H1 — TUTTU: 8 / 8 ham eşit.** Her ikilide JSON farklı 0 / 23 dosya (`ghidra_output/*.json` + `static/ghidra_*.json`), `.c` farklı 0 (296 / 625 / 250 / 1 144 / 1 148 / 2 588 / 1 444 / 2 821 dosya), `naming_map` farklı 0 / 3 (`out/` dahil), `ghidra_status` eski alan farkı 0, `pcode.jsonl` eşit. zstd'de bilinen kendiliğinden fark görülmedi.

**H4 — karşılaştırılamaz (hüküm yok).** Üç adımın toplamı (sn), taban → açık: cat 0,449 → 0,189; sort 1,192 → 0,507; tree 0,715 → 0,304; sqlite3 3,195 → 1,348; htop 3,062 → 1,329; tmux 12,944 → 6,654; zstd 22,276 → 7,558; mac/tmux 16,219 → 7,655. Oranlar 0,34–0,51, **ortanca 0,425** (8 ikilinin toplamı 60,05 → 25,54 sn). Taban başka yük koşulunda alındı (13:10–13:34; `uptime` başta 2,76, sonda 28,06; açık kol 15:14–15:32; 8,84 → 6,15): ön kayıttaki kurala göre hüküm verilmez; sayılar yön gösterici (eşiğin, 0,8'in, altında). Ölçüm `…/HZ4a/ozet/s8_h4.json`.

## Kalem 7 — T25 (H2, H3, H6): ürün koşuları, yük altında

Ollama dilimi, `python -m karadul analyze … --stage static --skip-dynamic`, taze `KARADUL_CACHE_DIR`, iki kolda da `JAVA_TOOL_OPTIONS=-Xlog:gc` (ürün kodu değişmez). Ayarlar `…/HZ4a/ozet/ayar/t25_{kapali,acik}.yaml` (OL2'nin T25 ayarı: ObjC ileti çözümleyicisi kapalı). Kıyas `…/HZ4a/ozet/t25_kiyas.json`.

| Kol | Ağaç | Kuyruk penceresi | `uptime` (baş → son) | BSim | Çıkış |
|---|---|---|---|---|---|
| kapalı | `urun-f144b9c9` | 14:36:35–15:16:14 (yuva 1) | 23,13 → 8,96 | açık (ingest 835 sn, sorgu atlandı) | 3 (`step_errors` boş; neden köprü dışı, OL2'deki gibi) |
| açık | `urun-f144b9c9` (CFG'de taze model DAHİL) | 15:16:14–15:36:49 (yuva 1; kapalının hemen ardından) | 8,96 → 5,79 | **kapalı** (sert sona yetişmek için; BSim üç adımdan SONRA koşar) | 3 |
| açık-2 | `urun-8bf027a0` (**son kod**: CFG main'deki gibi) | aşağıda | | kapalı | |

Koşullar aynı değil: kapalı kolun decompile / xref / CFG'si sırasında makinede iki tam takım (pytest) ve HZ2'nin T25'i de koşuyordu; açık kol sırasında S8 koşuyordu. Decompile 694,4 sn (kapalı) ↔ 435,2 sn (açık) bu farkı gösteriyor.

| Adım (sn) | kapalı | açık (`f144b9c9`) | oran |
|---|---|---|---|
| çağrı grafiği (decompile'dan önce) | 28,52 | 9,83 | 0,345 |
| xref (decompile'dan sonra) | 130,87 | 8,67 | 0,066 |
| CFG | 292,17 | 402,12 | 1,376 |
| **toplam** | **451,56** | **420,61** | **0,931** |

- **H2 — TUTTU: 3 / 3.** `ghidra_output/{call_graph,xrefs,cfg}.json` ve `static/ghidra_{call_graph,xrefs,cfg}.json` iki kolda JSON-eşit (altı dosya).
- **H3 — TUTMADI: 0,931 > 0,5.** Çağrı grafiği + xref 159,4 → 18,5 sn'ye indi (0,116), ama CFG toplamın %65'i ve inmedi; açık kolda CFG daha da uzun sürdü. Neden: "Ayrı bulgu" (JPype tetikli tam Python toplaması). CFG süresi = Java toplaması sayısı × Python toplaması süresi: kapalı 41 Java toplaması × 7,1 sn; açık 57 × 7,1 sn (GC günlüğü: `…/ozet/gc_t25_{kapali,acik}.json`). Açık kolda Java toplamasının %39 fazla olmasının adayı, o ağaçtaki fonksiyon başına taze blok modeli (her fonksiyonda atılan model = daha çok Java çöpü); taze süreçte bu fark görünmüyordu (17,4 ↔ 17,7–19,7 sn) çünkü orada Python toplaması ucuz. Değişiklik son kodda yok (Kalem 4b); son kodun açık kolu ayrıca ölçülüyor (açık-2).
- **H6 — TUTTU: en uzun `ILERLEME` sessizliği üç adımda 22 sn** (kapalı 22 sn, açık 22 sn; ≤ 60).
- Adım içi JVM GC payı her adımda < %0,6 (iki kol).
- Yan gözlem (aynı mekanizma): açık kolda `ghidra.types` 5,4 sn (kapalı 0,04), `ghidra.function_id` 14,2 sn (kapalı 0,09) — adım sırasında denk gelen tek bir tetiklenmiş Python toplaması adımı saniyelerce uzatıyor.

### HZ-4b koşulu için sayı (hüküm 8)

Açık kolda (BSim'siz köprü 1 003,1 sn) üç adımın payı **%41,9** (420,6 sn; neredeyse tamamı CFG). Kapalı kolun BSim süresi (842,2 sn) eklenirse köprü 1 845,4 sn, pay **%22,8**. Son kodun (açık-2) payı aşağıda. Not: bu pay Java çağrısı sayısından değil tetiklenen Python toplamasından geliyor; HZ-4b'nin (Java yardımcısı) CFG'de kazandıracağı şey çağrı sayısı değil Java ayırma miktarıdır. Önce HZ-4c (aşağıdaki notlar) ölçülmeli.

## Ek koşu (ön kayıt DIŞI; hüküm değil bulgu; ana oturumun onayıyla): xref öncesi `gc.freeze()`, CFG sonrası `gc.unfreeze()`

Ürün kodu DEĞİŞMEDİ: sarmalayıcı `…/HZ4a/betik/dondur_kos.py` ürünü aynen koşar (`runpy`), yalnız `_extract_xrefs` çağrılmadan önce `gc.collect(); gc.freeze()`, `_extract_cfg` döndükten sonra `gc.unfreeze()`. **Bayrak KAPALI** (bugünkü döngüler: çarenin etkisi HZ-4a'dan ayrı görünsün), BSim kapalı, ürün ağacı `urun-f144b9c9`, T25 ayarı (`…/ozet/ayar/t25_dondur.yaml`), kuyruk `HZ4a T25:dondur` (yuva 2) 15:32:35–15:46:37, `uptime` 5,82 → 6,10 (aynı anda yuva 1'de açık / açık-2 kolları koşuyordu: yük altında). Çıkış 3 (köprü dışı neden; `step_errors` boş).

| Adım (sn) | kapalı kol (14:36) | freeze'li kol | oran |
|---|---|---|---|
| çağrı grafiği (decompile'dan önce; freeze yok) | 28,52 | 26,30 | 0,92 |
| xref (içinde 5,63 sn `gc.collect` + 3 sn'lik yığın örneği) | 130,87 | 39,25 | 0,30 |
| CFG (içinde 3 sn'lik yığın örneği) | 292,17 | **23,25** | **0,080** |
| üç adım toplamı | 451,56 | 88,80 | 0,197 |

- **(a) Süreler:** xref 130,9 → 39,2 sn, CFG 292,2 → 23,2 sn. Freeze'li kolda süreler taze süreçteki kıyasın "eski" sürelerine iniyor (27,5 / 30,8 / 17,4 sn): fark tetiklenen Python toplamasıydı. Java toplaması sayısı benzer (xref 15 ↔ 11, CFG 41 ↔ 28); değişen, toplama başına Python süresi.
- Dondurulan nesne sayısı (xref başında): **15 256 488**; dondurmadan önceki tek `gc.collect` 5,63 sn (0,37 µs / nesne). `gc.unfreeze` 0,00 sn.
- **(b) Bellek** (dışarıdan `ps` ile 2 sn'de bir RSS; `…/t25_*/rss.txt`): xref penceresi — kapalı kol tek okuma 2 953 MB (14:52:20; izleyici 14:55'te başladı), freeze'li kol 3 343–3 378 MB; CFG penceresi tepe — kapalı kol 3 242 MB (pencerenin 14:55:27'den sonraki kısmı), açık kol 3 145 MB, **freeze'li kol 4 059 MB** (pencere başında 3 421 MB). Freeze'li kolda CFG sonunda RSS ~0,8–0,9 GB daha yüksek. Ne kadarının dondurulan çöpten, ne kadarının 12 kat hızlı döngüde JVM genç kuşağının büyümesinden geldiği AYRILMADI (JVM yığını ayrıca ölçülmedi). Sürecin `ru_maxrss`'i 7 878 MB (koşunun tamamı; tepe decompile'da; `ps` RSS'iyle aynı ölçü değil).
- **(c) Çıktı:** `ghidra_output/{call_graph,xrefs,cfg}.json` kapalı kolla **bayt bayt aynı, 3 / 3** (sha256 önekleri eşit; `…/ozet/t25_kapali_dondur.json`).
- **(d) Mekanizma öbür adımlarda** (yığın örnekleri, `…/ozet/ornek_*.txt`; "ana iş parçacığı `take_gil`'de" / örnek):

| Adım | Kol | Ana iş parçacığı GIL bekliyor | "Python Reference Queue" `PyGC_Collect`'te |
|---|---|---|---|
| çağrı grafiği (decompile'dan önce) | freeze'li (o anda freeze yok) | ~49 / 2 228 | 32 / 2 228 (%1,4: var ama ucuz, yığın küçük) |
| decompile (4. dakika) | açık | 613–615 / 1 218 | 614 / 1 218 (**~%50**) |
| xref | kapalı | 2 838 / 2 844 | 2 844 / 2 844 |
| P-code (1 sn'lik örnek) | açık | 3 / 762 | görülmedi (o saniyede Java toplaması yok) |
| CFG | kapalı | 2 221 / 2 228 | tamamı |
| BSim ingest | kapalı | 2 186 / 2 195 | 2 195 / 2 195 |
| xref | freeze'li | 14 / 2 168 | görülmedi |
| CFG | freeze'li | ~226 / 2 231 | 190 / 2 231 (%8,5: yalnız dondurmadan sonraki nesneler) |
| types / FunctionID | — | örneklenmedi (adımlar < 0,1 sn) | açık kolda bu adımlar 5,4 / 14,2 sn sürdü: tek tetiklenmiş toplama denk gelmiş (dolaylı) |

  Decompile adımının kendisi de etkileniyor: örneğin yarısı tetiklenen toplamada (kapalı kolda decompile penceresinde 122 Java toplaması, 694 sn). BSim ingest (kapalı kol 835 sn) örneğin tamamında GIL bekliyor.

### (ii) için TAHMİN: Python yığını küçülürse (ÖL-3) kazanç

- Ölçülen: xref başında izlenen nesne 15,26 M; köprünün o ana kadar ürettiği döküm sözlüklerinin kap sayısı (diskteki JSON'lardan sayıldı, `…/ozet/kap_sayimi_kapali.json`): functions 27 580 + strings 60 540 + call_graph 197 922 + decompiled 290 913 + types 828 = **0,58 M**; yorumlayıcı + Karadul içe aktarma tabanı 0,09 M. Yani 15,26 M'nin ~14,6 M'si döküm çıktısı DEĞİL: decompile adımının bellekte tuttuğu ara veri (aday: P-code için saklanan fonksiyon listesi; `pcode.jsonl` 128,3 MB). CFG sırasında da toplama ~7 sn sürdüğüne göre P-code adımındaki serbest bırakma yığını küçültmüyor: **kimin tuttuğu ölçülmedi** (HZ-4c'nin ilk işi: `gc.get_objects()` türe göre sayım).
- Varsayım: tam toplamanın süresi izlenen nesne sayısıyla orantılı (ölçülen 0,37 µs / nesne tek başına; adım içinde ortalama 7,1 sn / 15,3 M = 0,46 µs).
- TAHMİN: ara veri bellekte tutulmazsa yığın xref / CFG sırasında 1–2,5 M nesneye iner (0,7 M taban + adımın kendi çıktısı: xref 0,16 M, CFG 0,97 M) → toplama başına 0,4–1,2 sn → CFG (41–57 Java toplaması) **~35–90 sn** (bugün 292–402), xref (eski döngü, 15 toplama) ~37–50 sn (bugün 131), BSim ingest (175 toplama) ~70–210 sn + kendi işi (bugün 835; kendi işi ölçülmedi). Aralık geniş: Java toplaması sayısı koşudan koşuya %40 oynuyor ve adımın kendi çıktısı da yığını büyütüyor. `gc.freeze` (i) ile ölçülen değer bu aralığın altında (CFG 23 sn) çünkü dondurma o anki yığının TAMAMINI toplama dışına alıyor.

## HZ-4c için notlar (ayrı paket; karar ana oturumda — bu pakette ürün koduna hiçbir GC değişikliği GİRMEDİ)

### Kanıt (özet; ayrıntı "Ayrı bulgu" bölümünde ve ek koşuda)

- Mekanizma: JPype 1.6.0'da Java tarafındaki `org.jpype.ref.JPypeReferenceQueue` iş parçacığı ("Python Reference Queue") her Java çöp toplamasından sonra `JPypeReferenceNative.wake` → `JPGarbageCollection::triggered()` → **`PyGC_Collect()`** çağırıyor: GIL'i tutan TAM bir Python toplaması. Süresi Python'da izlenen kap (sözlük / liste) sayısıyla orantılı; decompile adımı milyonlarca kabı bellekte bıraktığı için decompile'dan sonraki her Java toplaması saniyeler süren bir Python toplamasına dönüşüyor.
- Yığın örnekleri (`/usr/bin/sample`, T25 kapalı kol; ana iş parçacığının `take_gil`'de beklediği örnek / toplam): xref 2 838 / 2 844, CFG 2 221 / 2 228, **BSim ingest 2 186 / 2 195**; üçünde de "Python Reference Queue" iş parçacığı örneklerin tamamında `PyGC_Collect` içinde.
- GC günlüğü (kapalı kol): xref penceresinde 15 Java duraklaması, toplam 48 ms (adımın %0,04'ü) ↔ adım 130,9 sn: Java toplaması başına ~8,7 sn Python toplaması.
- Etkilenen adımlar: decompile'dan sonraki bütün köprü adımları (xref, CFG, BSim ingest örneklendi; öbürleri aşağıda). T25'te bu üç adımın toplamı ~16–17 dk.

### Çare adayları ve riskleri

**(i) Adımlar arasında `gc.freeze()` / `gc.unfreeze()`** (decompile'dan sonra `gc.collect(); gc.freeze()`, köprünün sonunda `gc.unfreeze()`).
- Etki: tetiklenen `PyGC_Collect` yalnız dondurmadan SONRA oluşan nesneleri gezer (ek koşuda ölçüldü; aşağıda).
- Riskler: (a) dondurulan nesneler arasındaki döngüsel çöp `unfreeze`'e kadar toplanmaz (bellek maliyeti: ek koşuda tepe RSS farkı); (b) `gc.freeze` süreç genelidir: aynı süreçte başka iş parçacığı / kitaplık da etkilenir (Karadul'un sunucu kipinde uzun ömürlü süreçte `unfreeze` unutulursa kalıcı sızıntı → `try / finally` şart); (c) `unfreeze`'den sonraki ilk tam toplama bütün yığını bir kez gezer (bir kerelik bedel); (d) döküm adımlarının kendi çıktısı (CFG ~10⁶ kap) dondurmadan sonra oluştuğu için adım ilerledikçe toplama yine uzar — her adımın sonunda yeniden `freeze` çağrılabilir (ölçülmedi); (e) decompile'ın KENDİSİ korunmaz (yığın o sırada büyüyor): parti aralarında `freeze` denenebilir (ölçülmedi).

**(ii) Decompile sonuçlarını bellekte tutmamak (ÖL-3'ün akış biçimli yazımı).**
- Etki: toplama süresi izlenen kap sayısıyla orantılı olduğu için Python yığını küçüldükçe her tetiklenen toplama kısalır; Java toplaması sayısı değişmez.
- Riskler: ÖL-3'ün kendi riskleri (şema, okuyucular); kazanç yığının ne kadarının decompile sonucu olduğuna bağlı. Tek başına yetmeyebilir: döküm adımlarının kendi çıktıları da bellekte birikiyor (`scripts_output`).

**(iii) JPype'ın Java GC → `PyGC_Collect` bağını kapatan ayar: YOK.** Yerelde kurulu JPype 1.6.0 (`/opt/anaconda3/lib/python3.12/site-packages/jpype`): `jpype/config.py`'de yalnız `onexit`, `destroy_jvm`, `free_resources` var; Python dosyalarında GC bağıyla ilgili seçenek yok; yerel kitaplıkta (`_jpype…so`, `native/common/jp_gc.cpp`) dışarı açılan tek şey salt okunur `_jpype.gcStats()`. (Yalnız yerel kurulum okundu; ağa çıkılmadı.)

**(iv) Ek aday (yerelde tek satırla sınandı, köprüde ölçülmedi): döküm adımları boyunca `gc.disable()`.** CPython 3.12.7'de `PyGC_Collect()` toplayıcı kapalıyken hiçbir şey yapmadan dönüyor (`ctypes.pythonapi.PyGC_Collect()`: kapalıyken 0, açıkken 1 000 nesne). Yani `gc.disable()` JPype'ın tetiklediği toplamayı da etkisiz kılar. Risk: o aralıkta hiç döngüsel toplama olmaz (döküm çıktıları döngüsüz sözlük / liste olduğu için beklenen bellek etkisi küçük; ölçülmedi); süreç genelidir (`try / finally` ile `gc.enable()`).

**(v) Java toplamasını seyreltmek** (genç kuşağı büyütmek; HZ-5): tetikleme sayısını düşürür, toplama başına süreyi düşürmez. Kapalı kolda JVM yığını 880 MB'ta kalıyor (üst sınır ~14 GB): genç kuşak küçük, toplamalar sık. Risk: A-9 (ayar donanımdan türetilmeli), bellek.

### Ek koşunun (i) için gösterdiği

Bayrak kapalıyken bile xref 130,9 → 39,2 sn, CFG 292,2 → 23,2 sn; çıktı bayt bayt aynı; bellek maliyeti CFG sonunda ~0,8–0,9 GB RSS (nedeni ayrılmadı). HZ-4a ile birlikte beklenen (ölçülmedi, TAHMİN): çağrı grafiği ~10 sn + xref ~2 sn (+ dondurma öncesi tek toplama ~6 sn) + CFG ~20–25 sn ≈ 40 sn (kapalı kol 451,6 sn). Dondurma decompile'dan ÖNCE de düşünülmeli (decompile'ın yarısı aynı toplamada): ölçülmedi.

### HZ-4c'nin ilk adımları (öneri)

1. Yığını kimin tuttuğunu say (`gc.get_objects()` türe / sahibine göre; decompile'dan hemen sonra ve P-code adımından sonra).
2. (iv) `gc.disable()` ve (i) `gc.freeze()` kollarını aynı T25'te ölç (xref, CFG, BSim ingest, decompile; tepe RSS; JVM yığını ayrı).
3. Çıktı eşitliği S8 + T25 (bu pakette ek koşuda 3 / 3 bayt eşit).
4. `_jpype.gcStats()` sayaçlarını `ghidra_status.json`'a ölçüm alanı olarak yazmak (HZ-1'in kancası gibi) kalıcı görünürlük sağlar. Not: ek koşuda `gcStats()['triggered']` xref öncesi ve CFG sonrası aynıydı (43): bu sayacın neyi saydığı (Python → Java yönü olabilir) kaynaktan doğrulanmadı.
