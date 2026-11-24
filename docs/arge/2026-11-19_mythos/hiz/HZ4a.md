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
