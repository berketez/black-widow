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
