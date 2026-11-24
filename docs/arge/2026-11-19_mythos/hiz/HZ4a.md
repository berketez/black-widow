# HZ-4a — döküm adımlarında tek başvuru geçişi ve yineleyiciler (ilerleme)

İş emri: `docs/arge/2026-11-23_dalga1/gonderim/HZ4a.md`. Dal `worktree-agent-aafb4378ffb9a2eb9`, taban main `2263c887` (ürün kodu `534e252b` ile aynı; aradaki commit'ler belge). Başlangıç 2026-11-24 13:56; sert son 16:10. Koşu kökü `~/karadul_olcum/runs/dalga1-2026-11-23/HZ4a/`.

## Durum

| # | Kalem | Durum | Commit |
|---|---|---|---|
| 1 | Profil betiği (`scripts/arge/hiz/hz4a_profil.py`) | yazıldı; vekil Ghidra'sız (yalın JPype) sınandı | `5a570ee5` + ek |
| 2 | Profil (H0), Ollama dilimi | kuyrukta (14:08'den beri) | |
| 3 | Ön kayıt | bekliyor (profilden sonra, koddan önce) | |
| 4 | Kod + testler + mutasyon | bekliyor | |
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
