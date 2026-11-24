# HZ-4a ön kayıt (2026-11-24)

Kaynak: `docs/arge/2026-11-23_dalga1/gonderim/HZ4a.md` "Ön kayıt" (sayılar ana oturumun; aşağıda aynen). Bu dosya profil ölçümünden (H0) SONRA, kod commit'inden ve bütün "sonra" ölçümlerinden (kıyas, sqlite3, S8, T25) ÖNCE commit'lenir. Tutmayan beklenti silinmez; eşik sonradan değişmez.

## Beklentiler (değişmez)

> H0 (profil; yön bildirilmez): üç adımda baskın maliyet (≥ %50 pay) Python ↔ Java çağrı sayısı mı, Java işinin kendisi mi, GC mi — ilk ölçüm. Başvurusu olan adres sayısı / gövdedeki adres sayısı oranı — ilk ölçüm.
> H1 (eşitlik, S8, tek kök, ORTAK_D0 §6 sırası, bayrak açık): taban `~/karadul_olcum/runs/dalga1-2026-11-23/ANA/s8_taban_534e252b`. `ghidra_output/*.json`, `static/ghidra_*.json`, `decompiled/*.c` ve `out/naming_map.json` ham eşit 8 / 8.
> H2 (eşitlik, T25): Ollama diliminde `ghidra_call_graph.json`, `ghidra_xrefs.json`, `ghidra_cfg.json` bayrak kapalı ↔ açık JSON-eşit (aynı ağaç, art arda iki koşu).
> H3 (süre, T25, yük altında, art arda): çağrı grafiği + xref + CFG toplamı, açık / kapalı oranı ≤ 0,5.
> H4 (süre, S8): aynı üç adımın toplamı, 8 ikilinin ortancasında açık / taban oranı ≤ 0,8 (taban koşusu başka yük koşulunda alındıysa "karşılaştırılamaz" yaz, hüküm verme).
> H5 (bütçe): sqlite3'te `timeouts.ghidra_adim: 1` ile xref ya da CFG kesildiğinde çıktı geçerli JSON, `kismi: true`, `islenen` ≤ `toplam`; kesilmeyen alanlar tam çıktıyla aynı.
> H6 (olay): T25'te üç adımın içinde en uzun `ILERLEME` sessizliği ≤ 60 sn (ÖL-2'de sağlanıyordu; geriye gitme yok).

## H0'ın ölçüm tanımı (profilden önce yazıldı; betik `scripts/arge/hiz/hz4a_profil.py --kip profil`, commit `5a570ee5` + bu commit'teki ekler)

- **Çağrı sayısı payı** = (vekilin saydığı Java çağrısı sayısı × aynı JVM'de ölçülen yalın geçiş süresi) / adımın vekilli duvar süresi. Yalın geçiş süresi: önemsiz bir Java çağrısının (`Address.getOffset`, `Address.getAddressSpace`, `str(Address)`) çağrı başına süresi; hesapta üçünün en büyüğü kullanılır (çağrı sayısının payına üst sınır).
- **Java işi payı** = (vekilin Java çağrılarının çevresinde ölçtüğü toplam süre − çağrı sayısı × yalın geçiş süresi) / adımın vekilli duvar süresi.
- **GC payı** = adımın çevresindeki `GarbageCollectorMXBean.getCollectionTime` farkı / adım süresi. Profil decompile koşmadan alınır (JVM yığını ürün koşusundakinden boş): GC payı alt sınırdır.
- "Baskın" = payı ≥ %50 olan; yoksa "belirsiz". Hüküm adım başına ve üç adımın toplamı için ayrı yazılır.
- Oran = `getReferenceSourceIterator(gövde, True)`'nun verdiği adres sayısı / `gövde.getNumAddresses()` toplamı (bütün fonksiyonlar).

## H2 / H3'ün iki ölçümü (ikisi de yazılır; hüküm ürün koşusundan)

1. **Aynı süreçte kıyas** (`hz4a_profil.py --kip kiyas`): aynı program nesnesi üstünde yeni → eski → yeni; `json.dumps` metni eşitliği ve süreler. Decompile / BSim koşmaz. Sıra etkisi (ikinci koşan sıcak önbellek bulur) yüzünden oran iki biçimde yazılır: yeni(1, soğuk) / eski ve yeni(2) / eski.
2. **Ürün koşusu** (`python -m karadul analyze … --stage static`, bayrak kapalı ve açık, art arda, aynı ürün ağacı): H2, H3 ve H6'nın hükmü buradan. Sert sona (16:10) yetişmezse "kalan" yazılır ve 1. ölçüm hüküm yerine geçmez; yalnız "aynı süreçte" etiketiyle raporlanır.

## Bilinen kendiliğinden fark

zstd `FUN_001063c0`: decompiler 6 koşunun 1'inde iki geçici değişkeni yer değiştiriyor (P16e). Bir `.c` farkı görülürse o ikili bir kez daha koşulur.

## Hükümler (2026-11-24 15:4x; yukarıdaki beklentiler ve eşikler değiştirilmedi)

| # | Beklenti | Ölçülen | Hüküm |
|---|---|---|---|
| H0 | baskın maliyet (≥ %50) hangisi; oran | Taze süreçte (profil) çağrı sayısı payı: çağrı grafiği %68, xref %66, CFG %50,4, toplam %64 (üst sınır tabanıyla; alt sınırla %19–25); GC %0,2. Başvurusu olan adres / gövde adresi 665 483 / 5 972 683 = 0,111 | **çağrı sayısı** (CFG sınırda: çağrı sayısı + Java işi karışık). Ürün koşusunda (decompile'dan sonra) ise baskın maliyet bunların hiçbiri değil: JPype'ın tetiklediği tam Python toplaması (ön kayıtta öngörülmeyen dördüncü neden; `HZ4a.md` "Ayrı bulgu") |
| H1 | S8 ham eşit 8 / 8 | JSON 0 / 23, `.c` 0, `naming_map` 0 / 3 fark; 8 ikilide | **TUTTU (8 / 8)** |
| H2 | T25 üç döküm JSON-eşit | `ghidra_output/` ve `static/` kopyaları, altı dosya eşit | **TUTTU (3 / 3)** |
| H3 | T25 toplam açık / kapalı ≤ 0,5 | 420,61 / 451,56 = 0,931 (çağrı grafiği 0,345; xref 0,066; CFG 1,376) | **TUTMADI** |
| H4 | S8 ortanca açık / taban ≤ 0,8 | ortanca 0,425 (0,34–0,51) | **karşılaştırılamaz** (taban başka yük koşulunda; hüküm yok) |
| H5 | sqlite3'te 1 sn bütçeyle xref / CFG kesilince çıktı geçerli, `kismi`, `islenen` ≤ `toplam`, kesilmeyen alanlar aynı | Ürün koşusunda xref 0,084 sn, CFG 0,961 sn: kesilmedi (üç döküm tam çıktıyla JSON-eşit). Aynı süreçte gerçek Ghidra'yla bütçe denemesi (Ollama ve sqlite3; üç adım): geçerli JSON, `kismi: true`, `islenen` ≤ `toplam`, işlenen kayıtlar tam çıktıyla aynı | **koşul ürün koşusunda oluşmadı**; kıyas kolunda tuttu |
| H6 | T25'te en uzun `ILERLEME` sessizliği ≤ 60 sn | 22 sn (iki kol) | **TUTTU** |

H3'ün tutmamasının nedeni: beklenti "üç adımın süresi Java çağrısı sayısıyla orantılı" varsayımına dayanıyordu. Çağrı grafiği + xref'te öyle (159,4 → 18,5 sn); CFG'de değil: CFG'nin süresi adım sırasındaki Java çöp toplaması sayısı × decompile'dan kalan Python yığınını gezen tam Python toplamasının süresi (≈ 7 sn). Eşik değiştirilmedi; aynı süreçte kıyasın oranı (0,376 / 0,405; taze süreç, decompile yok) hüküm yerine geçmez.

Açık kol, CFG'de fonksiyon başına taze blok modeli içeren ağaçta (`f144b9c9`) koştu; o değişiklik kıyas sonucuyla geri alındı. Son kodun (`8bf027a0`) açık kolu ayrıca koşuldu (açık-2; `HZ4a.md` "Kalem 7b"): H3'ün hükmü yukarıdaki ilk koşuya göredir, açık-2 ek bilgidir.
