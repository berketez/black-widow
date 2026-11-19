# HIZ — bulgular (tur 1, 2026-11-19)

Soru (Berke): "Optimizasyon üzerine çalışıldı mı? M silikonlarda daha nasıl hızlandırırız?" Kapsam düzeltmesi (Berke, aynı gün): öneriler tek işlemciye değil, gelecekteki M5 / M6 ve öbür platformlara da uymalı; değerler donanımdan türetilmeli, kabul ölçütleri oranla yazılmalı.

Bu belgedeki her sayı bir betiğin çıktısıdır; betik ve komut yanında. Betikler `scripts/arge/hiz/`, çıktıları `~/karadul_olcum/runs/arge-2026-11-19/hiz/`. Kazanç öngörüleri **TAHMİN** etiketlidir ve aralıkla verilir. Ürün kodu değiştirilmedi; Ghidra ve `karadul analyze` koşulmadı.

**Ölçüm makinesinin künyesi (hedef değil, kayıt):** Apple M4 Max, `hw.perflevel0.logicalcpu` 10, `hw.perflevel1.logicalcpu` 4, 36 GiB, macOS 27.2.1, Python 3.12.7 (Anaconda arm64), JPype 1.6.0, pyghidra 3.0.0, JVM Homebrew OpenJDK 21.0.13.1 arm64, Ghidra 12.1.2. Avast Security sistem uzantısı etkin (`systemextensionsctl list`). Ölçümler sırasında yük ortalaması 23–43 (başka ajanların Ghidra ve yeniden oynatma koşuları). **Mutlak süreler yük altındadır; okunacak olan pay, sıra ve orandır.**

## 0. Bir bakışta

1. **Baskın aşama ikilinin boyutuyla değişiyor.** 119 ikilik taban koşusunda (en büyüğü 5 697 fonksiyon) en büyük kalem Python yeniden kurmanın `feedback_loop` adımı (sınıfa göre duvarın %27–34'ü); Ghidra köprüsü toplamın %36,5'i. 13 559 fonksiyonluk gösteri diliminde (uçtan uca 7 729 sn) Ghidra köprüsü %49,4 (BSim tek başına %25,3, CFG %7,8, decompile %6,8, xref %4,5), yeniden kurma %30,4, istihbarat %11,4, deobfuscate %8,6.
2. **Yeniden kurmanın yarısı düzenli ifade derlemesi.** Ghidra'sız profilde (mac/tmux, seri kip) yeniden kurmanın 953 sn'sinin 481 sn'si `re` derlemesi: aynı desenler milyonlarca kez yeniden derleniyor (3,68 M derleme; `c_namer.py:4409-4413`, `:3902-3907`, `api_param_db.py:396-399`, `:511-519`). Ayrıca 96 338 dosya okuması 135 sn; `binary_prep`'in kurduğu bellek içi dosya önbelleğini öbür adımlar kullanmıyor.
3. **BSim 32,5 dk koştu, sonucu boştu ve zaten adlara girmiyordu.** Depo koşuya özel ve boş (`known_executables: 1`); BSim öntanımda gölge kipte (`shadow_mode=True`, `use_bsim_fusion=False`). Koşarken de fonksiyonları iki kez daha, tek iş parçacığında decompile ediyor; Ghidra'nın kendi paralel taraması (`GenSignatures.scanFunctions`) kullanılmıyor.
4. **Ghidra döküm adımları fonksiyon sayısıyla doğrusal üstü büyüyor** (log-log eğim CFG 1,53; xref 1,35; çağrı grafı 1,27; decompile 1,24). Döngüler Python'dan Java'ya adres / komut / varnode başına çağrı yapıyor: gösteride ~115 milyon geçiş (alt sınır); gövdedeki her adres için başvuru sorgusu aynı veri üzerinde üç kez koşuyor.
5. **Yalın JPype geçişi ucuz (0,7–2,0 µs), ama büyük ikilide adım başına zımni maliyet 13–20 kat yüksek.** Bu fark JPype'ın kendisinden değil, Ghidra tarafından geliyor (mikro deneyde büyük Python yığını ve canlı Java sarmalayıcıları etkisiz). Nedenin ayrılması boş makinede JFR ile (HZ-0).
6. **Bu makinede küçük dosya açmak pahalı:** var olan `.c` dosyasını açmak ortanca 0,6–0,9 ms düşük yükte, 0,7–2,8 ms yük altında (p99 ~70 ms); yeni dosya oluşturmak 0,04–0,05 ms. Profilde istihbarat ve deobfuscate aşamalarının işlemci dışı süresinin tamamına yakını `open()`. Erişimde tarayan güvenlik yazılımıyla (Avast etkin) tutarlı; nedensellik ölçülmedi.
7. **İkinci `feedback_loop` turu 119 ikilinin 118'inde 0 yeni ad üretti** ve döngü süresinin %36,7'sini aldı. Yakınsama denetimi ilk turdan sonra hiç durmuyor. Büyük ikilide ikinci tur zaten tur süre sınırıyla (600 sn) atlanıyor (gösteri: tek tur, 1 311 sn).
8. **Donanım türetmesi bugün tek makineye göre ayarlı:** yığın tavanı 32 768 MB sıkıştırılmış göstericileri kapatıyor (ölçüldü: 31 744 MB'de açık, 32 767 MB'de kapalı), Windows'ta bellek hiç algılanamıyor (yığın her makinede 4 096 MB), 8 GB makinede yığın belleğin %50'si; 8 yerde sabit işçi sayısı var.

## 1. Zaman çizelgesi (kalem 1)

### 1.1 Gösteri koşusu (Ollama 0.40.3 arm64 dilimi, 26,6 MB, 13 559 fonksiyon)

Komut: `python scripts/arge/hiz/zaman_cizelgesi.py gosteri --kok ~/karadul_olcum/runs/gosteri-2026-11-19/ollama --cikti ~/karadul_olcum/runs/arge-2026-11-19/hiz/zaman` → `gosteri_zaman.md`, `gosteri_zaman.json`. Yöntem: her Ghidra adımı çıktısını bitince yazar (`karadul/ghidra/headless.py:359-606`); adım süresi = kendi dosyasının değişme zamanı − öncekinin. Ghidra başlangıcı = max(`static/lief_analysis.json`, `combined_results.json` − `ghidra_status.duration_seconds`).

| Saat | Biten | Öncekinden (sn) | Başlangıçtan (dk) |
|---|---|---|---|
| 11:10:50 | koşu başladı (`BASLADI`) | — | 0,00 |
| 11:11:04 | Ghidra öncesi statik (otool, dizgi, sembol, LIEF) | 14,8 | 0,25 |
| 11:16:25 | JVM + içe aktarma + otomatik analiz (226,4 sn, `ghidra_log.txt`) + fonksiyon listesi | 320,6 | 5,59 |
| 11:16:28 | dizgiler | 2,6 | 5,63 |
| 11:17:23 | çağrı grafı | 55,6 | 6,56 |
| 11:26:07 | decompile (13 554 `.c` yazımı dahil) | 523,9 | 15,29 |
| 11:26:14 | tipler | 6,7 | 15,41 |
| 11:32:03 | xref dökümü | 348,7 | 21,22 |
| 11:32:06 | pcode JSONL yazımı | 3,1 | 21,27 |
| 11:42:06 | CFG dökümü | 600,9 | 31,28 |
| 11:42:07 | FunctionID | 0,1 | 31,29 |
| 12:14:38 | BSim ingest 1 152,1 + sorgu 789,4 sn; 0 eşleşme | 1 951,9 | 63,82 |
| 12:14:43 | Ghidra döndü, proje silindi, durum yazıldı | 4,9 | 63,90 |
| 12:14:50 | Ghidra çıktılarının ikinci serileştirmesi (`macho.py:434-438`) | 6,3 | 64,00 |
| 12:29:30 | ikili istihbarat taraması (`macho.py:472-509`) | 879,8 | 78,67 |
| 12:29:36 | YARA + capa (`stages.py:573-577`) | 6,1 | 78,77 |
| 12:33:45 | statik kapanış + deobfuscate `copytree` + `glob` (ayrılamıyor) | 249,6 | 82,93 |
| 12:40:39 | deobfuscate dosya başına döngü (son `.c`) | 414,0 | 89,83 |
| 12:44:48 | yeniden kurma: ilk dosya (`binary_prep` dosya önbelleği 153,5 + `ghidra_metadata` 95,6 sn …) | 249,0 | 93,98 |
| 13:19:52 | yeniden kurma: son dosya; `pipeline_result.json` | 2 103,7 | 129,05 |

Ghidra içi paylar (3 815,4 sn): BSim %51,2; CFG %15,7; decompile %13,7; xref %9,1; ilk adım %8,4; çağrı grafı %1,5.

**Koşu bitti** (`CIKIS` = 3, `BITTI` 13:20:12; çıkış 3 nedeni hızla ilgisiz: evrensel ikilideki Go dilimi analiz edilmedi). Aynı komut yeniden koşuldu; `pipeline_result.json` ve `/usr/bin/time -l` alanları:

| Kalem | sn | uçtan uca payı (7 729,1 sn) |
|---|---|---|
| Ghidra köprüsü | 3 815,4 | **%49,4** |
| ↳ BSim ingest + sorgu (0 eşleşme) | 1 951,9 | %25,3 |
| ↳ CFG dökümü | 600,9 | %7,8 |
| ↳ decompile | 523,9 | %6,8 |
| ↳ xref dökümü | 348,7 | %4,5 |
| ↳ JVM + içe aktarma + otomatik analiz + fonksiyon listesi | 320,6 | %4,1 |
| statik: Ghidra dışı (istihbarat 879,8 sn) | 897,0 | %11,6 |
| deobfuscate | 663,5 | %8,6 |
| yeniden kurma | 2 353,1 | **%30,4** |
| ↳ `feedback_loop` (tek tur: 1 311,2 sn > 600 sn tur sınırı → `iteration_timeout`; 23 yeni ad) | 1 315,8 | %17,0 |
| ↳↳ `c_naming` | 939,8 | %12,2 |
| ↳↳ `xtride_typing` / `ngram_naming` | 150,5 / 117,6 | %1,9 / %1,5 |
| ↳ `deep_tracing` / `project_build` / `kesin_anchors` | 260,9 / 245,7 / 173,4 | %3,4 / %3,2 / %2,2 |
| ↳ `parallel_algo_eng` / `binary_prep` / `algorithm_id` | 157,9 / 153,5 / 110,9 | %2,0 / %2,0 / %1,4 |

`time -l`: gerçek 7 761,62 sn; kullanıcı 8 050,11 sn; sistem 447,04 sn; azami RSS 4,68 GB; tepe bellek ayak izi 5,83 GB (deneme 1: 7,38 GB, otomatik analizde takılı kaldığı anda).

### 1.2 Taban koşusu (119 ikili, `urun-onarim-a62f15e`, 3 paralel, ortak BSim deposu)

Komutlar: `zaman_cizelgesi.py taban --kok ~/karadul_olcum/runs/urun-onarim-a62f15e --cikti …/zaman` (→ `taban_zaman.md`) ve `taban_ayrinti.py --taban …/taban_zaman.json --gosteri …/gosteri_zaman.json` (→ `taban_ayrinti.md`). Sınıf sınırları sayılara bakmadan yazıldı (DEFTER 12:50).

| Kalem (duvar payı) | küçük (<1 000 fn; 109 ikili, ortanca 307 fn) | orta (1 000–4 999; 7 ikili) | büyük (≥5 000; 3 ikili) |
|---|---|---|---|
| `feedback_loop` (yeniden kurma) | **%30,5** | **%34,3** | **%27,4** |
| Ghidra: JVM + içe aktarma + fonksiyon listesi | %11,8 | %2,2 | — (<%1,4) |
| Ghidra: otomatik analiz | %7,2 | %7,3 | %5,4 |
| Ghidra: BSim (kilit hariç) | %6,2 | %12,0 | %12,8 |
| Ghidra: BSim kilit bekleme (ortak depo) | %2,1 | %3,0 | %5,5 |
| Ghidra: decompile | %3,7 | %12,9 | %20,0 |
| statik: Ghidra dışı (istihbarat, kopya, YARA) | %7,7 | %2,8 | %1,4 |
| yeniden kurma: `project_build` | %4,1 | %5,5 | %5,2 |
| yeniden kurma: `deep_tracing` | %2,3 | %5,2 | %5,6 |

- Ghidra köprüsü 119 ikilinin toplam duvarının %36,5'i (4 305 / 11 806 sn). İkili başına sabit "JVM + içe aktarma + fonksiyon listesi" ortanca 8,2 sn (çeyrekler 6,7 / 10,0).
- `feedback_loop` içi (taban toplamı 3 614,9 sn): `c_naming` iter0 %22,2 + iter1 %19,7; `type_recovery` iter0 %14,0 + iter1 %6,3; `ngram_naming` %10,0 + %5,2; `name_merger` %6,9 + %5,8; `xtride_typing` iter0 %6,5.
- **Ölçekleme** (log-log eğim, adım süresi ~ fonksiyon^eğim; 119 ikili): CFG 1,53; xref 1,35; pcode 1,33; çağrı grafı 1,27; decompile 1,24; BSim 0,96; deobfuscate 0,57; `feedback_loop` 0,67. Gösteri eklenince CFG 1,65; xref 1,46.
- Fonksiyon başına (ms): CFG Ollama 44,3 ↔ taban 0,5–5,2; xref 25,7 ↔ 0,6–4,7; decompile 38,6 ↔ 8,7–48,2; BSim ingest 85,0 ↔ 5,2–20,4; Ghidra sonrası statik 64,9 ↔ 1,1–15,8.

**Cevap (kalem 1'in sorusu):** küçük ve büyük ikilide baskın aşama **aynı değil**. ≤ 5 700 fonksiyonda baskın olan Python yeniden kurma (`feedback_loop`, özellikle `c_naming`; Ghidra köprüsü toplamın %36,5'i); 13 559 fonksiyonda baskın olan Ghidra köprüsü (%49,4; tek başına BSim %25,3) ve onu yeniden kurma (%30,4; `c_naming` %12,2), istihbarat (%11,4) ve deobfuscate (%8,6) izliyor. İki uçta ortak olan kalem `c_naming`: küçükte `feedback_loop`'un %41,9'u, büyükte uçtan ucun %12,2'si.

## 2. Sıcak noktalar (koddan; kalem 2)

Geçiş sayıları `gecis_sayimi.py --go <static/ghidra_output>` (alt sınır; çarpanlar betikte satır numaralarıyla). Gösteri: fonksiyon 13 559, gövde adresi toplamı 5 417 829, komut 1 354 455, CFG bloğu 255 609 / kenar 355 152, seçici pcode op 1 815 138 / varnode 5 342 414.

| Adım | Döngü (dosya:satır) | Geçiş neyle ölçekleniyor | Gösteride geçiş (M, alt sınır) | İş parçacığı | Bellek / disk |
|---|---|---|---|---|---|
| Çağrı grafı | `headless.py:890-930`; gövdedeki **her adres** için `getReferencesFrom` (`:909-913`) | gövde baytı × 3 | 17,1 | tek (Python ana) | bütün sonuç sözlükte; `indent=2` yazım |
| Decompile | `headless.py:1185-1307`; ardışık statik parçalar `chunk_size = n // n_threads` (`:1226-1229`) | fonksiyon; parça içi sıra | — | `CPU_PERF_CORES` Python iş parçacığı (`:1151-1169`, `:1260`); GIL Python tarafında | `.c` başına bir dosya (`:1497-1502`); `_all_functions` JSONL yazılana dek bellekte (`:1303-1306`) |
| ↳ disassembly | `headless.py:986-1024`: komut başına `getMnemonicString`, `getNumOperands`, işlenen başına `getDefaultOperandRepresentation`, `str(cu)` | komut × ~8 | 10,8 | decompile iş parçacığı | yalnız `address`, `text` ve uzunluk kullanılıyor (`:1487-1490`, `:1508`); `mnemonic` / `operands` atılıyor |
| ↳ fonksiyon xref'i | `headless.py:1062-1079`: yine her adres için `getReferencesFrom` | gövde baytı × 3 | 16,3 | decompile iş parçacığı | çağrı grafının aynısı (ikinci kez) |
| ↳ seçici pcode | `headless.py:1530-1558`: her op için `getMnemonic`, varnode başına 6 çağrı | op + varnode | 42,9 | decompile iş parçacığı | 1,8 M op listesi bellekte |
| xref dökümü | `headless.py:1737-1803`: her adres için `getReferencesFrom` (üçüncü kez); bütün simgeler üzerinde `getReferencesTo` (`:1792-1803`) yalnız bir sayı için | gövde baytı × 3 + simge | 17,0 (simge döngüsü hariç) | tek | — |
| CFG dökümü | `headless.py:2045-2111`: blok başına `getInstructions(block)`, komut başına `getMnemonicString` + `str`; kenar başına ~9 | blok + komut + kenar | 11,2 | tek | 128,3 MB `indent=2` (sıkı yazımda 65,7 MB) |
| BSim ingest | `bsim.py:1260-1266`: fonksiyon başına `gen.scanFunction(func)` (GenSignatures her fonksiyonu kendi decompiler'ıyla yeniden decompile eder) | fonksiyon × decompile | 13 160 decompile | tek | depo `KARADUL_CACHE_DIR/bsim` |
| BSim sorgu | `bsim.py:1443-1449`: yeni `GenSignatures`, bütün fonksiyonlar **üçüncü kez** decompile; tek `QueryNearest` | fonksiyon × decompile | 13 160 decompile | tek | — |
| JSON yazımı | `headless.py:2451-2457` (`indent=2`, saf Python kodlayıcı); `macho.py:434-438` aynı veriyi `static/ghidra_*.json` olarak ikinci kez | bayt | — | tek | 202,7 MB ikinci kopya |
| İstihbarat | `binary_intelligence.py:2142-2205`: bütün `.c`'leri okur, `min(10, n)` süreçlik havuz (`:2181`); `analyze` dizgi kümeleme (`:2088-2140`) | dosya + dizgi | — | 10 süreç (sabit) | `.c` başına bir `open` |
| Deobfuscate | `binary_deobfuscator.py:145-149` `copytree`; `:177-257` tek iş parçacıklı dosya başına regex + yeniden yazım | dosya, bayt | — | tek | `.c` başına `copy2` + `open` ×2 |

Ek gözlemler:
- **"Python Reference Queue"** (JPype'ın Java iş parçacığı): gösteri sürecinde bir iş parçacığı 2 261 sn kullanıcı işlemcisi biriktirdi (12:46 ölçümü; o an yaşayan 53 iş parçacığının toplamı 3 263 sn, bunun %69,6'sı; bitmiş decompile iş parçacıkları ve yerel decompiler süreçleri bu toplamda yok; `is_parcacigi.py --pid 74835`, `ps -M`, müdahalesiz), Ghidra sonrası büyümedi (12:47'de aynı). HIZ.md'deki jstack (49. dk) bu iş parçacığına 1 714 sn diyor. Deneme 1'de (çıkarım başlamadan, `deneme1_jstack.txt`) 1 661 sn'de 33,8 sn idi.
- Çıkarım adımları JVM'in tek bir Python iş parçacığından sürülüyor; decompile dışında hiçbir döküm paralel değil.
- Seri yazım: `cfg.json` serileştirmesi 128 MB'de 3,42 sn (`json_olcum.py`); adımın 600,9 sn'sinin küçük bir parçası.

## 3. Ghidra'sız profil (kalem 3)

**Yöntem.** P12a yeniden oynatması: taban koşusunun `mac/tmux` çalışma alanı (2 821 fonksiyon) kendi veri dizinime KOPYALANDI (`reconstructed/`, `reports/`, `deobfuscated/` hariç; taban kökü değişmedi), kopyada sırayla A istihbarat (`BinaryIntelligence.analyze` + `analyze_decompiled`), B deobfuscate (`BinaryDeobfuscator.deobfuscate`), C yeniden kurma (`ReconstructionStage().execute`) ayrı `cProfile` ile koşuldu. cProfile yalnız çağıran iş parçacığını gördüğü için `concurrent.futures` süreç ve iş parçacığı havuzları satır içi (seri) yürütücüyle değiştirildi (`--seri`): işçilerin işi de profile girer, paralellik yükü (spawn, pickle) girmez. Komut: `PYTHONHASHSEED=0 PYTHONDONTWRITEBYTECODE=1 python scripts/arge/hiz/profil_yeniden.py --kaynak ~/karadul_olcum/runs/urun-onarim-a62f15e/mac/tmux/ws/workspaces/tmux/20261119_052129 --hedef ~/karadul_olcum/runs/arge-2026-11-19/hiz/profil/mac_tmux_seri --seri --referans <P12d yeniden_taban/mac/tmux naming_map.json>`; tablolar `profil_cagiranlar.py --prof …/C_yeniden_kurma.prof --ilk 20 --karadul 30 --islev …` (→ `…/mac_tmux_seri/cagiranlar.md`). Yük ortalaması ~34.

**Yöntem denetimi.** Referans: P12d'nin `agac_taban` ağacıyla (bugünkü `karadul/` ile aynı; `diff -rq` yalnız `.DS_Store` ve izlenmeyen boş dizin) paralel kipte üretilmiş ad haritası. Seri kipin ad haritası **bayt aynı** (sha256 `56233eb0…`). Seri yürütücü çıktıyı değiştirmedi.

| Aşama | duvar (sn) | işlemci (sn) | Not |
|---|---|---|---|
| A istihbarat | 21,8 | 5,1 | `_io.open` 2 824 çağrı 15,3 sn |
| B deobfuscate | 24,9 | 5,1 | `_io.open` 11 291 çağrı 20,1 sn; `copy2` 8,9 sn |
| C yeniden kurma | 953,3 | 746,8 | aşağıda |

**C yeniden kurma, öz süreye göre ilk 20 (toplam 953,0 sn):**

| # | işlev | çağrı | öz sn | öz pay | kümülatif sn |
|---|---|---|---|---|---|
| 1 | `_io.open` | 122 041 | 134,1 | %14,1 | 134,7 |
| 2 | `re.Pattern.search` | 515 488 775 | 124,4 | %13,1 | 124,4 |
| 3 | `re/_parser.py:512 _parse` | 7 759 029 | 90,0 | %9,4 | 244,3 |
| 4 | `re/_compiler.py:37 _compile` | 23 447 701 | 60,9 | %6,4 | 135,3 |
| 5 | `re/_parser.py:168 __getitem__` | 272 441 299 | 36,4 | %3,8 | 52,1 |
| 6 | `list.append` | 544 417 716 | 32,1 | %3,4 | 32,1 |
| 7 | `re/_parser.py:176 append` | 110 375 524 | 31,9 | %3,4 | 39,5 |
| 8 | `c_namer.py:4356 _line_search` | 3 060 750 | 29,9 | %3,1 | 136,8 |
| 9 | `re/_parser.py:178 getwidth` | 23 486 016 | 21,8 | %2,3 | 27,8 |
| 10 | `re/_parser.py:261 get` | 129 702 150 | 21,0 | %2,2 | 34,8 |
| 11 | `isinstance` | 363 048 687 | 20,3 | %2,1 | 20,3 |
| 12 | `len` | 264 542 024 | 18,3 | %1,9 | 21,4 |
| 13 | `re/__init__.py:280 _compile` | 5 450 337 | 16,1 | %1,7 | **480,8** |
| 14 | `re/_parser.py:240 __next` | 139 118 477 | 15,1 | %1,6 | 15,1 |
| 15 | `c_namer.py:3226 _propagate_passthrough_params` | 2 | 13,1 | %1,4 | 16,9 |
| 16 | `any` | 541 094 | 11,6 | %1,2 | 22,9 |
| 17 | `re/_compiler.py:243 _optimize_charset` | 13 463 436 | 11,1 | %1,2 | 16,8 |
| 18 | `engineering/data_flow.py:623 <genexpr>` | 339 981 285 | 11,1 | %1,2 | 11,1 |
| 19 | `re/_compiler.py:511 _compile_info` | 3 681 079 | 7,3 | %0,8 | 34,4 |
| 20 | `re/_parser.py:164 __len__` | 55 809 873 | 7,0 | %0,7 | 10,3 |

**Kümülatif (karadul işlevleri):** `feedback_loop` 780,3 sn (%81,9); `c_namer.analyze_and_rename` (iki tur) 702,4 (%73,7); `_run_heuristics_worker` 659,9; `_strategy_local_var_naming` 442,5 (%46,4); `_strategy_api_param_propagation` 121,4; `_strategy_dataflow` 80,4; `api_param_db.reverse_propagate_function_names` 63,3; `propagate_params` 59,0; `run_typing_phase` 62,5; `deep_tracing` 36,2; `run_ngram_naming` 30,4; `algorithm_id` 26,6.

**Üç sıcak nokta:**
1. **Düzenli ifade derlemesi: 480,8 sn (%50,5).** 3 681 079 gerçek derleme. Çağıranlar: `c_namer._strategy_local_var_naming` (`c_namer.py:4409-4413`: her değişken × 125 desen için `re.compile(pattern.pattern.replace("PARAM", re.escape(var_name)))`) 3 063 272 derleme / 298,0 sn; `_strategy_dataflow` (`:3902-3907`, aynı kalıp) 719 775 / 61,2 sn; `api_param_db.reverse_propagate_function_names` (`api_param_db.py:511-519`) 11 272 / 56,6 sn ve `propagate_params` (`:396-399`) 6 775 / 51,6 sn — bu ikisi çağrıdan bağımsız, yalnız API veritabanına bağlı dev bir seçenekli deseni HER çağrıda yeniden kuruyor. `re` modülünün önbelleği (512 girdi) milyonlarca farklı desenle taştığı için sabit desenler bile her seferinde yeniden derleniyor. Değişken adları fonksiyonlar arasında çok tekrarlı (`uVar1`, `local_10`, `param_2`…), yani (desen, ad) çifti başına bir kez derlemek neredeyse her derlemeyi kaldırır; çıktı değişmez (aynı desen metni → aynı derlenmiş ifade).
2. **Satır başına arama: 515 M `search`, 124,4 sn öz.** `_line_search` (`:4356`) her (değişken, desen) için gövdenin bütün satırlarını geziyor (405 M arama / 106,9 sn); `:3873` 92,6 M / 10,7 sn. 125 desenin hepsinde `PARAM` bir kez ve zorunlu konumda (`profil` sonrası denetim, DEFTER 13:20) → bir satır yalnız değişken adını içeriyorsa eşleşebilir; "adı içeren satırlar" bir kez süzülürse sonuç aynı, arama sayısı birkaç büyüklük mertebesi azalır.
3. **Dosya okuma: 96 338 `read_text` / 135,4 sn; yazma 20 789 / 1,9 sn.** `binary_prep._build_file_cache` (`binary_prep.py:130`) bütün `.c`'leri bir kez okuyor (19,8 sn) ama çoğu adım aynı dosyaları diskten yeniden açıyor: `c_algorithm_id._analyze_file` 21,3 sn; `engineering/analyzer._analyze_file` (3 × 2 821) 12,1; `stages._recover_main_from_entry` (`stages.py:1816`) 11,8; `c_namer._read_and_extract` 11,3 ve `_rename_one` 7,1; `tarif/kesin.load_static` 8,3; `signature_db.match_all` 6,7; `c_type_recoverer` (üç yer) 11,9; `run_ngram_naming` 4,8; `_collect_swift_mangled_symbols` 3,2; `block_annotator.annotate` 2,2. Açma başına ortalama 1,1 ms; bu makinede açma maliyeti erişimde taramayla tutarlı (§4.4).

**Seri ↔ paralel adım süreleri (yalnız yön; koşullar aynı değil).** Taban koşusu (10 işçi, yük altında) ile seri profil (yük altında, cProfile yüklü) arasında: `project_build` 30,3 ↔ 3,0 sn; `engineering_annotation` 15,4 ↔ 4,6; `semantic_naming` 12,7 ↔ 6,4; `c_naming` iter0 + iter1 72,2 ↔ 702,4. Paralellik `c_naming`'de (süreç havuzu) belirgin kazandırıyor. Küçük adımlardaki ters fark havuz yükünden değil: havuz sayacı koşusu (§4.5) gösterdi ki `project_build` adım koşucusunun iş parçacığı düzeyinde `deep_tracing` ile aynı anda koşup GIL'i paylaşıyor; ölçülen süresi kendi işi değil, komşu adımın süresi.

## 4. Seçenekler (kalem 4)

Her seçenekte: beklenen etki (TAHMİN), nasıl ölçülür, risk, ve **genel mi (her platformda) / yalnız başarım–verim çekirdekli işlemcide mi anlamlı**.

### 4.1 Donanım türetmesi bugün nasıl davranıyor (Berke'nin düzeltmesi)

`python scripts/arge/hiz/donanim_turetme.py --java <JDK 21 java> --cikti …/donanim_turetme.json` (→ `donanim_turetme.md`): ürünün KENDİ işlevleri (`config.py` `_detect_cpu_cores`, `_detect_available_memory_mb`) işletim sistemi yanıtları yamalanarak çağrıldı; yığın formülü `config.py:222`'den okunup değerlendirildi.

| Profil | CPU_PERF_CORES | TOTAL_MEMORY_MB | GHIDRA_HEAP_MB (belleğin %) | decompile i.p. | c_namer süreç | c_type_recoverer süreç | istihbarat süreç |
|---|---|---|---|---|---|---|---|
| bugün: M4 Max 10+4, 36 GB | 10 | 36 864 | 14 745 (%40) | 10 | 10 | 14 | 10 |
| M giriş 4+4, 8 GB | 4 | 8 192 | 4 096 (**%50**) | 4 | 4 | 8 | 10 |
| M giriş 4+6, 16 GB | 4 | 16 384 | 6 553 (%40) | 4 | 4 | 10 | 10 |
| M üst 16+4, 128 GB | 16 | 131 072 | **32 768** (%25) | 16 | 16 | 20 | 10 |
| M Ultra 24+8, 192 GB | 24 | 196 608 | **32 768** (%17) | 24 | 24 | 32 | 10 |
| Intel Mac 8 çekirdek / 16 i.p., 32 GB | 11 | 32 768 | 13 107 (%40) | 11 | 11 | 16 | 10 |
| Linux x86 16 i.p., 32 GB | 11 | 32 768 | 13 107 (%40) | 11 | 11 | 16 | 10 |
| Linux melez 8P(16 i.p.)+16E, 64 GB | **22** | 65 536 | 26 214 (%40) | 22 | 22 | 32 | 10 |
| Linux kapsayıcı 64 i.p., cgroup 8 GiB | **44** | 8 192 | 4 096 (%50) | 44 | 44 | 64 | 10 |
| Windows 32 mantıksal, 32 GB | 22 | **8 192** | **4 096** (%12) | 22 | 22 | 32 | 10 |

Bulgular:
- **Sıkıştırılmış göstericiler (compressed oops):** aynı JDK ile `-Xmx31744m` → `UseCompressedOops=true`; `-Xmx32767m` ve `-Xmx32768m` → `false` ("Max heap size too large for Compressed Oops"). Bugünkü tavan (`config.py:222` `min(32768, …)`) ≥ ~80 GB bellekli her makinede göstericileri 8 bayta çıkarıyor: aynı yığın daha az nesne taşır, önbellek kullanımı kötüleşir. **Genel** (bütün 64 bit JVM'ler).
- **Windows'ta bellek algılanmıyor:** `os.sysconf` yok, `sysctl` yok → `return 8192` yedeği (`config.py:215`) → yığın her Windows makinesinde 4 096 MB. **Genel** (platform kusuru).
- **8 GB makinede yığın belleğin %50'si:** taban `4096` baskın; Python süreci ve decompiler süreçleri için 4 GB kalır. **Genel**, Apple'da birleşik bellek GPU / model ile de paylaşıldığı için daha keskin.
- **Verim çekirdeği bilgisi olmayan makinede `max(2, int(cpu_count × 0.7))`** (`config.py:147`): Linux melez Intel'de 22 (16 başarım i.p.'yi aşar); kapsayıcıda cgroup CPU kotası okunmuyor (64 → 44). **Melez çekirdekli işlemcilere özgü** (Apple, Intel 12. kuşak+, ARM big.LITTLE).
- **Tutarsızlık:** `c_type_recoverer.py:1330, 1455` `os.cpu_count()` (verim çekirdekleri dahil), öbür havuzlar `CPU_PERF_CORES`.
- **Sabit sayılar** (`python scripts/arge/hiz/sabit_tarama.py` → `sabit_tarama.md`): `binary_intelligence.py:2181` `min(10, …)`; `batch.py:389` ve `cli.py:1653` `min(…, 3)`; `computation/struct_recovery/solver.py:41` `_MAX_PARALLEL_WORKERS = 10` ve `:680` `max_workers = 2`; `config.py:215` `return 8192`; `pipeline/runner.py:25` `_HARD_PARALLEL_CAP = 7`; `pipeline/steps/parallel_algo_eng.py:63` `max_workers=2` (iki adımı paralel koşturur; donanım değil iş sayısı). Türetilmiş + sabit kırpma: `config.py:129` (`or 4`), `:147` (`× 0.7`), `:222` (`4096`, `32768`, `0.4`), `headless.py:68-69` (`max(2, P)`, `P // 2`), `headless.py:2515`, `semantic_namer.py:2773` (`max(2, n // 500)`). Toplam 58 satır listelendi.
- Öneri: PLAN HZ-5 (formüller, tek yerde, benzetim testleriyle).

### 4.2 JVM

| Seçenek | Beklenen etki (TAHMİN) | Nasıl ölçülür | Risk | Kapsam |
|---|---|---|---|---|
| Yığın tavanı 31 744 MB (oops sınırı) | ≥ 80 GB makinede aynı yığında %10–30 daha fazla nesne; bu makinede etki yok | HZ-5 testi (`-XX:+PrintFlagsFinal`); büyük makinede GC günlüğü | yok | genel |
| Yığın formülü (taban, rezerv, `ayrilmis_mb`) | 8 GB makinede takas riskini kaldırır; büyük ikilide yığın yetmezse yavaşlar | HZ-0 GC günlüğünden tepe yığın doluluğu ↔ fonksiyon sayısı | küçük yığında `OutOfMemoryError` | genel; birleşik bellekte (Apple) KaradulLM ile paylaşım |
| AppCDS (`-XX:+AutoCreateSharedArchive -XX:SharedArchiveFile=<önbellek>/karadul.jsa`; JDK 21'de bayrak var, doğrulandı) | ikili başına sabit "JVM + içe aktarma" (ortanca 8,2 sn) içindeki sınıf yükleme kısmı −%15–35 → küçük ikilide uçtan uca −%1–4 | kod değişmeden `JAVA_TOOL_OPTIONS` ile K'de 3 tekrar (HZ-0 ek kolu) | arşiv sürüm uyuşmazlığında JVM yok sayar (güvenli) | genel |
| `ActiveProcessorCount = max(2, P)` (`headless.py:81`) kaldırmak | Ghidra'nın iç paralel kuyrukları (BSim `scanFunctions`, "Decompiler Switch Analysis") verim çekirdeklerini de kullanır: 0 ile +%15 (TAHMİN) | HZ-3 adım 5 | başka ağır işle çekişme | başarım / verim çekirdekli işlemcide anlamlı |
| GC seçimi (G1 → Parallel) | yalnız GC payı ≥ %5 ise anlamlı; bilinmiyor | HZ-0 GC günlüğü (toplam duraklama / Ghidra süresi) | Parallel GC uzun duraklama (etkileşimli değil, sorun değil) | genel |
| `G1PeriodicGCInterval` (Ghidra bitince yığını geri ver) | hız değil bellek: JVM süreç içinde açık kalıyor (gösteride yeniden kurmada süreç RSS 3,1 GB); birleşik bellekte modele yer açar | ÖLÇ-A RSS zaman serisi | yok | genel; Apple birleşik bellekte daha değerli |

### 4.3 Python ↔ Java geçişi

- Mikro deney (`python scripts/arge/hiz/jpype_gecis.py --jvm <libjvm> --n 1000000 --yigin 5 --canli 1`; aynı JPype 1.6.0 ve aynı JDK, Ghidra yok, yük ~34): geçiş başına 0,73–2,02 µs (ilkel dönüşlü statik çağrı 0,73–1,02; nesne dönen çağrı + yöntem 1,52–2,02; yineleyici 1,17–1,40; `str()` 1,15–1,80). 5 M sözlüklük canlı Python yığını, `gc.freeze()` ve 1 M canlı Java sarmalayıcısı geçiş maliyetini değiştirmedi; Python çöp toplayıcı bu döngülerde hiç tetiklenmedi. "Python Reference Queue" kalıp başına ~0,001 sn; koşu boyunca toplam 2,51 sn (boşta yoklama).
- Gösteride zımni maliyet: CFG adımında ~11,2 M geçiş / ~597 sn ≈ 53 µs; mac/tmux ~4 µs; openssl ~2,6 µs. **Yalın JPype maliyeti bu farkı açıklamıyor;** neden Ghidra tarafında (program veritabanı erişimi, blok modeli) ya da Ghidra'nın JPype kullanımına özgü. HZ-0'da JFR ile ayrılır (ön kayıt H0-d).
- Seçenekler: (a) aynı veriyi bir kez gez (HZ-4a; HZ-3 adım 3), (b) atılan alanları hesaplama (HZ-3 adım 2), (c) yalnız başvurusu olan adresleri gez (`getReferenceSourceIterator`, Ghidra 12.1.2'de var: `javap`), (d) döngüyü Java'ya taşı (HZ-4b, koşullu). (a)–(c) geçiş sayısını azaltır; kazanç, adım süresi geçiş sayısıyla orantılıysa orantılıdır (HZ-0 H0-d). **Genel.**

### 4.4 Disk ve dosya

- **Küçük dosya açma** (`acma_gecikmesi.py`). Yük ~30: kendi kopyamdaki `.c` açma ortanca 2,83 ms (p90 11,8; p99 69,0); taban koşusunun 5 saatlik `.c`'leri 0,73 ms (p90 14,9); depodaki `.py` 31,0 ms; `/usr/share/zoneinfo` 0,51 ms; okuma + kapama 0,014 ms; **yeni** dosya oluşturma 0,047 ms. Yük 4,9: `.c` açma 0,59 / 0,87 ms (p99 4,49 / 2,38); yeni oluşturma 0,041 ms; depodaki `.py` 0,93 ms; zoneinfo 0,37 ms. Yük kuyruğu büyütüyor; var olanı açma ↔ yeni oluşturma oranı düşük yükte de ~15–20 kat (yükte 15–60). Avast Security EndpointSecurity uzantısı etkin; tablo erişimde taramayla tutarlı, nedensellik ölçülmedi (dışlama Berke'nin kararı).
- Profilde etkisi: yeniden kurmada 96 338 okuma 135,4 sn (§3); istihbaratta 15,3 sn (işlemcisi 5,1 sn olan aşamada); deobfuscate'te 20,1 sn. Gösteride dosya sayısı 4,8 kat (13 554 `.c`): istihbarat 880 sn, deobfuscate ≥ 664 sn.
- Seçenekler: (a) bir kez oku, bellekten paylaş (`binary_prep._build_file_cache` zaten var; adımlar kullanmıyor) — HZ-7; (b) okumaları iş parçacıklarıyla örtüştür (beklemeli iş: GIL serbest) — HZ-6; (c) `copytree` + yeniden yazım yerine tek yazım — HZ-6; (d) erişimde taramadan yalnız `.c` dizinlerini dışlamak (yapılandırma; güvenlik ödünleşimi: çalışma alanında hedef ikilinin kopyası da var). **Genel** (Windows Defender dahil her erişimde tarayıcı); APFS'ye özgü bir şey ölçülmedi.
- **JSON yazımı** (`json_olcum.py`): CPython 3.12 `indent` verilince saf Python kodlayıcı (`json/encoder.py`, doğrulandı); ürün kodunda 76 `indent=2`. 128 MB `cfg.json`: `indent=2` 3,42 sn, `indent=None` 0,85 sn, orjson `OPT_INDENT_2` 0,12 sn; 5 / 5 dosyada orjson çıktısı ürününkiyle **bayt aynı**. Küçük kalem: gösteride JSON yazımı toplamı ~10 sn mertebesinde (TAHMİN), 3 815 sn'lik köprünün yanında. **Genel.**
- **Biçim:** `cfg.json` sıkı yazımda 65,7 MB (bugün 128,3 MB; oran 0,51). Akış biçimli yazım ve çift yazımın kaldırılması ÖLÇEK ÖL-3'te.

### 4.5 Süreç havuzları, iş parçacığı düzeyleri, çöp toplayıcı

**Havuz sayacı koşusu** (`profil_yeniden.py --havuz-say --isci 2 --asamalar C`; havuzlar sarmalanır, işler gerçekten paralel koşar; yük 2,6 → 4,9): yeniden kurma 261,6 sn duvar; **ad haritası referansla aynı** (2 işçi ↔ 10 işçi). Bir yeniden kurmada **25 havuz** kuruldu, 10'u süreç havuzu: `engineering/analyzer.py:465` ×3, `c_namer.py:2285` ×2 (tur başına), `c_type_recoverer.py:1342` ×2 ve `:1471` ×2, `semantic_namer.py:2793` ×1. Süreç havuzunda ilk sonuç gecikmesi (spawn + `karadul` içe aktarma + `initargs` pickle) 0,18–1,38 sn (2 işçi, düşük yük). `c_namer` havuzu bütün gövdeleri, dizgileri ve çağrı grafını `initargs` ile her işçiye ayrı ayrı gönderiyor (`c_namer.py:2262-2289`); spawn'da bu her işçi için bir pickle demek.

- Ölçeği: 2 işçiyle havuz başına ~0,2–1,4 sn × 10 süreç havuzu ≈ birkaç saniye; küçük ikilide (yeniden kurma ~60–250 sn) %2–5, büyükte daha az (TAHMİN). İşçi sayısı ve yük arttıkça (10 işçi aynı anda `karadul` içe aktarıyor; içe aktarma bu makinede 0,4–1,9 sn, `karadul.stages` 6,4 sn) büyür.
- Seçenekler: (a) havuzu koşu boyunca yeniden kullan (aynı işlev imzalı işler için tek havuz; `initargs` yerine ilk kullanımda yüklenen salt okur veri), (b) `forkserver` + `set_forkserver_preload([...karadul modülleri])` (JVM'siz sunucudan çatallanan işçi içe aktarmayı miras alır; `spawn` bugün her platformda zorunlu, çünkü JVM süreç içinde ayaktayken `fork` kilitli mutex'leri kopyalayıp kilitleniyor — `cli.py:542-552`; forkserver JVM içermeyen ayrı bir süreçten çatalladığı için bu kısıtı aşar; macOS'ta çatallanan süreçte Objective-C çalışma zamanı başlatılmışsa çökme riski var, ölçülmeli), (c) küçük işte havuz açmama (`engineering/analyzer.py:465` 57 iş). Hepsi **genel**; çıktı eşitliği bayt düzeyinde sınanır.

**Adım koşucusunun iş parçacığı düzeyleri GIL yüzünden hız kazandırmıyor.** `project_build` seride 3,0 sn, paralel kipte 36,2 sn: `runner.py:332` havuzunda `deep_tracing` (36,9 sn) ile aynı anda koşup GIL'i paylaşıyor (düzeyin havuzu: "ilk sonuç 36,2 sn, ömür 36,88"). Taban koşusundaki `project_build` 30,3 sn de bu yapı. İki sonuç: (1) işlemci yoğun Python adımlarında `parallel_steps=True` duvar süresini kısaltmıyor (düzey süresi ≈ adım sürelerinin toplamı); (2) paralel düzeydeki `*_duration_s` değerleri toplanamaz, adımın kendi maliyeti değildir (HZ-0 ve HZ-1 bunu bilmeli). Gerçek paralellik için süreç tabanlı adım koşturma ya da GIL'siz Python (3.13+ serbest iş parçacıklı derleme) gerekir: bugün kapsam dışı, not.

**Python çöp toplayıcı** (`gc_maliyeti.py --jsonl <gösteri pcode.jsonl>`): decompile sonuçlarının (seçici pcode) bellekteki şekli 9 022 399 izlenen kap; bunları kurarken 15 tam toplama 3,74 sn (kurulumun 5,09 sn'sinin %73'ü); tek tam toplama 0,82 sn (GIL tutulur, 10 decompile iş parçacığı bekler); `gc.freeze()` sonrası ~0. Gösteri decompile adımının ~%1'i (TAHMİN) → küçük kalem; toplu kurulum öncesi `gc.freeze()` / eşik yükseltme ucuz bir ekleme (HZ-3'e not). **Genel.**

### 4.6 Yerel kod / vektörleştirme

Profilin sıcak noktaları algoritmik israf (aynı deseni milyonlarca kez derlemek, aynı dosyayı onlarca kez açmak, aynı başvuru verisini üç kez gezmek); asıl iş zaten C'de (`re`, `json`, Ghidra decompiler). Bu yüzden **yerel uzantı (Cython / Rust) şu an değmez**: önce israf kaldırılmalı, sonra yeniden profil. Tek aday: `engineering/data_flow.py:623` üreteci (340 M çağrı, 11,1 sn öz) küme işlemiyle yazılabilir — küçük kalem, çıktı eşitliğiyle. **Genel.**

### 4.7 Başarım / verim çekirdeği (Apple'a ve melez işlemcilere özgü)

- İşçi havuzları `CPU_PERF_CORES` = başarım çekirdeği sayısıyla kuruluyor. macOS öntanım QoS'ta iş parçacıklarını önce başarım çekirdeklerine koyar, doldukça verim çekirdeklerine taşar; başka yük varken havuzun bir kısmı verim çekirdeklerinde koşar.
- **Statik parçalama verim çekirdeğinde koşan parçayı darboğaz yapar.** Dinamik dağıtım (HZ-3) bu riski platformdan bağımsız kaldırır; melez işlemcide kazanç daha büyüktür.
- Verim çekirdeklerini de saymak (`basarim + verim`) decompile gibi yerel süreç süren işlerde iş hacmini artırabilir; ölçülmeden açılmaz (HZ-3 adım 5, `perf.decompile_verim_cekirdegi`).
- QoS sınıfı (Python 3.12'de `os.PRIO_DARWIN_THREAD / PROCESS / BG` var; `taskpolicy -c`): yalnız kritik yolda olmayan, ileride işe yarayacak işler (ör. BSim ingest'i yalnız sonraki koşular için) arka plan sınıfına konabilir; arka plan sınıfı G/Ç'yi de kısar → kritik yolda kullanılmaz. Ölçülmedi; paket yok, araştırma notu.

## 5. Gereksiz iş (kalem 5)

| İş | Kanıt | Atlama / azaltma koşulu | Çıktıya etkisi | Paket |
|---|---|---|---|---|
| BSim sorgusu, depoda başka program yokken | gösteri: `known_executables: 1`, 789,4 sn, 0 eşleşme | provenance'ta kendisi dışında kayıt yoksa sorgu atlanır | `bsim_matches.json` aynı anlam (0 eşleşme); durum alanları farklı | ÖLÇEK ÖL-2 |
| BSim'in iki ek decompile'ı (ingest + sorgu) | `bsim.py:1263-1266`, `:1443-1449`; tek iş parçacığı | sorgu ingest'in tanım yöneticisini kullanır; tarama paralel | aynı | HZ-2 |
| BSim'in tamamı, gölge kipte | `config.py:728-751`; `_feedback_naming_merger.py:583-625` | `shadow_mode=True` ∧ `use_bsim_fusion=False` iken BSim adlara girmiyor; büyük ikilide ertelenebilir / bütçelenebilir | adlar değişmez; rapor / arayüzdeki BSim bölümü boş kalır | karar (§6 ve PLAN §6); bütçe ÖL-2 |
| İkinci `feedback_loop` turu | `tur_sayimi.py`: 118 / 119 ikilide 0 yeni ad; 1 326 sn = döngünün %36,7'si | yakınsama ilk turda denetlenemiyor (`_feedback_helpers.py:132`); "ikinci tur çıktıyı değiştirmiyor" ancak ölçülerek | **değiştirebilir** (tip / yorum); ad sayısı 118 / 119'da aynı | HZ-7 (ön sınama) |
| Disassembly'nin `mnemonic` / `operands` alanları | `headless.py:986-1024` hesaplıyor; `:1487-1490`, `:1508` kullanmıyor | her zaman | aynı | HZ-3 |
| Başvuru verisinin üç kez gezilmesi | çağrı grafı, decompile fonksiyon xref'i, xref dökümü; gösteride 3 × 17 M geçiş | tek geçiş | aynı | HZ-3 / HZ-4a |
| Gövdedeki her adres için başvuru sorgusu | `headless.py:909-913`, `:1062-1065`, `:1737-1741`; 5 417 829 adres | yalnız başvurusu olan adresler (`getReferenceSourceIterator`) | aynı | HZ-4a |
| xref'te bütün simgelerin başvuru yineleyicisi | `headless.py:1792-1803` yalnız bir sayı (`total_globals_with_xrefs`) için | `hasReferencesTo` | aynı | HZ-4a |
| Ghidra çıktılarının ikinci serileştirmesi | `macho.py:434-438`; 202,7 MB, gösteride ~7 sn | kopya / bağ | aynı içerik (`ensure_ascii` farkı: `ghidra_output` UTF-8, `static/` ASCII kaçışlı) | ÖLÇEK ÖL-3 |
| Aynı düzenli ifadeyi her çağrıda derlemek | §3: 3,68 M derleme, 480,8 sn (seri) | desen önbelleği | aynı | HZ-7 |
| Aynı `.c`'yi her adımda diskten okumak | §3: 96 338 okuma / 135,4 sn; `_build_file_cache` var | paylaşılan bellek içi metin deposu (yazımda güncellenir) | aynı | HZ-7 |
| Deobfuscate `copytree` + yeniden yazım | `binary_deobfuscator.py:149`, `:257` | doğrudan dönüştürüp tek yazım | aynı | HZ-6 |
| İstihbarat ve deobfuscate'in aynı `.c`'leri ayrı ayrı okuması | `binary_intelligence.py:2168-2178`, `binary_deobfuscator.py:177-179` | ortak okuma (ileri adım; mimari: ÖLÇEK ÖL-7) | aynı | HZ-6 (paralel okuma) / ÖL-7 |
| Ham ikilinin iki kopyası | gösteri `raw/Ollama` ve `raw/Ollama_arm64` (26,6 MB × 2) | evrensel dosyada yalnız seçilen dilim | — (disk) | ÖLÇEK |
| `cfg.json` ↔ `pcode.jsonl` örtüşmesi | `cfg_pcode_ortusme.py`: içerik farklı (blok / kenar / komut adı ↔ seçici op / değişken); ortak yalnız fonksiyon kimliği (13 553 / 13 559) | örtüşme yok; israf biçimde (`indent=2`, oran 0,51) | JSON-eşit | ÖLÇEK ÖL-3 |

## 6. Öncelik tablosu (kalem 6)

Kazançlar **TAHMİN**; dayanağı sağdaki sütunda. "Küçük / orta" = taban koşusu (119 ikili, toplam duvar 11 806 sn); "büyük" = gösteri (7 729 sn). Payların kaynağı §1. Emek: S (bir dosya, birkaç işlev), M (2–4 dosya), L (yeni bileşen / derleme zinciri). Çıktı: "aynı" = bayt eşitliğiyle kabul; "değişebilir" = ad ölçümüyle kabul.

| # | Öneri | Paket | Kazanç küçük / orta (uçtan uca) | Kazanç büyük (uçtan uca) | Dayanak | Emek | Risk | Çıktı | Kapsam |
|---|---|---|---|---|---|---|---|---|---|
| 1 | Düzenli ifade deseni önbelleği + "adı içeren satır" ön süzgeci (`c_namer`, `api_param_db`) | HZ-7a | −%6–10 | −%7–10 | `c_naming` uçtan ucun %12,8'i (taban) / %12,2'si (gösteri); seri profilde `c_naming` 702,4 sn'nin ~%83'ü derleme (467,4 sn: 298,0 + 61,2 + 56,6 + 51,6) + satır araması öz süresi (106,9 + 10,7 sn) | S | düşük | aynı | genel |
| 2 | BSim: paralel `scanFunctions` + sorguda ingest yöneticisini yeniden kullanma | HZ-2 | −%4–7 | −%15–23 | BSim kilit hariç taban %8,0, gösteri %25,3; ingest tek iş parçacığı, sorgu üçüncü decompile | M | orta (fonksiyon kümesi eşitliği) | aynı | genel; paralel tarama melez çekirdekte verim çekirdeklerini de kullanır |
| 3 | Ghidra sonrası dosya işleri: deobfuscate tek yazım + paralel okuma; istihbarat paralel okuma | HZ-6 | −%1–4 | −%6–12 | gösteride deobfuscate %8,6, istihbarat %11,4; profilde işlemci dışı sürenin çoğu `open` | S–M | düşük | aynı | genel (erişimde tarayıcılı her makinede büyür) |
| 4 | Döküm adımlarında tek başvuru geçişi, `getReferenceSourceIterator`, `hasReferencesTo`, fonksiyon başına tek komut yineleyicisi | HZ-4a | −%1–2 | −%5–9 | gösteride çağrı grafı + xref + CFG %13,0; doğrusal üstü büyüme (eğim 1,27–1,53) | M | orta (KİMLİK PK-8 ile aynı işlev) | aynı | genel |
| 5 | `stat` doğrulamalı paylaşılan `.c` metni önbelleği (yeniden kurma okumaları) | HZ-7b | −%3–7 | −%2–4 | seri profilde 96 338 okuma = yeniden kurmanın %14'ü | M | orta (bayat içerik geçmişi: BORU-11) | aynı | genel |
| 6 | İkinci `feedback_loop` turunu ölçülmüş koşulda atlama | HZ-7c | −%0–11 | ~0 (zaten atlanıyor) | 118 / 119 ikilide 0 yeni ad, 1 326 sn | S (kod) + M (ölçüm) | ad / tip değişebilir | değişebilir | genel |
| 7 | Decompile: dinamik dağıtım, atılan disassembly alanları, fonksiyon xref'ini yeniden hesaplamama | HZ-3 | −%0–8 (orta / büyükte daha çok) | −%1–3 | dengesizlik openssl 5,62 … Ollama 1,05; decompile payı %3,7–20 | M | düşük | aynı | genel; dengesizlik melez çekirdekte büyür |
| 8 | Süreç havuzu yeniden kullanımı / `forkserver` ön yükleme / küçük işte havuz açmama | HZ-7d | −%2–5 | −%0–1 | 25 havuz, 10 süreç havuzu, ilk sonuç 0,18–1,38 sn (2 işçi) | M | orta (forkserver + ObjC) | aynı | genel (POSIX) |
| 9 | AppCDS (`AutoCreateSharedArchive`) | HZ-5 ek | −%1–4 (küçük) | ~0 | ikili başına sabit JVM + içe aktarma ortanca 8,2 sn | S | düşük | aynı | genel |
| 10 | Donanım künyesi ve formüller (yığın oops tavanı, Windows belleği, melez çekirdek, cgroup) | HZ-5 | bu makinede 0 | bu makinede 0 | doğruluk: 8 GB'ta takas, ≥ 80 GB'ta oops kaybı, Windows'ta 4 GB yığın | M | düşük | aynı | genel + melez |
| 11 | Ölçüm kancaları (çözümleyici süreleri, adım süreleri) | HZ-1 | 0 | 0 | ölçüm açığı (`headless.py:713` ↔ `macho.py:1124-1146`) | S | yok | aynı | genel |
| 12 | Java yardımcı sınıfı | HZ-4b | ? | ? (HZ-4a sonrası kalan döküm payının yarısı) | koşullu (H0-d) | L | yüksek (paketleme, sürüm bağı) | aynı | genel |
| 13 | orjson ile `indent=2` yazım | HZ-8 | <%1 | <%1 | 128 MB'de 3,42 → 0,12 sn, bayt aynı | S | düşük (bağımlılık) | aynı | genel |
| 14 | `gc.freeze()` / eşik (toplu kurulum öncesi) | HZ-3 notu | <%1 | ~%0–1 | 9 M kap, tam toplama 0,82 sn | S | düşük | aynı | genel |
| 15 | Erişimde taramadan `.c` dizinlerini dışlama (yapılandırma) | HZ-0 adım 7 | ? | ? (açma başına 0,6–2,8 ms × yüz binlerce açma) | §4.4 | — | güvenlik ödünleşimi | aynı | Avast / Defender olan makine |

**Çıktıyı değiştirmeyen hızlandırmalar (bayt eşitliğiyle kabul edilebilir):** 1, 2, 3, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14 (ve yapılandırma 15). **Çıktıyı değiştirebilen:** 6 (ikinci tur); ayrıca bu turda önerilmeyen ama literatürde / P16c'de geçen "Decompiler Switch Analysis"ı kapatmak (`.c` değişiyor, P16c kalem 2), BSim'i büyük ikilide ertelemek (rapordaki BSim bölümü), `cfg.json`'u sıkı biçimde yazmak (JSON-eşit, bayt farklı).

**En çok kazandıracak üç öneri:** BSim hızlı yolu (büyükte −%15–23), düzenli ifade deseni önbelleği (her boyutta −%6–10; en küçük emek), Ghidra sonrası dosya işleri + paylaşılan metin önbelleği (büyükte −%8–16, küçükte −%4–11). Hepsi çıktıyı değiştirmez.

## 7. Ölçülmeyenler ve sınırlar

- **Bütün mutlak süreler yük altında** (taban koşusu 3 paralel; gösteri yük 40–60; profil ~34; havuz ve düşük yük ölçümleri 2,6–7). Oranlar ve sıralar okunmalı. HZ-0 boş makinede yineler.
- **Doğrusal üstü büyümenin nedeni ayrılmadı** (Ghidra veritabanı mı, JPype mı, yük mü). Yalın JPype mikro deneyi geçiş maliyetinin büyüklükle artmadığını gösterdi; Ghidra tarafı ölçülmedi (JFR, HZ-0).
- **"Python Reference Queue" iş parçacığının işlemcisinin nedeni** bilinmiyor; mikro deneyde geçişle büyümedi. HZ-0 JFR `jdk.ThreadCPULoad` ile zamana göre izlenecek.
- **Erişimde tarama nedensellik değil korelasyon** (dışlama denemesi Berke'nin kararı).
- **İkinci `feedback_loop` turunun çıktıya etkisi** (tip, yorum, ad değeri) ölçülmedi; yalnız yeni ad sayısı.
- **Ghidra'nın çözümleyici başına süreleri** bu koşularda kaydedilmedi (ölçüm açığı; HZ-1). P16c'nin küçük ikililerdeki oranları (Decompiler Switch Analysis %55) büyük ikiliye taşınamaz.
- **İşçi sayısı 6 / 9 / 12 ya da P / P+E** karşılaştırması yapılmadı (Ghidra koşusu gerekir; HZ-3 adım 5).
- **Yalnız bir makine** ölçüldü; öteki donanımlar benzetim (`donanim_turetme.py`).
- Profil seri kipte: paralellik yükü görünmez; paralel davranış havuz sayacı koşusuyla (2 işçi) ayrıca ölçüldü.
