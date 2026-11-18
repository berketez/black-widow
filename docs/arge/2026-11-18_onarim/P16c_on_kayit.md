# P16c — ön kayıt (ürün kodu değişmeden önce)

Tarih: 2026-11-18 akşam. Taban: `e944437`. Süre aracı: `scripts/measurement/p16c_sure.py` (Ghidra köprüsünü tek JVM'de, ürün kodunu değiştirmeden adım adım zamanlar; Ghidra'nın `AutoAnalysisManager` çözümleyici zaman raporunu okur; çıktı dosyalarının zaman alanları ayıklanmış özetini yazar).

## 0. Ön gözlem (yalnız bir deneme koşusu; karar dayanağı değil, hipotez kaynağı)

Debian `cat` (296 fonksiyon, 107 program fonksiyonu), taban kod, yük ortalaması ≈ 15,9, eşzamanlı Ghidra süreci 5:
Ghidra köprüsü toplam 38,2 sn; **BSim sorgusu 26,5 sn (%69)**, içe aktarma 2,2, otomatik analiz 3,9, decompile 2,3, BSim ingest 2,3, öbür adımlar < 1. BSim ingest 107 fonksiyonu tek `GenSignatures` ile 2,3 sn'de tarıyor; sorgu aynı 107 fonksiyonu fonksiyon başına yeni bir `GenSignatures` (her birinde `openProgram` + decompiler) ile 0,25 sn / fonksiyon tarıyor. Otomatik analizde en pahalı çözümleyici "Decompiler Switch Analysis" (1,4 sn / 3,9).

## 1. Kollar ve beklentiler

### K-BSIM — toplu BSim sorgusu (kalem 3)
- **Değişiklik:** `_BSimNativeWrapper`'da bütün fonksiyonlar tek `GenSignatures`'ta taranır, tek `QueryNearest` (aynı `thresh`, `signifthresh`, `max + ek yuva`) koşulur; sonuçlar `SimilarityResult.getBase()` adresiyle fonksiyona eşlenir; dışlama (kendisi / aynı dosya / aynı yapı), sayaçlar ve `max_results` kırpması fonksiyon sırasıyla eskisi gibi uygulanır. Kilit / oturum / H2 bırakma (P16b) değişmez.
- **Süre beklentisi:** BSim sorgu adımı fonksiyon başına ≈ 0,25 sn'den ≤ 0,05 sn'ye (≥ 5×); `cat`'te 26,5 → ≤ 5 sn. Ghidra köprüsü toplamı küçük ve orta ikilide en az %40 kısalır.
- **Çıktı beklentisi:** `bsim_matches.json` ve `bsim_shadow.json` (zaman alanları ayıklanmış) **bayt bayt aynı**; aday sayısı, dışlanan sayıları (`excluded`), `unrecorded_candidates` aynı. Öbür Ghidra çıktıları (`functions.json`, `decompiled.json`, `decompiled/*.c`, `types.json`, `xrefs.json`, `cfg.json`, `call_graph.json`, `strings.json`) dokunulmadığı için aynı. Ad haritası: BSim gölge kipte ve ad kanalına bağlı değil (P16b H7) → `naming_map.json` değişmez.
- **Kabul:** eşleşme kümesi aynı değilse öntanım OLMAZ (eski yol ayar arkasında kalır ya da değişiklik geri alınır).
- **Ölçüm:** 4 ikili (`cat`, `tree`, `sort`, Mac `htop`), her kolda ayrı taze BSim deposu (`KARADUL_CACHE_DIR`), aynı sıra; kollar sırayla A, B, A, B, A, B (3 + 3), ortanca.

### K-ANALIZ — otomatik analiz süre sınırı (kalem 1, GHIDRA-06 kalanı)
- **Değişiklik:** `open_program(analyze=False)` + Karadul'un kendi analiz çağrısı (pyghidra 3.0.0 `_analyze_program`'ın aynısı: `shouldAskToAnalyze`, `acquireBundleHostReference`, `analyzeAll`, `markProgramAnalyzed`), ama `FlatProgramAPI(program, TimeoutTaskMonitor.timeoutIn(t, SECONDS))` ile. `t` = `timeouts.ghidra` × büyük ikili çarpanı (bugünkü `effective_timeout`). Süre dolarsa `step_errors["analysis"]` = zaman aşımı, sonuçta `analysis.status = "timeout"`, analiz kısmi; adımlar kısmi programla sürer. Sonuçta ayrıca `analysis.duration_s`, çözümleyici başına süreler.
- **Süre beklentisi:** öntanımlı sınırla (7 200 sn) değişiklik yok (gürültü içinde).
- **Çıktı beklentisi:** öntanımlı sınırla Ghidra çıktıları **aynı** (aynı `analyzeAll` yolu). Küçük sınırla (ör. 2 sn, `sqlite3`) analiz sınırın yakınında (≤ sınır + 5 sn) biter, `analysis.status = "timeout"` ve `step_errors["analysis"]` yazılır, fonksiyon / decompile sayıları düşer (kısmi).
- **Yığın:** `analysis.ghidra_max_heap_mb` PyGhidra JVM'ine bağlanır (bugün `GHIDRA_HEAP_MB` sabiti; öntanım değeri aynı → davranış aynı).

### K-COZ — çözümleyici profili (kalem 2)
- **Hipotez:** otomatik analiz Ghidra köprüsünün küçük bir payı (≤ %20, BSim toplu sorgudan sonra da ≤ %30); tek tek çözümleyicilerin kapatılması toplamı en çok birkaç yüzde kısaltır. Karadul'un okuduğu çıktıları (fonksiyon sınırları, tipler, dizgiler, adlar, FunctionID, decompile) etkileyen çözümleyiciler öntanımda kapatılmaz.
- **Kabul:** bir çözümleyicinin öntanımda kapanması için Ghidra köprüsü süresi ≥ %5 kısalmalı VE `functions.json`, `decompiled/*.c`, `types.json` aynı kalmalı (fark varsa sayılıp yazılır ve kapatma yalnız ayar olur). Ayar alanı `config.py`'de yok → yama (`yamalar/P16c__config.py.patch`), kod `getattr` ile okur.

### K-DEC — decompile işçileri (kalem 4)
- **Hipotez:** decompile toplam sürenin küçük bir payı (`cat`'te %6); işçi sayısı `CPU_PERF_CORES` (bu makinede 9). `ghidra_batch_size` gövdede kullanılmıyor (yalnız parametre). Beklenti: işçi sayısı değişikliğinin kazancı yük altında ölçülemeyecek kadar küçük → öntanım değişmez; ölü parametre kaldırılır (çıktı aynı).

## 2. Ad / tip ölçümü
K-BSIM ve K-ANALIZ (öntanımlı sınır) Ghidra çıktısını değiştirmediği için ad haritası aynı olmalı. Doğrulama: çıktı özetleri (bütün Ghidra çıktı dosyaları) iki kolda karşılaştırılır; farklı dosya çıkarsa ürün koşusu (`urun_kos.py`) ile `naming_map.json` farkı sayılır.
