# OL1 — ÖL-1: Ghidra köprüsünde takılan çözümleyici bekçisi ve ilerleme olayları (ilerleme dosyası)

Paket: uygulama oturumu 2, OL1 (`docs/arge/2026-11-23_dalga1/gonderim/OL1.md`). Plan: `docs/arge/2026-11-19_mythos/olcek/PLAN.md` "ÖL-1".
Taban: main `e2c079d` (`git merge --ff-only main` sonrası; P16e içinde: `caller_sort_key` `headless.py:245`). Başlangıç: 2026-11-23 09:15. Sert son: 12:15.

## Kalemler

| # | Kalem | Durum | Commit |
|---|---|---|---|
| 1 | Fizibilite (çözümleyici adını okuma yolu) | bitti: **yol (a) seçildi**; iptal + kapatma + ikinci tur gerçek Ghidra'da çalıştı | bu commit |
| 2 | Ön kayıt (`on_kayit_ol1.md`) | bekliyor | — |
| 3 | Bekçi (`_CozumleyiciBekcisi`) + `_run_auto_analysis` | bekliyor | — |
| 4 | İlerleme olayları (`_analyze_pyghidra`) | bekliyor | — |
| 5 | Testler (`tests/test_ol1_kopru_bekci.py`) | bekliyor | — |
| 6 | Mutasyon (`mutation_specs_ol1.json`) + altı eski tanım | bekliyor | — |
| 7 | `config.py` yaması | bekliyor | — |
| 8 | S8 (8 ikili, taban `P16e/s8_sonra_3`) | bekliyor | — |
| 9 | T25 (Ollama dilimi) | bekliyor | — |
| 10 | Tam takım (yamasız) | bekliyor | — |

## Kalem 1 — fizibilite (plan adım 1)

Koşu: 2026-11-23 09:20:36–09:20:43, kuyruk `OL1 fiz:debian/cat` (yuva 2; yük 13,85 / 17,25 / 20,86). Girdi debian `cat` (S8 tabanının `raw/` kopyası, sha256 `0d5a5dd543ed8d31…`). Betik ve sonuç depo dışında: `~/karadul_olcum/runs/dalga1-2026-11-23/OL1/fizibilite/{fiz.py,cat.json,cat.log}`; Ghidra 12.1.2 kaynakları (`Base-src.zip`, `Generic-src.zip`, `Decompiler-src.zip`) okumak için aynı dizinde `src/`.

Betik: `pyghidra.open_program(analyze=False)` + ana iş parçacığında `FlatProgramAPI.analyzeAll` (izleyici `TimeoutTaskMonitor`, ürünle aynı); ayrı bir Python daemon iş parçacığı 0,1 sn aralıkla üç yolu da okur. Okumanın kendisi sınansın diye eşik 0,5 sn: aynı görev 0,5 sn tepede kalınca izleyici `cancel()`, çözümleyici `GhidraHeadless._disable_analyzers` ile kapatılır, `analyzeAll` yeni izleyiciyle bir kez daha.

| Yol | Ne okur | Dolu okuma / toplam | Hata | Sonuç |
|---|---|---|---|---|
| (a) `AutoAnalysisManager.activeTask` (özel alan, Java yansıması `getDeclaredField(...).setAccessible(true)`) → `AnalysisTaskWrapper.task.getName()` | çözümleyicinin **seçenek adı** (`AnalysisTask` kurucusu `scheduler.getName()` = `analyzer.getName()`; `_disable_analyzers`'ın kullandığı ad) | 20 / 21 (boş olan, analiz başlamadan önceki ilk okuma) | 0 | **seçildi** |
| (b) `java.lang.Thread.getAllStackTraces()` → `AnalysisScheduler.runAnalyzer` çerçevesinin üstü | sınıf + yöntem (`ghidra.app.plugin.core.analysis.DecompilerSwitchAnalyzer.added`, iş parçacığı `main`) | 19 / 21 | 0 | ad değil sınıf verir; kapatmak için sınıf → seçenek adı eşlemesi gerekir (çözümleyici kaydını gezmek) |
| (c) `TaskMonitor.getMessage()` (`AnalysisScheduler.runAnalyzer` başta `setMessage(ad)` çağırıyor) | — | **0 / 21** | 0 | `TimeoutTaskMonitor.timeoutIn` temsilcisi `TaskMonitorAdapter`; ileti saklamıyor. Ayrıca çözümleyici iletiyi sonra kendisi değiştirebilir. İletiyi saklayan izleyici Python'da `JProxy` ister (köprüdeki iş parçacığı notu: `_parallel_decompile_java_threads` belge dizgisi) |

- Okuma maliyeti (a + b + c birlikte): ortanca 1,23 ms, en büyük 11,46 ms (ilk okuma). Bekçi 15 sn aralıkla okur.
- **İptal zinciri gerçek Ghidra'da çalıştı:** "Decompiler Switch Analysis" 0,532 sn tepede kalınca `cancel()`; 1. tur 1,072 sn'de döndü (`isCancelled` true, `didTimeout` false, istisna yok; `AutoAnalysisManager.getNextTask` iptal görünce kuyruğu boşaltıyor). `_disable_analyzers` adı buldu (`true`). 2. tur (`analyzeAll` = `initializeOptions` + `reAnalyzeAll(null)` + `startAnalysis`) 27 çözümleyiciyi koştu, kapatılan çözümleyici 2. turda **0** okumada görüldü ve `getTaskTimesString`'de yok.
- Takılan çözümleyici için iptalin ulaşacağı yer kaynaktan doğrulandı: `ObjcMessageAnalyzer.getAddressFromVarnode` (gösteri 1. denemenin jstack'inde özyinelemenin döndüğü yöntem) her özyinelemede `monitor.checkCancelled()` çağırıyor (`ObjcMessageAnalyzer.java:560`) ve paralel decompile geri çağrısı dış izleyiciyi (`monitor`) kullanıyor (`:148`); `ParallelDecompiler` `CancelledException`'ı yukarı atıyor (`:155-158`). Gerçek takılmada işe yaradığı T25'te ölçülür.
- **Neden (a):** adı doğrudan seçenek adı olarak veriyor (kapatma için gereken ad; eşleme yok), okuma her iki dakikada bir değil her aralıkta tutarlı (20 / 21), yalnız okuma (Java'ya geri çağrı / `JProxy` yok). Sınırı: Ghidra'nın iki özel alanına (`activeTask`, `task`) bağlı; Ghidra 12.1.2'ye sabitli (`warn_if_ghidra_unpinned`). Alanlar okunamazsa bekçi kendini kapatır ve bunu günlüğe yazar; ad uydurulmaz.
- Aynı görev denetimi adla değil **görev sarmalayıcısının kimliğiyle** (`AnalysisTaskWrapper`, Java `equals` = kimlik): aynı çözümleyici art arda yeniden kuyruğa girip her seferinde bitiyorsa takılma sayılmaz. Kuyrukta çözümleyici olmayan komut (ör. `DisassembleCommand`) da olabilir: o zaman `cozumleyici` alanı yazılmaz ve kapatma tetiklenmez (yalnız `AnalysisTask`).
