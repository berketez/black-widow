# HZ2 — HZ-2: BSim hızlı yol (paralel tarama; çıktıyı değiştirmez) — ilerleme dosyası

Paket: uygulama oturumu 4 (2026-11-24), HZ2 (`docs/arge/2026-11-23_dalga1/gonderim/HZ2.md`). Plan: `docs/arge/2026-11-19_mythos/hiz/PLAN.md` "HZ-2" (gönderim metnindeki hükümlerle).
Taban: main `cfe93cef` (`git merge --ff-only main` sonrası; ürün kodu `534e252b` ile aynı, arada yalnız belge). Başlangıç: 2026-11-24 13:13. Sert son: 15:20.
Koşu kökü: `~/karadul_olcum/runs/dalga1-2026-11-23/HZ2/` (özetler `ozet/`). Ürün ağacı: `~/karadul_olcum/urun-af7dae70` (kod commit'i `af7dae70`; altı bağ).

## Kalemler

| # | Kalem | Durum | Commit |
|---|---|---|---|
| 1 | Ghidra API doğrulaması (`javap` + yerel kaynak zip'leri) | bitti (aşağıda) | `285ee3af` |
| 2 | Kod (`bsim.py`) | bitti; S8 1. turda yakalanan dispose hatası onarıldı (kalem 9a) | `285ee3af`, `af7dae70`, `068be1fd` |
| 3 | Testler (`tests/test_hz2_bsim_hizli.py`) | bitti: 31 / 31; ilgili eski testler (ol2, p16b, p16c, bsim) 119 / 119 | `af7dae70`, `068be1fd` |
| 4 | Mutasyon: hz2 23 / 23; taşınan ÖL-2 tanımı öldü; eski tanımlar ol2 33 / 33, p16b 24 / 24, p16c 16 / 16 | bitti (2. tur onarım sonrası) | `db04064a`, `068be1fd`, `710d745e` |
| 5 | `config.py` yaması (`yamalar/HZ2__config.py.patch`; `git apply --check` temiz; uygulanmadı) | bitti; yamalı kopyada 9 dosya 335 / 335 | `3a81c102` |
| 6 | Ön kayıt (`on_kayit_hz2.md`) | bitti | `3a81c102` |
| 7 | Fizibilite (kısmi ingest'i tamamlama) | bitti: ikinci `InsertRequest` reddedilir; sil + yeniden ekle çalışır (ÖL-9'a not) | `76e810df` |
| 8 | H4 (sqlite3, bütçe 2 sn) | bitti: **TUTTU** (2,064 sn, `kismi`, 6 / 429) | `5d880bab` |
| 9 | H1 / H2 (S8) | bitti: **H1 TUTTU** (BSim 8 / 8; `.c` zstd tekrarıyla 8 / 8), **H2 TUTTU** (2 / 2) | `6b3fc56f`, `801b7274` |
| 10 | H3 / H5 (T25) | koşuyor (14:38:21'den beri) | |
| 11 | Tam takım (yamasız) | bitti: 11 197 geçti / 23 atlandı / 1 kaldı (beklenen p15a) | `c829a25a` |

## Kalem 1 — Ghidra 12.1.2 API (yerel kurulum `~/Library/BlackWidowBuild/ghidra_12.1.2_PUBLIC`; `javap` + `BSim-src.zip`, `Generic-src.zip`, `Decompiler-src.zip`, `Docking-src.zip`, `Project-src.zip`; ağa çıkılmadı)

- `ghidra.features.bsim.query.GenSignatures` (BSim.jar): `public void scanFunctions(java.util.Iterator<ghidra.program.model.listing.Function>, int, ghidra.util.task.TaskMonitor) throws ghidra.app.decompiler.DecompileException`; `public void scanFunction(Function) throws DecompileException`; `public DescriptionManager getDescriptionManager()`; `public void dispose()`.
- `scanFunctions` → `new ParallelDecompileTask(program, monitor, new SignatureTask()).decompile(iter, n)` → `DecompilerConcurrentQ` (`AutoAnalysisManager.getSharedAnalsysThreadPool()`), işçi başına `SignatureTask.clone(i)` (kendi `DecompInterface`'i; 0. işçi yöneticinin sürüm / ayarını yazar: tekli yoldaki `clone(0)` ile aynı). İmzalar `writeToManager` (**synchronized**) ile TEK `DescriptionManager`'a; yönetici `TreeSet` (sıra tarama sırasından bağımsız: exe, ad, adres). `SignatureTask.decompile` izleyicinin iptalini imza üretiminden önce ve sonra denetler: iptal edilen iş yöneticiye yazılmaz.
- `generic.concurrent.ConcurrentQ` (izleyiciyle): her iş bitince `monitor.setProgress(tamamlanan_ya_da_iptal_edilen)` (`QMonitorAdapter.taskEnded`); `monitor.addCancelledListener(...)` → iptalde `cancelAllTasks(true)` (bekleyenler atılır, koşanlar kesilir). İptal edilen iş hata sayılmaz (`QResult.hasError` `CancellationException`'ı dışlar): tarama istisnasız döner.
- `ghidra.util.task.TimeoutTaskMonitor` (Generic.jar): `public static TimeoutTaskMonitor timeoutIn(long, java.util.concurrent.TimeUnit, TaskMonitor)`; `didTimeout()`; `getProgress()` / `setProgress` / `cancel` / `addCancelledListener` temsilciye gider; temsilci iptal edilemiyorsa `TaskMonitorAdapter(true)` ile değiştirilir.
- Sayaç: `TaskMonitorAdapter` ilerlemeyi SAKLAMAZ (`getProgress` → `NO_PROGRESS_VALUE`); `ghidra.framework.task.GTaskMonitor` saklar ama `addCancelledListener` `UnsupportedOperationException` atar (ConcurrentQ kullanamaz); saklayan ve dinleyici kabul eden tek sınıf paket-içi `ghidra.util.task.BasicTaskMonitor` (Docking.jar; `progress` alanı, `cancelEnabled = true`). Kod onu yansımayla kurar (`Class.forName(…, TaskMonitorAdapter'ın yükleyicisi)`, `setAccessible`); kurulamazsa `TaskMonitorAdapter(true)` + "sayaç okunamadı" (olay yok, `scan_sayac` durum alanı).
- İkinci ekleme (kaynaktan; fizibilite koşusu ölçecek): `AbstractSQLFunctionDatabase.testExecutableDuplication` aynı md5'li, kütüphane olmayan yürütülebilir için `DatabaseNonFatalException("… is already ingested")` atar → ikinci `InsertRequest` reddedilir. Tamamlama adayı: `QueryDelete` (`ExeSpecifier.exemd5`) + tam `InsertRequest`.

## Kalem 2 — kod (`karadul/ghidra/bsim.py`)

- Bayrak `bsim.paralel_tarama` (`BSimDatabase._paralel_tarama`, `getattr`; kapalı = bugünkü yol, kod yolu ve çıktı değişmez). `BSimDatabase` değeri sarmalayıcıya **öznitelikle** verir (ÖL-2'nin `denetci` düzeni; sahte `_native`'lerin imzaları değişmez).
- **Ingest** (`_BSimNativeWrapper.ingest_program`): `_iter_real_functions` listesi (aynı küme ve sıra) `_java_iterator` ile `java.util.ArrayList`'e, `gen.scanFunctions(it, n, izleyici)`. Bütçe izleyicide: denetçinin son anından kalan süre `TimeoutTaskMonitor.timeoutIn(ms)`; kalan ≤ 0 ise tarama yapılmaz (`islenen 0`). İptalde `islenen` = yöneticide imzası olan fonksiyon sayısı (`_imzali_fonksiyon_sayisi`; depoya giren gerçek iş; izleyicinin sayacı iptalde atılan işleri de "tamamlandı" saydığı için kullanılmaz), denetçiye aynı sayı yazılır (`doldu`, `islenen`, `toplam`): `last_ingest_kismi`, `BSimDatabase._ingest_kismi`, kısmi olay sözleşmesi aynı. Taranan kısım eklenir (ÖL-2 gibi).
- **Sorgu** (`query_functions`): aynı oturumda aynı program TAM ingest edildiyse (`hazir_yonetici`: aynı program nesnesi + aynı fonksiyon sayısı) ingest'in yöneticisi `QueryNearest.manage` olur, yeni `GenSignatures` kurulmaz. Değilse (ör. md5 depoda zaten var) paralel tarama. `QueryNearest.execute`'tan hemen önceki bütçe denetimi iki yola ortak satırda (metin değişmedi).
- **Adım içi olay** (`_TaramaIzleyicisi`): okuyucu iş parçacığı `analysis.bekci_aralik_sn`'de (denetçinin `aralik_sn`'i) izleyicinin `getProgress()`'ini okur ve ÖL-2'nin denetim noktasına verir (`denetci.denetle(n, toplam)` → `durum=suruyor islenen=n toplam=N`); bütçe dolduysa izleyiciyi iptal eder. Sayaç okunamıyorsa (kurulamadı / istisna / negatif) olay üretmez, sayar; iş parçacığı JVM'den ayrılır.
- **Yedek yol**: paralel tarama iptal dışı bir istisna atarsa `gen` bırakılır, yenisi kurulur, tekli döngü koşar (aynı denetçiyle); `last_scan_mode = serial_fallback`, günlükte WARN, durumda `scan_mode: serial_fallback` + `scan_fallback_error`. Bir adımda düşüş olduysa `scan_mode` öyle kalır.
- **Durum alanları** (yalnız bayrak açıkken): `bsim_detail.scan_mode` (`parallel` / `serial_fallback`); yalnız ilgili durumda `scan_fallback_error`, `scan_sayac`.
- **Kısmi ingest'in kalıcılığı** (hüküm 5): köken kaydında `kismi: {islenen, toplam}`; aynı md5 sonra TAM ingest edilirse işaret kalkar; md5 depoda zaten varsa (ingest atlandı) işarete dokunulmaz ve durumda `onceki_ingest_kismi: "t / N"` + WARN.

## Kalem 4 — mutasyon

- `scripts/measurement/mutation_specs_hz2.json`: **20 mutant, 20 öldü**, hata 0 (üretici `…/HZ2/betik/spec_uret.py`: her `find` tekil, `replace` farklı uzunlukta). Günlük `…/HZ2/mutasyon/hz2.log`. İçinde ÖL-2'nin tekli yol satırı (`hz2_tekli_ingest_kesilmez`, eski metin ve eski ÖL-2 testi: bayrak kapalı / yedek yol) ve ortak `QueryNearest` öncesi denetimin paralel (ingest yöneticisi) yolu testiyle kopyası.
- **Taşınan iki ÖL-2 tanımı** (`mutation_specs_ol2.json`): `ol2_ingest_kesilmez` paralel yolun bütçe satırına taşındı (`find` `iptal = self._paralel_tara(gen, funcs, denetci, kalan)` → `replace` `…, None)`: izleyiciye kalan süre verilmez; `test` `tests/test_hz2_bsim_hizli.py::test_ingest_butcesi_izleyicide_kismi_ve_taranan_kisim_eklenir`): **öldü**. `ol2_toplu_cagri_oncesi_denetim_yok`: satır iki tarama yoluna ortak yere kaydı, metni değişmedi → tanım değişmedi, **öldü** (paralel yol karşılığı `hz2_yonetici_yolunda_cagri_oncesi_denetim_yok` da öldü).
- Eski tanımlar (`bsim.py`'ye bakan): ol2 **33 / 33**, p16b **24 / 24**, p16c **16 / 16** öldü (hata 0); bayatlayan `find` yok; koşu sonunda `git diff` yalnız tanım dosyaları (bsim.py temiz). Günlükler `…/HZ2/mutasyon/{hz2,ol2,p16b,p16c}.log`.
- **2. tur (onarım `068be1fd` sonrası, kalem 9a):** `mutation_specs_hz2.json` **23 mutant** (+ `hz2_ingest_taramasi_birakilir`, `hz2_sorgu_yonetici_birakmaz`, `hz2_java_yineleyici_tur_hatasi`; `hz2_sorgu_yoneticiyi_kullanmaz`'ın `find`'ı yeni satıra), **23 / 23 öldü**; ol2 **33 / 33** (taşınan `ol2_ingest_kesilmez` ve `ol2_toplu_cagri_oncesi_denetim_yok` dahil, ikisi de öldü); p16b **24 / 24**; p16c **16 / 16**; hata 0; bayatlayan `find` yok; `git diff` sonda temiz. Günlükler `…/HZ2/mutasyon2/`.

## Kalem 4 ek — yamalı kopyada denetim (ön kayıt dışı)

Worktree DIŞINDA bir kopyada (`…/HZ2/yamali_kopya/`: `karadul/`, `tests/`, `scripts/arge/hiz/`, `docker/measurement/karadul.yaml`, `pyproject.toml`; `patch -p1 < HZ2__config.py.patch`; ağaca uygulanmadı): `bsim.paralel_tarama` öntanımı True iken `test_hz2_bsim_hizli`, `test_ol2_bsim_kosul`, `test_p16b_bsim`, `test_p16c_bsim_toplu`, `test_bsim`, `test_hz1_olcum_kancasi`, `test_ol2_adim_butcesi`, `test_p15a_etkisiz`, `test_bayrak_on_paketi`: **335 geçti / 13 atlandı / 0 kaldı**. Yama başka test dosyası yaması gerektirmiyor (bu dokuz dosyada).

## Kalem 7 — fizibilite (tek küçük Ghidra koşusu; kuyruk `HZ2 fizibilite:sqlite3`, yuva 1, 13:37:26–13:38:15; 1 dk yük 20,2 → 20,8: **yük altında**)

Betik `…/HZ2/betik/fizibilite.py` (ürün ağacının `bsim.py`'si; `pyghidra.open_program(analyze=True)`; ayrı depo `…/HZ2/fizibilite/is/depo`). Sonuç `ozet/fizibilite.json`. Debian sqlite3, 429 gerçek fonksiyon.

| Deney | Ölçülen |
|---|---|
| Sayaçlı izleyici (gerçek Ghidra) | kuruldu: `TimeoutTaskMonitor` + yansımayla `BasicTaskMonitor`; sayaç **okunuyor** (okuyucu 0,1 sn arayla 4 okuma, 0 okunamayan) |
| A: 0,5 sn bütçeli paralel tarama | 0,521 sn'de **iptal** (`didTimeout` true), istisna yok; ilk 0,42 sn sayaç 0 (işçilerin decompiler süreçleri açılıyor). İptalden sonra `getProgress()` = **429** (iptal edilip atılan işler de "tamamlandı" sayılıyor → `islenen` için sayaç değil yönetici sayımı doğru). Yönetici: **2 imzalı** fonksiyon + 1 imzasız çağrılan tanımı (3); yarım fonksiyon yok |
| A: kısmi yöneticinin eklenmesi | kabul: `numexe 1`, `numfunc 3` (2 imzalı + 1 çağrılan tanımı); md5 artık depoda (`_exe_already_ingested` true) |
| D: tekli ↔ paralel tam tarama imzaları | **eşit**: 429 / 429 imza, ad@adres → `LSHVector.calcUniqueHash` farkı **0**; yönetici fonksiyon sayısı 668 / 668. Süre (yük altında, aynı koşu, art arda): tekli 8,836 sn, paralel 6,295 sn (oran 0,71; küçük ikilide işçi açılışı baskın) |
| B: aynı yürütülebilir için İKİNCİ `InsertRequest` (tam küme) | **reddedildi**: `Skipping -insert- : sqlite3 is already ingested` (`testExecutableDuplication`: kütüphane olmayan aynı md5 → `DatabaseNonFatalException`) |
| C: `QueryDelete` (md5) + tam `InsertRequest` | silme: 1 yürütülebilir, `funccount 3`; yeniden ekleme **kabul**: `numexe 2`, `numfunc 668` |

**Hüküm (hüküm 5):** "kalanı ekleme" (aynı yürütülebilir için ikinci `InsertRequest`) Ghidra 12.1.2'de **mümkün değil** (ölçüldü ve kaynakta: kütüphane olmayan md5 ikinci kez eklenmez). Bu yüzden tamamlama bu pakette UYGULANMADI; uygulanan: köken kaydında `kismi` işareti + sonraki koşuda `onceki_ingest_kismi` durumu ve WARN. Çalışan aday yol (C): aynı md5'i `QueryDelete` ile silip tam ingest — ÖL-9'a not (aşağıda).

## Kalem 8 — H4 (sqlite3, `bsim.ingest_butcesi_sn: 2`)

- Koşu: kuyruk `HZ2 H4:debian/sqlite3`, yuva 1, 13:38:15–13:39:01; 1 dk yük 20,75 → 18,34 (**yük altında**). `python -m karadul analyze <S8 sqlite3 ham kopyası> --stage static --config ayar/h4_sqlite3.yaml` (`bsim.paralel_tarama: true`, `bsim.ingest_butcesi_sn: 2`; öbürleri öntanım), taze `KARADUL_CACHE_DIR`, ürün ağacı `urun-af7dae70`. Özet `ozet/hz2_ozet.json` → `H4`.
- **Çıkış 3** (`step_errors.bsim_ingest` "adım bütçesi (2 sn) doldu"). `ghidra.bsim.ingest` **2,064 sn**; `bsim_matches.json` geçerli JSON; `bsim_status: kismi`, `ingest_islenen 6`, `ingest_toplam 429`, `ingested_functions 6`, `scan_mode: parallel`, `scan_sayac` yok (sayaç okundu); sorgu atlandı (taze depo).
- Olaylar: `ghidra.bsim.ingest durum=kismi islenen=6 toplam=429 gecen_sn=2.064 neden="bsim_ingest: adım bütçesi (2 sn) doldu"` → `ghidra.bsim.query durum=atlandi`.
- **H4: TUTTU** (≤ 2 + 10 sn; `kismi`; JSON geçerli; 6 ≤ 429).
- **Not (hüküm değil, olumsuz bulgu):** 2 sn'lik bütçede paralel yol yalnız **6** fonksiyon taradı; ÖL-2'nin tekli yolu aynı ikilide aynı bütçeyle 253 taramıştı (dün akşam, farklı yük). Neden fizibilitede görüldü: işçi başına ayrı decompiler süreci açılıyor, ilk ~0,4–2 sn sayaç 0. Kısa bütçede (birkaç sn) paralel yol daha AZ iş yapar; büyük ikilide açılış payı küçük.

## Kalem 9a — S8 1. tur (kod `af7dae70`): HATA yakalandı, tur durduruldu

- 13:39–13:45 (yuva 1, 1 dk yük 10,9–18,3; **yük altında**): cat, sort, tree bitti; sqlite3 koşarken 13:49'da durduruldu (süreçler öldürüldü; çıktı `…/HZ2/s8_tur1_af7dae70/`, kanıt olarak duruyor).
- cat: taban ile **eşit** (`scan_mode` dışında; taze depo, sorgu atlandı). sort ve tree: `.c`, öbür JSON'lar, ad haritaları eşit; eşleşme listesi eşit (sort 244 sorgu / 180 eşleşme, tree 119 / 50) AMA üç BSim dosyasında `bsim_detail.query_mode` `batch` → `per_function` ve yeni `bsim_detail.batch_query_error` = `RuntimeError: BSim QueryNearest (toplu) basarisiz: Fatal error during -querynearest- : Query signature data has no setting information`; sorgu sort'ta 2,607 → 56,511 sn, tree'de 1,674 → 27,305 sn.
- **Kök neden:** `GenSignatures.dispose()` → `clear()` → `manager.clear()` (`GenSignatures.java` `clear()`; `DescriptionManager.clear()` fonksiyonları VE `major / minor / settings`'i sıfırlar). Ingest'in `finally`'si `gen.dispose()` çağırdığı için sorguya verilen "ingest yöneticisi" boş ve ayarsızdı → `checkSettingsForQuery` kod 3 → toplu sorgu düştü → `BSimDatabase` fonksiyon başına yola geçti (P16c yedeği; eşleşmeler o yüzden aynı). Kod yorumumdaki "yönetici dispose'dan etkilenmez" varsayımı kaynağa bakılmadan yazılmıştı; birim testindeki sahte `dispose` yöneticiyi temizlemiyordu → yeşil testler hatayı göremedi.
- **Onarım (`068be1fd`):** tam ingest'in `GenSignatures`'ı açık tutulur, sahipliği sorguya geçer (sorgu bitince bırakır); kullanılmazsa yeni ingest'te ve `close`'da bırakılır. Sahte `dispose` artık yöneticiyi temizliyor, sahte `QueryNearest` ayarsız yöneticide `None` dönüyor (eski kodda `test_sorgu_ingest_yoneticisini_kullanir_yeni_tarama_yok` ve yeni `test_tam_ingest_taramasi_sorguya_kadar_birakilmaz` kırmızı: mutant `hz2_ingest_taramasi_birakilir`). Ayrıca tam takımda (başka bir test JVM'i başlatmışken) `_java_iterator` sahte öğeleri `ArrayList`'e koyamıyordu (`TypeError`) → Python yineleyicisine düşer (yalnız Java olmayan öğede).
- Fizibilite ve H4 1. turda (`af7dae70`) koşuldu; onarım o yollara dokunmuyor (kısmi ingest yöneticiyi saklamaz; yineleyici düşüşü yalnız Java olmayan öğede), yeniden koşulmadı.
- 2. tur kuyruk: yuva 1'i PUV6b ardışık çağrılarla tuttu (13:49–14:11 HZ2 bekledi); ana oturumun Ollama koşusu 14:11:45'te bitince S8 yuva 2'de başladı (14:11:46). Ara sonuç: cat **eşit**; sort **eşit** (`scan_mode` dışında; BSim dosyaları dahil; sorgu ingest yöneticisini kullandı: sorgu adımı 2,607 → **0,289 sn**, ingest 2,776 → 3,209 sn; yük altında).
- **13:50 — bekliyorum (2. tur):** sürücü yeniden başladı (`urun-068be1fd`, ayrı kök `…/HZ2/s8`): S8 (8) → H2 (cat, zstd) → T25. Yuva 1'de PUV6b ile sıra, yuva 2'de ana oturumun Ollama koşusu. TAHMİNİ: S8 14:20–14:40, H2 14:30–14:50, T25 ancak 14:52'den önce başlarsa (15:12'de süre sınırı), değilse "kalan".

## Kalem 9b — S8 2. tur (kod `068be1fd`; H1)

- Koşu: ürün ağacı `urun-068be1fd`, kökte `karadul.yaml` = `ayar/s8_acik.yaml` (`bsim.paralel_tarama: true`; öbürleri main öntanımı), sürücü `betik/kos_hepsi.zsh` (ikili başına bir kuyruk çağrısı, `urun_kos.py --zaman-asimi 2400`), sıra ORTAK_D0 §6, tek kök `…/HZ2/s8`, koşuya özel boş `KARADUL_CACHE_DIR` (`…/HZ2/s8/cache`). 14:11:46–14:31:25, 8 / 8 çıkış 0, yuva 2; koşu başında 1 dk yük 9,1–18,4 (**yük altında**).
- Kıyas: taban `ANA/s8_taban_534e252b` ↔ `HZ2/s8`, ham (`s8_esitlik.ikili_kiyasla`, `HARIC_ALANLAR` = zaman alanları); ek olarak yalnız `bsim_detail.scan_mode (yalnız sonra)` birimi düşüldü (`betik/analiz.py` → `ozet/hz2_ozet.json` `H1`).

| İkili | JSON farklı / dosya | `.c` farklı / dosya | ad haritası farklı / dosya | `ghidra_status` eski alan | `pcode.jsonl` | BSim (sonra) | ingest sn (taban → sonra) | sorgu sn (taban → sonra) |
|---|---|---|---|---|---|---|---|---|
| debian/coreutils/cat | 0 / 23 | 0 / 296 | 0 / 3 | 0 | eşit | `atlandi`, 0 / 0 | 1,458 → 3,617 | 0,216 → 0,228 |
| debian/coreutils/sort | 0 / 23 | 0 / 625 | 0 / 3 | 0 | eşit | `ok`, 244 / 180 | 2,776 → 3,209 | 2,607 → 0,289 |
| debian/tree/tree | 0 / 23 | 0 / 250 | 0 / 3 | 0 | eşit | `ok`, 119 / 50 | 1,662 → 3,480 | 1,674 → 0,263 |
| debian/sqlite3/sqlite3 | 0 / 23 | 0 / 1 144 | 0 / 3 | 0 | eşit | `ok`, 429 / 95 | 5,429 → 6,185 | 5,324 → 0,391 |
| debian/htop/htop | 0 / 23 | 0 / 1 148 | 0 / 3 | 0 | eşit | `ok`, 609 / 188 | 3,336 → 3,830 | 3,091 → 0,218 |
| debian/tmux/tmux | 0 / 23 | 0 / 2 588 | 0 / 3 | 0 | eşit | `ok`, 1 920 / 384 | 11,845 → 7,129 | 12,728 → 0,793 |
| debian/zstd/zstd | **2 / 23** (`decompiled.json` ve `static/ghidra_decompiled.json`: `functions[].pcode_ops` 6 yaprak) | **1 / 1 444** (`FUN_001063c0.c`) | **2 / 3** (`ws/reconstructed/src{,_iter1}/naming_map.json`; `out/naming_map.json` eşit) | 0 | **farklı** | `ok`, 1 086 / 561; BSim dosyaları eşit | 32,739 → 8,935 | 42,652 → 0,706 |
| mac/tmux | 0 / 23 | 0 / 2 821 | 0 / 3 | 0 | eşit | `ok`, 2 588 / 1 385 | 19,274 → 6,639 | 19,775 → 1,186 |

- **BSim dosyaları** (`bsim_matches.json`, `bsim_shadow.json`, `static/ghidra_bsim.json`): `scan_mode` dışında **8 / 8 eşit** (eşleşme listesi, sayaçlar, `query_mode: batch`, dışlama sayaçları dahil). `scan_mode` 8 / 8 `parallel`; `scan_fallback_error` / `scan_sayac` hiçbirinde yok.
- **zstd farkı:** `FUN_001063c0.c`'de iki geçici değişkenin yer değiştirmesi (`iVar11 = (int)local_180; iVar12 = local_180._4_4_;` ↔ tersi, ve çağrıdaki sıra) — ön kayıtta yazılı bilinen kendiliğinden fark (P16e: 6 koşunun 1'i). Decompile adımı BSim'den önce koşar ve bu paket ona dokunmaz; kural gereği zstd paralel açık bir kez daha koşuluyor (aşağıda).
- **zstd tekrarı** (paralel açık; S8'in zstd öncesi deposunun kopyası `…/HZ2/s8_zstd_tekrar/cache`, ikinci ürün ağacı `urun-068be1fd-b` aynı commit + aynı `karadul.yaml`; kuyruk `HZ2 S8tekrar:debian/zstd/zstd`, 14:3x–14:36:33): taban ile `scan_mode` dışında **tam eşit** (JSON 0 / 23, `.c` 0 / 1 444, ad haritası 0 / 3, `pcode.jsonl` eşit). İki sonuç: 1. koşu `FUN_001063c0` takası (bilinen), 2. koşu eşit → fark kendiliğinden (`ozet/zstd_tekrar.json`).
- **H1 hükmü:** BSim dosyaları `scan_mode` dışında **8 / 8 bayt eşit**; `decompiled/*.c`, öbür `ghidra_output/*.json`, `out/naming_map.json`: ilk koşuda **7 / 8** (zstd: ön kayıtta yazılı bilinen `FUN_001063c0` takası; `out/naming_map.json` orada da eşit), zstd tekrarıyla **8 / 8** → **TUTTU** (ön kayıttaki tekrar kuralıyla; iki sonuç da yazıldı).

## Kalem 9c — H2 (bayrak kapalı: cat, zstd)

- Ürün ağacı kökünde `karadul.yaml` = `ayar/s8_kapali.yaml` (`bsim.paralel_tarama: false`). cat taze depoyla (tabanda da ilk ikili), zstd S8'in zstd öncesi deposunun kopyasıyla (`…/HZ2/s8_kapali/cache_zstd`; taban zstd'si 6 programlık depoda koştu). Kuyruk yuva 2, 14:31:25–14:38:21, yük 10,7–20,8 (**yük altında**).
- cat: **ham eşit** (JSON 0 / 23 — BSim dosyaları dahil, `scan_mode` yok; `.c` 0 / 296; ad haritası 0 / 3; `pcode.jsonl` eşit); ingest 1,536 sn (taban 1,458). zstd: **ham eşit** (JSON 0 / 23, `.c` 0 / 1 444, ad haritası 0 / 3, `pcode.jsonl` eşit).
- **H2: TUTTU (2 / 2).**

## Kalem 10 — T25 (H3, H5)

- **14:38 — bekliyorum:** T25 14:38:21'de yuva 2'de başladı (`HZ2 T25:ollama`; 1 dk yük 20,76; aynı anda yuva 1'de HZ4a'nın `T25:kapali` koşusu: **yük altında**). `python -m karadul analyze …/gosteri-2026-11-19/ollama/girdi/Ollama --stage static --config ayar/t25_ollama.yaml --verbose` (OL2 T25'in `analysis` bölümü + ÖL-2 değerleri + `bsim.paralel_tarama: true`), taze `KARADUL_CACHE_DIR`, ürün ağacı `urun-068be1fd`, süre sınırı 2 019 sn (15:12). TAHMİN: BSim ingest ≈ 14:55'te başlar (OL2'de köprü başından 16,5 dk), köprü 15:00–15:10 biter; 15:12'de bitmemişse koşu kesilir ve `ILERLEME` satırlarından ölçülebilen kadarı yazılır.

## Süre notu (S8)

- Süreler "yük altında"; taban (ANA, 13:10–13:35) ile sonra aynı anda koşmadı → oran hükmü yok (yalnız yön): küçük ikililerde (≤ ~600 fonksiyon) ingest paralel yolda daha YAVAŞ (işçi açılışı), büyüklerde hızlı (zstd 3,7×, mac/tmux 2,9×); sorgu ingest yöneticisini kullandığı için ikinci tarama yok (sorgu 10–60× kısa).

## Kalem 11 — tam takım (yamasız)

- 1. koşu (13:35:51–13:47:41, kod `db04064a` = `af7dae70` + belge / tanım): 11 181 geçti / 23 atlandı / 13 kaldı. 12'si `tests/test_hz2_bsim_hizli.py`: tam takımda başka bir test JVM'i başlatmışken `_java_iterator` sahte öğeleri `java.util.ArrayList`'e koyamadı (`TypeError: No matching overloads found for java.util.ArrayList.add(_Func)`) → kalem 9a'daki onarımla (`068be1fd`) giderildi. 13.'sü beklenen `test_p15a_etkisiz`.
- **2. koşu (kesin; 13:55:24–14:05:58, 632 sn; kod `710d745e` = `068be1fd` + belge / tanım; 1 dk yük 8,82 → 7,23, aynı anda Ghidra kuyruğu ve başka ajanlar: yük altında): 11 197 geçti / 23 atlandı / 1 kaldı** (152 seçilmedi). Kalan tek test beklenen: `tests/test_p15a_etkisiz.py::test_inert_registry_is_accurate` — `AssertionError: kayıtta ama okunuyor: {'bsim.paralel_tarama': ['karadul/ghidra/bsim.py']}` (yama INERT satırını siler; yamalı kopyada 11 / 11 geçti, kalem 4 ek). Uyarılar (3) bu paketten değil (iki `ComputationRecoveryConfig`, bir `jpype.isThreadAttachedToJVM` — `headless.py:275`, ÖL-1).
- Worktree'de geçici çalışma verisi bağları (`sigs`, `vendor`, `scripts/node_modules`, `signatures*.json`, `sigs_macos_system.json`, `signatures.lmdb`) kuruldu; commit'lenmedi; kapanışta kaldırılacak. Günlük `…/HZ2/tam_takim2/pytest.log`, kopyası `ozet/tam_takim_pytest.log`.

## Sonraki paketlere not

### ÖL-9 (kısmi ingest'in tamamlanması; önbellek)

- **Ölçüldü:** aynı md5 için ikinci `InsertRequest` reddedilir (`Skipping -insert- : <ad> is already ingested`; `AbstractSQLFunctionDatabase.testExecutableDuplication`: yalnız `ExecutableRecord.isLibrary()` olan yürütülebilire kısmi ekleme var). `QueryDelete` (`ExeSpecifier.exemd5 = md5`) + taze yöneticiyle tam `InsertRequest` kabul edilir (sqlite3: 3 → 668 fonksiyon tanımı). NOT: reddedilen ekleme denemesi yöneticinin yürütülebilir kaydına satır kimliği / "zaten saklı" işareti yazar; silmeden sonra AYNI yönetici yeniden kullanılmamalı (fizibilitede taze tarama kullanıldı).
- **Öneri (uygulanmadı):** `_exe_already_ingested` doğru VE köken kaydında `kismi` varsa (bu paketin işareti) depo kilidi altında `QueryDelete(md5)` → tam ingest (bütçeyle; yine kesilirse işaret kalır) → tam bittiyse işaret kalkar (`_ProvenanceStore.record(..., tam=True)` hazır). Silme ile yeniden ekleme arasında süreç ölürse md5 depoda hiç kalmaz (kısmidan kötü değil; sonraki koşu baştan ekler). Silme bu depodaki başka kayıtlara dokunmaz (md5 ile).
- Bugün görünen: `bsim_detail.onceki_ingest_kismi: "t / N"` + WARN; köken kaydında `executables.<md5>.kismi`.

### ÖL-3 + HZ-4a (Java tarafı paralellik / döküm)

- Ghidra'nın `ConcurrentQ` yolu izleyici ister: ilerleme sayacı için tek uygun sınıf paket-içi `BasicTaskMonitor` (yansımayla; `TaskMonitorAdapter` saklamaz, `GTaskMonitor.addCancelledListener` `UnsupportedOperationException`). İptalden sonra sayaç atılan işleri de sayar (fizibilite: 2 imzalı iş, sayaç 429): kesilme anındaki "işlenen" sayısı sayaçtan değil çıktıdan sayılmalı.
- İşçi açılış maliyeti gerçek: decompiler işçisi başına süreç; sqlite3'te ilk ~0,4 sn sayaç 0; 2 sn bütçede paralel yol 6 fonksiyon (tekli 253); S8 cat'te (107 fonksiyon) ingest 1,458 → 3,41 sn (yük altında). Küçük iş kümesinde paralel yol kayıp; eşik (fonksiyon sayısı) A-9 gereği donanımdan türetilmeli — HZ-9 ölçümüyle.
- Java yineleyicisi: 13 bin fonksiyonluk `ArrayList` Python'dan tek tek `add` ile kuruluyor (JPype çağrısı başına); ölçülmedi, T25'te ingest süresinin içinde.

### Ana oturum (yamayı uygularken)

- Yama `bsim.paralel_tarama` öntanımını True yapar: sonraki bütün koşularda `bsim_matches.json` / `bsim_shadow.json` / `static/ghidra_bsim.json`'da `bsim_detail.scan_mode` alanı çıkar → S8 tabanı yenilenmeli ya da kıyas bu alanı düşmeli (`s8_esitlik.HARIC_ALANLAR` ön kayıtla sabit; HZ-1 kuralı gereği koşudan sonra genişletilmedi, bu pakette ayrı süzgeç `betik/analiz.py`).
- Başka test dosyası yaması gerekmiyor (yamalı kopyada 9 dosya 335 / 335).

## Ölçüm

**13:35 — bekliyorum:** ölçüm sürücüsü (`…/HZ2/betik/kos_hepsi.zsh`, arka planda) kuyrukta: fizibilite → H4 (sqlite3) → S8 (8 ikili, paralel açık, tek kök `…/HZ2/s8`) → H2 (cat taze depo, zstd S8'in zstd öncesi deposunun kopyasıyla; kapalı) → T25. Yuva 2'yi ana oturumun Ollama kabul koşusu tutuyor (13:10'dan beri), yuva 1'de OL4 ve PUV6b ile sıra. 1 dk yük 26–56 (**yük altında**). TAHMİNİ bitiş: fizibilite + H4 13:45–13:55; S8 14:25–14:45 (taban S8 yük altında ≈ 30 dk); H2 14:35–14:55; T25 ancak 14:52'den önce başlarsa (süre sınırı 15:12'de biter), değilse "kalan".
