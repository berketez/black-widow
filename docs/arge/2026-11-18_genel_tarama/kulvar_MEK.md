# Kulvar MEK — ana oturumun mekanik ve canlı denetimleri
Kapsam: tam test takımı, CI dışı testler, pyflakes, mypy, içe aktarma erişim haritası, ayar okunma haritası,
CLI duman testi, arayüz sunucusunun canlı yoklaması (tarayıcıyla), JS hattının uçtan uca denemesi,
HEAD (e9d2d08, 1.23.1) ile 14 gerçek ikilinin koşusu. Ham çıktılar: `mekanik/`.
Hepsi bu oturumda çalıştırılarak ya da koddan okunarak görüldü; ajan aktarımı değil.

## Sağlam çıkanlar (bulgu değil, zemin)
- Tam takım: **8 289 geçti, 10 atlandı, 0 kaldı** (185 sn). CI dışı `integration`/`benchmark` kümesi: **141 geçti, 12 atlandı, 0 kaldı** (130 sn).
- Testler çalışma ağacını kirletmiyor (`git status` yalnız bu tarama dizinini gösteriyor).
- 7 127 test fonksiyonunun yalnız 16'sında doğrulama ifadesi yok (çoğu "istisna atmamalı" türü); test takımı yapısal olarak sağlıklı.
- pyflakes: 307 uyarının tamamı kullanılmayan içe aktarma / kullanılmayan yerel / Ghidra betik globali; tanımsız ad ya da gölgeleme hatası yok (tek istisna MEK-14).
- README bugünkü durumu dürüst anlatıyor (ölçülmüş yanlış ad oranları, "sürüm yok", "kalibre değil").

## MEK-01 — `karadul analyze` boru hattı başarısız olunca da çıkış kodu 0 veriyor ve hatayı ekrana yazmıyor
- Önem: YÜKSEK
- Tür: sahte/yanlış gösterim
- Yer: `karadul/cli.py:813-862` (sonuç tablosu; başarısızlıkta yalnız çerçeve rengi sarı), `analyze` gövdesinde `result.success` için `sys.exit` yok
- Etkin mi: evet
- Ne: Boş dosya ya da düz metin verildiğinde `pipeline.success = false`, `static` aşaması "Analyzer bulunamadi: No analyzer registered for TargetType.UNKNOWN", `reconstruct` "Deobfuscate edilmis dosya bulunamadi" hatası taşıyor; ama CLI hiçbir hata satırı basmıyor, "Results" tablosunu ve dört rapor dosyasını üretiyor, çıkış kodu 0. "Pipeline" başlığının altı boş kalıyor.
- Kanıt: `: > bos; python -m karadul analyze bos --skip-dynamic; echo $?` → tablo + `0`; `reports/report.json` içinde `"success": false`.
- Etki: Betikle çalıştıran (toplu koşu, `urun_kos.py`, CI) başarısız analizi başarılı sayar; analist tanınmayan dosyada "0 fonksiyon" raporu alır, neden olduğunu görmez.
- Güven: kesin
- Onarım kapsamı: `karadul/cli.py` (analyze sonu: aşama hatalarını yaz, `result.success` değilse çıkış 1; `--json` yolunda da). S. Dikkat: `urun_kos.py` ve arayüz sunucusu çıkış kodunu okuyor; birlikte gözden geçirilmeli.
- Nasıl sınanır: boş dosyada çıkış kodu ≠ 0 ve stderr'de aşama hatası; geçerli ikilide 0.

## MEK-02 — `karadul diff` Ghidra projesini incelenen ikilinin yanına yazıyor
- Önem: ORTA
- Tür: hata
- Yer: `karadul/ghidra/program_diff.py:199-221` (`effective_output = output_dir or binary1.parent`; `open_program(..., project_name="diff_prog1")`)
- Etkin mi: evet (`karadul diff`)
- Ne: Çıktı dizini verilmezse proje dizini ilk ikilinin bulunduğu dizin oluyor. Salt okunur dizinde komut düşüyor; yazılabilir dizinde örnek dosyanın yanına `diff_prog1` / `diff_prog2` proje dizinleri bırakıyor (inceleme altındaki kanıt dizinini kirletir).
- Kanıt: `python -m karadul diff /bin/ls /bin/cat` → `HATA: Diff basarisiz: [Errno 1] Operation not permitted: '/bin/diff_prog1'`.
- Güven: kesin
- Onarım kapsamı: `program_diff.py` (geçici dizin + temizlik). S.
- Nasıl sınanır: `/bin/ls` ile `/bin/cat` karşılaştırması çalışır; ikililerin dizininde yeni dosya oluşmaz.

## MEK-03 — "Öntanımlı çevrimdışı" sözü JS hattında tutmuyor: `.d.ts` indirmesi ağ bayrağına bakmadan unpkg.com'a gidiyor
- Önem: YÜKSEK
- Tür: tutarsızlık | güvenlik (operasyonel gizlilik)
- Yer: `karadul/reconstruction/naming/pipeline.py:101-167` (`dts_namer_remote = DtsNamer(timeout=8)`; `fetch_dts_content`), `karadul/reconstruction/dts_namer.py:448-490`, `karadul/config.py:330-341` (`NetworkConfig.allow_dts_fetch`, `allow_source_match` hiç okunmuyor)
- Etkin mi: evet (`stages.py:1142 → _execute_js → stages.py:5369 NamingPipeline`), koşul: npm parmak izi eşleşen paket 11 adlık beyaz listede (`semver`, `chalk`, `commander`, `yaml`, …) ve yerelde `.d.ts` yok
- Ne: `NetworkConfig` belgesi "hiçbir HTTP çağrısı yapılmaz; `--enable-network` ile açılır" diyor ve README bunu yineliyor. Kaynak eşleme (`SourceMatchConfig.enabled = False`) ve başvuru indirme (`_feedback_naming_refdiff.py:118`) bu anahtara bağlı; `.d.ts` indirmesi bağlı değil. `network.enabled` yalnız `cli.py`, `config.py` ve `_feedback_naming_refdiff.py`'de okunuyor.
- Kanıt: `grep -rn "allow_network\|network.enabled\|allow_dts_fetch" karadul/reconstruction/` → `dts_namer.py` ve `naming/pipeline.py`'de eşleşme yok; `mekanik/ayar_okunma.txt` (`allow_dts_fetch`, `allow_source_match` erişim 0).
- Etki: Zararlı bir Electron/Node paketini inceleyen analistin makinesi, haberi olmadan dış sunucuya paket adlarını taşıyan istek atar. Ürünün yazılı güvencesi yanlış.
- Güven: yüksek (kod yolu izlendi; canlı istek bu oturumda tetiklenmedi, örnek dosyada parmak izi eşleşmedi)
- Onarım kapsamı: `naming/pipeline.py` (uzak namer'ı `config.network.enabled and allow_dts_fetch` koşuluna bağla), isteğe bağlı `dts_namer.py`. S.
- Nasıl sınanır: ağ kapalıyken `urllib.request.urlopen` çağrılırsa düşen birim testi; açıkken çağrıldığını gösteren test.

## MEK-04 — Uygulama her açılışta, ağ ayarından bağımsız olarak GitHub'a güncelleme sorgusu atıyor; kapatma ayarı yok
- Önem: ORTA
- Tür: tutarsızlık
- Yer: `ui/app_window.py:189-200, 512`, `ui/server.py:1287-1335`
- Etkin mi: evet (paketli uygulama; geliştirme kipinde `server.py` tek başına sorgu atmaz)
- Ne: Pencere açılınca arka planda `/api/update-check` çağrılıyor; sunucu `github.com/.../appcast.json`'a istek atıyor (önbellekle seyreltilmiş). `network.enabled = false` iken de çalışıyor; arayüzdeki ayar panelinde "ağ kapalı" görünürken dışarı istek gidiyor. Kapatacak bir ayar ya da ortam değişkeni yok.
- Güven: yüksek (kod; paketli uygulama bu oturumda çalıştırılmadı)
- Onarım kapsamı: `ui/app_window.py`, `ui/server.py` (ağ ayarına ya da ayrı bir `update_check` ayarına bağla). S. Karar: Berke (güncelleme bildirimi mi, tam çevrimdışılık mı).

## MEK-05 — 231 ayar alanının 83'üne kodda öznitelik erişimi yok; ~50'si hiçbir biçimde okunmuyor
- Önem: ORTA
- Tür: okunmayan ayar
- Yer: `karadul/config.py`; tam liste `mekanik/ayar_okunma.txt` (üretici `mekanik/ayar_okunma.py`)
- Etkin mi: evet (ayar dosyasında görünür, etkisi yok)
- Ne: Öne çıkanlar: `SecurityConfig`'in 8 sınırı (`max_download_size`, `max_decompress_bytes`, `max_flirt_entries`, `max_flirt_hex_length`, `max_capa_stderr_bytes`, …) hiç okunmuyor; `AnalysisConfig.max_file_size_mb` okunmuyor; `MinConfidencePresets`'in 16 eşiğinin 13'üne erişim yok (sihirli sayıları önlemek için kurulan merkezî tablo fiilen kullanılmıyor; eşikler kodda ayrıca sabit yazılı demektir); `DeepTraceConfig`'in 5 alanı; `enable_rtti_recovery`, `rtti_abi`; `DecompilersConfig.enable_parallel_decomp`, `secondary_backend`; `ToolPaths.ghidra_run`, `radare2`, `codesign`; `function_id_db_paths`; `max_decompile_timeout_per_func`. `dize` sütunu 0'dan büyük olanlar `getattr(cfg, "ad")` ile okunuyor olabilir; onlar tek tek doğrulanmalı.
- Kanıt: betik çıktısı; örnek doğrulama `grep -rn "max_file_size_mb" karadul ui` → yalnız tanım.
- Etki: Kullanıcı ayarı değiştirir, hiçbir şey değişmez; güvenlik sınırı "var" sanılır.
- Güven: yüksek (statik; `getattr` ile dinamik erişim `dize` sütununda ayrıca sayıldı)
- Onarım kapsamı: `karadul/config.py` (tehlikeli dosya: tek elden, sıralı). Her alan için karar: bağla ya da sil. M.

## MEK-06 — mypy 101 hata veriyor ve CI'da mypy koşmuyor
- Önem: DÜŞÜK
- Tür: test boşluğu
- Yer: `mekanik/mypy.txt`; `.github/workflows/ci.yml` (mypy adımı yok)
- Ne: Haziran'da "mypy 0 hata" kayıtlıydı. Bugün 12 dosyada 101 hata: `c_flow_simplifier.py` 48, `tarif/kesin.py` 23, `macho.py` 7, `c_project_builder.py` 5, `lm/probe.py` 5, `lm/agent.py` 5, … Çoğu `Optional` daraltması; `tarif/kesin.py:943-1048` aynı değişkene hem `int` hem `str`, hem `set` hem `tuple` atıyor (bakılmalı).
- Güven: kesin
- Onarım kapsamı: ilgili 12 dosya + CI adımı. M. Dosyaların dördü tehlikeli/yoğun dosya; başka onarımlarla aynı elden yapılmalı.

## MEK-07 — Ürün giriş noktalarından erişilemeyen 46 modül / 8 149 satır
- Önem: ORTA
- Tür: ölü kod
- Yer: `mekanik/erisim.txt` (üretici `mekanik/erisim.py`; `karadul.cli`, `karadul.__main__`, `ui/server.py`, `ui/app_window.py`'den statik içe aktarma kapanışı; üst paketin `__init__`'i içe aktarıyorsa erişilir sayıldı, yani liste ALT sınırdır)
- Ne: `karadul/lm/` paketinin tamamı (10 modül, 4 324 satır: arayüze ve CLI'a bağlı değil), `analyzers/container_classifier.py` (1 148), `reconstruction/engineering/confidence_calibration.py` (806), `computation/struct_recovery/field_namer.py` (315), `analyzers/demangler_registry.py` (276), `reconstruction/jsnice_renamer.py`, `pipeline/steps/_capa_comment_inject.py`, `pipeline/steps/trex_export.py`, `core/content_store.py`, `reconstruction/ts_declarations_namer.py`, `karadul/scripts/*` (3 betik; paket içinde ama giriş noktası tanımlı değil).
- Güven: yüksek (statik)
- Onarım kapsamı: kalem kalem karar (bağla / sil / `scripts/`'e taşı). `karadul/lm/` bilerek bağsız (Aşama 1b).

## MEK-08 — Arayüz: adsız fonksiyon etiketi adresin son 6 hanesinden üretiliyor; yeniden adlandırma kutusu bu uydurma etiketle doluyor
- Önem: ORTA
- Tür: sahte/yanlış gösterim | hata
- Yer: `ui/index.html:877, 975, 998, 1006, 1124`
- Etkin mi: evet (tarayıcıda görüldü; Mac htop çalışma alanı)
- Ne: Adsız fonksiyon listede, grafikte ve başlıkta `'FUN_'+f.addr.slice(-6)` ile gösteriliyor (`FUN_1000052f4` → `FUN_0052f4`). (1) Bu ad ikilide ve Ghidra'da yok; analist başka araçla (Ghidra, rapor, `naming_map.json`) çapraz bakarken bulamaz; aynı ekranda kod görünümü `FUN_1000052f4` yazıyor. (2) Alt 24 biti aynı olan iki fonksiyon (16 MB'tan büyük adres aralığı; hedeflenen 30–40 MB ikililer) aynı etiketi alır. (3) `renameInput` bu kısaltılmış etiketle doluyor; analist onay tuşuna basarsa var olmayan `FUN_0052f4` adı elle verilmiş ad olarak kaydedilebilir (sunucunun reddedip etmediği ARAYUZ kulvarında denetlenmeli).
- Kanıt: tarayıcıda `renameInput.value == "FUN_0052f4"`, satırın `data-addr == "FUN_1000052f4"`.
- Güven: kesin (görünüm); (3)'ün sonucu denenmedi
- Onarım kapsamı: `ui/index.html` (tam adı göster ya da kısaltmayı yalnız görsel kırpma yap; kutuyu boş ya da gerçek adla doldur). S.

## MEK-09 — CLI küçük kusurları
- Önem: DÜŞÜK
- Tür: hata | sahte/yanlış gösterim
- Yer: `karadul/cli.py` (ilgili komutlar)
- Ne: (a) `karadul clean <olmayan>` çalışma alanının varlığına bakmadan önce silme onayı soruyor. (b) `karadul score <boş dizin>` uyarısız `Toplam: 0.00/100`, çıkış 0 (C dosyası yokken puan anlamsız). (c) `karadul info` evrensel (fat) Mach-O'da dil `unknown`, dilimleri göstermiyor. (d) Bütün CLI metinleri Türkçe karaktersiz ("Hedef uzerinde tam analiz pipeline calistir", "Henuz analiz edilmis hedef yok"); proje yazım kuralına aykırı ve İngilizce başlıklarla karışık.
- Güven: kesin (a, b, d çalıştırıldı)
- Onarım kapsamı: `karadul/cli.py`, `cli_common.py`, `hacker_cli.py`. S-M (metinler çok; testler metne bağlı olabilir).

## MEK-10 — Hiç koşmayan / hep atlanan testler
- Önem: DÜŞÜK
- Tür: test boşluğu
- Yer: `tests/test_*_parity.py` (8 "Runtime parity" testi: "PyGhidra 3.0 + Ghidra 12.0.4 kurulu CI image'inda koşulmalıdır" — öyle bir CI işi yok), `tests/test_stages_split_parity.py:292` ("Faz 2'de aktif olacak"), `tests/test_pipeline_e2e.py:246` (yer tutucu), `tests/test_python_pipeline_hardening.py` ×4 + `tests/test_pyz_archive.py:675` (girdi `/private/tmp/pycdc_e2e/...`: yeniden başlatmada silinen dizin; bugün yok → atlanıyor)
- Ne: CI ayrıca `tests/test_pipeline_e2e_real_binary.py`'yi dışlıyor ve `integration`/`benchmark` işaretli 153 testi hiç koşturmuyor (Ghidra yok). Sonuç: uçtan uca analiz yalnız geliştirici makinesinde, elle sınanıyor.
- Güven: kesin
- Onarım kapsamı: testler + (karar) Ghidra'lı bir CI işi ya da yerel "sürüm öncesi" betiği. M.

## MEK-11 — İmza veritabanı Ghidra'nın yapay `entry` etiketini CoreGraphics simgesi sayıyor (güven 0,98)
- Önem: ORTA
- Tür: sahte/yanlış gösterim
- Yer: çıktı `out/naming_map.json` → `candidates["entry"] = {"new_name": "entry", "source": "signature_db", "confidence": 0.98, "library": "CoreGraphics", "reason": "same_as_original"}` (Mac htop ve Mac tmux, 1.22.1 koşusu); üreten kod IMZA kulvarında aranmalı (`signature_db.py` ad eşleme yolu)
- Ne: `entry` Ghidra'nın giriş noktasına verdiği yapay addır; ikilide böyle bir simge yok. Ad kataloğunda aynı yazılışlı bir simge bulunduğu için "CoreGraphics, 0,98" adayı doğuyor. Ad değişmediği için haritaya girmiyor, ama kitaplık atfı ve sayaçlar ("imza eşleşmesi") bu tür eşleşmeleri taşıyabilir. Aynı mekanizma Ghidra'nın öbür yapay adlarında (`FUN_`, `thunk_`, `caseD_`) ateşlemiyor olabilir; denetlenmeli.
- Ek gözlem: Mach-O'da `entry` = `LC_MAIN` giriş noktası = `main`. Bu kesin ve bedava bir ad; ürün `entry` olarak bırakıyor (ELF'te `__libc_start_main` yolu `main`'i kurtarıyor).
- Güven: kesin (çıktıda görüldü); kök neden koddan izlenmedi
- Onarım kapsamı: `signature_db.py` (yapay Ghidra adlarını ad eşlemesinden dışla) + Mach-O için `main` ön adı (`elf_boilerplate.py` benzeri). S-M.

## MEK-12 — JS hattı kendi örnek dosyasında kısmi başarısız: çıkarılan modüller ayrıştırılamıyor; sayaçlar birbirini tutmuyor
- Önem: ORTA
- Tür: hata | sahte/yanlış gösterim
- Yer: `karadul/deobfuscators/deep_pipeline.py` (module_rename adımı ve modül çıkarımı); `tests/fixtures/sample_minified.js`
- Ne: `python -m karadul analyze tests/fixtures/sample_minified.js --skip-dynamic` → "module_rename başarısız: 3/3 modül yeniden adlandırılamadı (ilk hata: module_0.js: Babel parse basarisiz: Unexpected token (12:9))". Yani webpack modül çıkarımı sözdizimi bozuk dosya üretiyor. Çıkış kodu 0. `reconstruct` sayaçları: `variables_renamed 3` ↔ `rename_low_confidence 20`; `params_recovered 6` ↔ `params_applied 7` ↔ `params_recovery_rate "40.0%"`. CLI tablosunda "Deobf steps N/A", "Modules extracted N/A" (3 modül çıkarılmışken).
- Güven: kesin (çalıştırıldı); kök neden izlenmedi → BICIM kulvarı
- Onarım kapsamı: `deobfuscators/`, `stages.py` JS dalı sayaçları, `cli.py` tablo anahtarları. M.

## MEK-13 — Depoda kişisel/sabit yollar ve artıklar
- Önem: DÜŞÜK
- Tür: tutarsızlık
- Yer: `karadul/batch.py:37` (`/Users/apple/.local/bin/claude`), `scripts/benchmark_claude_code.py:31`, `scripts/string_bridge_benchmark.py:31` (`/Users/apple/Desktop/claudeopen`), izlenen `scripts/apply-names.mjs.bak2`, `scripts/context-analyzer.mjs.bak2`; kökte 9 eski rapor/plan dosyası (`AUDIT_2026_05_13.md`, `BENCHMARK_2026_05_14.md`, `MATH_VERIFICATION_REPORT.md`, `.EXPLORATION_SUMMARY.txt`, …) ve `docs/` altında eski iddialı planlar (`PLAN_80_PERCENT.md`, `MASTER_PLAN.md`, `IMPOSSIBLE_SOLUTIONS_PLAN.md`)
- Ne: Depo herkese açık. Eski belgelerdeki doğrulanmamış iddialar (F1, "%80") README'nin dürüst diliyle çelişiyor; okuyan hangisinin güncel olduğunu bilemez.
- Güven: kesin (dosyalar var); belgelerin içeriği tek tek okunmadı
- Onarım kapsamı: silme/taşıma Berke onayıyla (kalem kalem). S.

## MEK-14 — `dotnet_binary.py` aynı adı iki kez içe aktarıyor
- Önem: DÜŞÜK
- Tür: tutarsızlık
- Yer: `karadul/analyzers/dotnet_binary.py:39, 45` (pyflakes: "redefinition of unused 'resolve_tool' from line 39")
- Güven: kesin (pyflakes); hangisinin kazandığı okunmadı → BICIM kulvarı

## HEAD ile gerçek ikili koşusu (bulgu değil; öbür kulvarların bulgularının bugünkü sürümde sürdüğünün kanıtı)
- Koşu: `python scripts/measurement/urun_kos.py --agac /Users/apple/Black_Widow --kok ~/karadul_olcum/runs/genel-tarama-2026-11-18 --paralel 3 --yalniz …` (14 ikili; ürün e9d2d08 = 1.23.1; Ghidra 12.1.2; GT okunmadı). 14/14 "tamam", çıkış 0. Disk: 2,0 GB (silinmesi Berke onayına bağlı).
- Not: koşu sırasında makinede test takımı ve tarama ajanları da çalışıyordu; süreler (47–851 sn) karşılaştırma için kullanılmaz.

| İkili | Uygulanan ad | `kebap_ad` | `on_ad:gnulib` | Sahte bileşim (CFD / roket / matris / VPN / ses) | "Bluetooth" kümesi | SARIF paket / anti-debug iletisi | `recovered_struct` | "Galois field" (kodda) | Yapı kurtarma "yeniden yazılan" / `.c` | CFG-iso eşleşme | Füzyon kabul |
|---|---|---|---|---|---|---|---|---|---|---|---|
| debian/coreutils/cat | 12 | 0 | 9 | 3 | var | — | 2 | 0 | 592 / 296 | 0 | 0 |
| debian/coreutils/expr | 10 | 0 | 7 | 3 | var | — | 2 | 0 | 596 / 298 | 0 | 0 |
| debian/coreutils/ls | 11 | 0 | 7 | 3 | var | AntiDebug_Timing, MPRESS_Packed | 15 | 0 | 1330 / 665 | 0 | 0 |
| debian/coreutils/sort | 13 | 0 | 8 | 3 | var | MPRESS_Packed | 13 | 0 | 1250 / 625 | 0 | 0 |
| debian/htop/htop | 5 | 0 | 0 | 5 | var | AntiDebug_Timing, MPRESS_Packed | 222 | 8 | 2296 / 1148 | 0 | 0 |
| debian/openssl/openssl | 33 | 2 | 1 | 5 | var | MPRESS_Packed | 37 | 0 | 11344 / 5672 | 0 | 0 |
| debian/redis-tools/redis-cli | 6 | 0 | 1 | 4 | var | AntiDebug_Timing | 177 | 2 | 2222 / 1111 | 0 | 0 |
| debian/sqlite3/sqlite3 | 18 | 1 | 0 | 4 | var | MPRESS_Packed | 118 | 10 | 2288 / 1144 | 0 | 0 |
| debian/tmux/tmux | 293 | 101 | 1 | 3 | var | AntiDebug_Timing | 1208 | 2 | 5176 / 2588 | 0 | 0 |
| debian/tree/tree | 3 | 0 | 0 | 3 | var | ASPack_Packed | 10 | 0 | 500 / 250 | 0 | 0 |
| debian/zstd/pzstd | 4 | 0 | 0 | 3 | var | MPRESS_Packed | 323 | 0 | 2312 / 1156 | 0 | 0 |
| debian/zstd/zstd | 63 | 0 | 2 | 4 | var | AntiDebug_Timing, MPRESS_Packed | 384 | 0 | 2888 / 1444 | 0 | 0 |
| mac/htop | 0 | 0 | 0 | 4 | var | AntiDebug_SysctlCheck, MPRESS_Packed | 200 | 0 | 1580 / 790 | 0 | 0 |
| mac/tmux | 395 | 135 | 1 | 4 | var | AntiDebug_Timing | 1398 | 2 | 5642 / 2821 | 0 | 0 |

- Okuma: 14 ikilinin 14'ünde sahte bileşim iddiası ve "Bluetooth" kümesi var (ARAYUZ-01, IMZA-01); 9'unda paketleyici yanlış alarmı (IMZA-05); yapı kurtarmanın "yeniden yazılan" sayısı her ikilide dosya sayısının tam iki katı (BORU-01); CFG-iso ve füzyon 14/14'te 0 (TIP-01, TIP-02); `kebap_ad` iki tmux'ta 236 ad (AD-01); `pipeline_result.success` 14/14 True (hata sayısı 0).
- Aynı çıktılar üstünde 2026-11-10 sağlamlık denetimi (`denetle.py`) koşuldu; sonuç §"Sağlamlık denetimi".

## Sağlamlık denetimi (HEAD, 14 ikili)
- Komut: `denetle.py`'nin kökü bu koşuya çevrilerek (2026-11-11'deki `denetle_yeni_urun.py` kalıbı); ham sonuç `mekanik/saglamlik_head.json`. 14 koşu, 31 sn.
- **Dikkat:** denetim betiği 2026-11-10'da yazıldı; sonradan değişen çıktı biçimini (ad haritası 1.1, yeni koşucu günlüğü) bilmiyor. Bu yüzden `bitmedi` 14/14, `log_*`, `sayi:*`, `out_harita_ws_haritadan_farkli` 12, `readme_yapi_uyusmuyor` 14 sayıları büyük olasılıkla denetimin bayatlığıdır (B-B5 için ARAYUZ kulvarı README'nin diskle tuttuğunu gösterdi). Onarım dalgasından önce denetim betiği bugünkü biçime göre güncellenmeli; yoksa onarımın "önce/sonra" kanıtı olmaz.
- Biçimden bağımsız, süren kusurlar (ikili / adet): `decompiled_json_kirpik` 11 / 13 664 (B-B4); `yerel_son_tur_baska_adla_fonksiyon` 11 / 2 695, `yerel_ad_uygulanmamis_fonksiyon` 11 / 490 (B-A5); `eski_fonksiyon_adi_yorumda_kalan` 13 / 773 (B-B3); `baslik_tanim_farkli` 3 / 18 (B-B1; zstd, Mac htop, Mac tmux); `fonksiyon_anahtari_ghidrada_yok` 12 / 25; `yeni_ad_var_olan_fonksiyonla_cakisiyor` 2 / 3 (AD kulvarı: denetimin yanlış alarmı olabilir, kayıtlar `same_as_original`); `eski_fonksiyon_adi_kodda_kalan` 1 / 2.
- Günlük iletisi (11/14 ikili): "BSim native ingest basarisiz, lite'a dusulecek: BSim DB initialize basarisiz (karadul_bsim): Database already in use by another process". Yani `bsim_yedege_dustu` (B-B9) kusurunun bir nedeni: ortak BSim veritabanı aynı anda yalnız bir koşuya izin veriyor; paralel koşuda (ölçüm koşuları 3 paralel, arayüz + CLI birlikte) geri kalanlar sessizce yedeğe düşüyor ve sonuç koşunun eşzamanlılığına bağlı hâle geliyor (belirlenimsizlik). Ayrıntı GHIDRA kulvarında.
- Koddaki algoritma etiketleri (14 ikili, 46 etiket): 12'si "Galois field operations" (TIP-09'un HEAD'deki karşılığı; htop 8, sqlite3 10 satır).
