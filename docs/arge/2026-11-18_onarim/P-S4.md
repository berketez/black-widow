# P-S4 — `stages.py` 4. tur: native olmayan hatlar, evrensel dilim, dürüst durumlar, bekleyen yamalar

- Taban: `main` = `0984090` (kod `a62f15e` ile aynı; arada yalnız belge). `git merge --ff-only main` yapıldı.
- Ölçüm kökü: `~/karadul_olcum/runs/onarim-2026-11-19/P-S4/` (salt bu paket).
  - `agac_taban/`: tabanın `git archive` kopyası (+ `git init`, çalışma zamanı verisi symlink'li).
  - `agac_sonra/`: `0208a62`'nin (kalem 1–6) `git archive` kopyası, aynı biçimde.
  - `urun_taban/`, `urun_sonra/`: tree, mac/htop, expr ürün koşusu (`urun_kos.py --paralel 1 --yalniz …`,
    `PYTHONHASHSEED=0`, koşu başına ayrı `KARADUL_CACHE_DIR`: `cache_taban/`, `cache_sonra/`). Sıralı:
    önce taban (3 ikili), sonra "sonra" kolu. Ghidra yalnız bu iki koşuda.
  - `native_taban/`, `native_sonra/` (+ `js_taban/`, `js_sonra/`, ara ölçümler `js_k12/`, `k5_sonra/`):
    `kos_native.py` — native olmayan 11 örnek, `python -m karadul analyze <girdi> --skip-dynamic`,
    `GHIDRA_INSTALL_DIR` var olmayan yola çevrili (hiçbir örnek native hatta gitmedi).
- **Örnekler çalıştırılmadı.** `~/karadul_olcum/dogrulama_native/` salt okundu; analiz girdisi olarak
  kopyaları `girdi/`'de (sha256'lar MANIFEST ile aynı). Fiddle için `.app`'in `app.asar`'ı (P20'nin açtığı
  kopya) ve iki gerçek webpack paketi (`.webpack/renderer/816/index.js`, `.webpack/main/index.js`) ek
  gösterim girdisi. Fiddle `.app` zip'i `fiddle_app_zip/`'e açıldı (yalnız bileşen keşfi; Ghidra yok).
- Yeni testler `scripts/node_modules` symlink'i ister (worktree'de bağ var; commit'lenmedi).

## Ön doğrulama: main'de zaten uygulanmış yamalar
| yama | durum | nasıl doğrulandı |
|---|---|---|
| `P-S3b__stages.py.patch` | uygulanmış | `git apply --check --reverse` temiz |
| `P19__stages.py.patch` | uygulanmış (P-S1 biçiminde) | ters yama satır kaydığı yüzünden tutmuyor; `ReconstructionStage.execute`'ta "Kapsayici tanindi" dalı + `container_executables_total` vardı |
| `P03__stages.py.patch` | uygulanmış (P-S1 biçiminde) | YARA / capa bloğu `_run_yara_scan` / `_run_capa_scan`'de; `yara_status`, `capa_status` her koşulda |
| `P13a__stages.py.patch`, `P13b__stages.py.patch` | yok | `yamalar/` altında bu adla dosya yok |
| `P20__stages.py.patch` | UYGULANMAMIŞTI | `git apply --check` temiz → kalem 6'da uygulandı |

## Kalem 6 — bekleyen yamalar + onaylı silme (`0a5d555`)
- **P20 yaması** uygulandı: `ProjectBuilder.build(..., named_source=current_file)`; `rename_candidates_high/medium/low`;
  başarılı ad koşusunun `naming_result.errors`'ı aşama hatalarına. Fiddle renderer/816'da yeni alanlar dolu
  (`rename_candidates_low` 210 ≠ uygulanan `rename_low_confidence` 95: P20'nin sözleşmesi).
- **`stages._collect_all_algorithms` silindi** (K-10). Çağıran-yok kanıtı (`k6/cagiran_yok.py`, sonuç
  `k6/cagiran_yok_once.json`): AST'de ad atfı 0; nitelik atfı `stages_mod._collect_all_algorithms` yalnız
  `tests/test_v192_fixes.py`'de (4 test, varlık / davranış); öbür atıflar adımların kendi kopyaları
  (`semantic_naming`, `struct_recovery`, `deep_tracing`, `engineering_annotation` → `SemanticNamingStep`);
  dinamik `getattr`/`hasattr` yalnız aynı testte; `.mjs/.json/.yaml`'da 0. Yalnız onu sınayan 4 test, silindiğini
  kilitleyen 1 testle değişti.
- **İkinci `_seed_recovery_pre_names` çağrısı kaldırıldı.** P13a elle ad zorlamasını birleştiriciye
  (`force_manual_names`) taşımıştı; dönüş değeri okunmuyordu; Faz 3 `extracted_names`'i okumuyor. Belge
  güncellendi (`_apply_manual_overrides`, `_seed_recovery_pre_names`). Ürün koşusunda ad haritası, köken ve
  gnulib aday kaydı karşılaştırıldı (aşağıda "Ürün koşusu").
- Test: `test_v192_fixes`, `test_main_gnulib_seed_ordering`, `test_p20_project_readme`, `test_step_semantic_naming`
  84/84. Mutant: silme / çağrı kaldırma için anlamlı mutant yok (davranış ürün koşusuyla sınandı).

## Kalem 1 — BICIM-02: JS yeniden kurmanın kaynağı (`fd6751b`)
**Önce (gerçek örnek, taban kodu):**
| örnek | deobfuscation | reconstruct kaynağı | reconstruct |
|---|---|---|---|
| extractthis.asar (JS'siz ASAR) | ikili `.asar` derin hatta verildi; Babel `Unexpected character '\x04'` | `01_beautified.js` = ikili arşivin "beautify"ı | **başarılı**, 5 dosyalık proje (src/index.js, package.json, README, Dockerfile, .gitignore) |
| Fiddle app.asar (main_window, 4,8 MB) | `status: failed` (derin adım fallback kopyası) | `01_beautified.js` | başarılı; kayıtta deobfuscation durumu yok |
| Fiddle main.js (2,9 MB) | `status: failed` | `01_beautified.js` | başarılı; aynı |
| Fiddle renderer/816 | `status: ok` | `03_enhanced_renamed.js` (en büyük olduğu için tesadüfen doğru) | başarılı |

**Onarım** (`stages.py`): `ReconstructionStage._select_js_source` + `_JS_STEP_OUTPUTS`; `_execute_js` kaynağı
buradan alır, kaynak yoksa 'atlandı' + neden. `DeobfuscationStage._resolve_deob_input`: Electron'da JS yoksa
ve hedef `.js` değilse `None` → `_execute_deep` 'atlandı'.

**Sonra:** extractthis.asar deobfuscate + reconstruct **atlandı** ("çıkarılmış JS dosyası yok"; çöp proje 5 → 0
dosya). Fiddle app.asar / main.js: kaynak aynı (`01_beautified.js`) ama `deobfuscation_status: failed`,
`source_selection: deobfuscate_output` ve aşama hatasında "derin dönüşüm uygulanmadı" uyarısı. renderer/816:
`source_selection: deobfuscate_output`, `03_enhanced_renamed.js`.
**Test:** `tests/test_ps4_js_kaynak.py` 5 test, eski kodda 5/5 kırmızı. **Mutant** `ps4_k1_*` 5/5.
**Kalan (bu paketin değil):** Fiddle `main_window/index.js` ve `main/index.js`'te derin adım beautify sonrası
ayrıştıramıyor (`Unexpected token, expected ","`); bu yüzden üç JS çıktısının 0'ı `node --check`'ten geçiyor
(taban ve sonra aynı). JS hattı (P20b) kusuru.

## Kalem 2 — BICIM-13: modül ayırıcı ve proje kurucu (`140f765`)
**Önce:** Fiddle renderer/816 (17 webpack modülü, P20'den beri 17/17 ayrışıyor) → `modules_split` yok,
`reconstruction_mode: project_builder` (ProjectReconstructor hiç koşmadı). `reconstruct-project.mjs`'in kendisi
(taban betiği, `k2_mjs.py`): gerçek 17 modülde bölme / birleştirme tetiklenmedi (17 → 17 dosya, 0 ayrışmayan);
sentetik dizinde (`k2_sentetik.py`: 707 satırlık modül + 4 küçük modül, hepsi ayrışıyor) 5 → **4 dosya, 3'ü
`node --check`'ten geçmiyor** (iki satır-bölme parçası + aynı `const`'ı iki kez bildiren birleşik dosya).

**Onarım:** `stages.py` `webpack_dir = deobfuscated/webpack_modules/modules`; ProjectReconstructor dalında
betiğin `modules_parse_ok / failed` sayaçları `project_modules_parse_*` olarak, ayrışmayan varsa hata satırı.
`scripts/reconstruct-project.mjs`: bölme ve birleştirme kalktı (her modül kendi dosyasında; birleşik kimliklerin
tek dosyaya eşlenmesi de gitti); her yazılan dosya `@babel/parser` ile sınanır (smart-webpack-unpack.mjs ile
aynı ayar).

**Sonra:** renderer/816 `modules_split` 17, `reconstruction_mode: project_reconstructor`, proje modülleri
17/17 ayrışıyor; yeniden kurulan `.js` (node_modules hariç) 22 (21 ayrışan) → 65 (65 ayrışan). Sentetik:
5 → 5 dosya, 0 ayrışmayan. **Test:** `tests/test_ps4_modul_dizini.py` 3 test (eski kodda iki davranış testi
kırmızı; sayaç testi yeni alan). **Mutant** `ps4_k2_*` 3/3.

## Kalem 5 — dürüst durumlar (`90361c1`)
**Önce:** nupkg ×2 + wheel: static "Analyzer bulunamadi: No analyzer registered for TargetType.UNKNOWN",
deobfuscate "Hedef türü tanınmadı; … .js uzantısıyla verin" (3/3). Kapsayıcısız UNKNOWN reconstruct'ta JS
hattına düşüp "Deobfuscate edilmis dosya bulunamadi". `_execute_binary`'nin üç `except RuntimeError` dalı
`reconstruct_status` yazmıyordu.
**Onarım:** `unsupported_target_reason` / `container_stats` (tek kaynak); static UNKNOWN'da
`static_status: desteklenmiyor` + "Desteklenmiyor: kapsayıcı tanındı (<tür>) ama doğrudan analiz hattı yok:
<P19 nedeni>" ya da "hedef türü tanınmadı (sihirli sayı …)"; aşama başarısız kalır (analiz yapılmadı; 'tam'
çıkış kodu sahte başarı olurdu). Deobfuscate / reconstruct aynı nedenle 'atlandı'; UNKNOWN JS hattına
girmez. `_runner_failure`: `reconstruct_status: basarisiz` + `reconstruct_failure_reasons` ("Faz N adım
koşucusu düştü: …").
**Sonra:** nupkg / wheel: üç aşamada da kapsayıcı türü + P19 nedeni ("Analyzer bulunamadi" / "Hedef türü
tanınmadı" 3/3 → 0/3); çıkış kodu 1 (değişmedi). **Test:** `tests/test_ps4_durumlar.py` 6 test (eski kodda
6/6 kırmızı); `test_ps1_kapsayici.py::test_unknown_without_container_still_goes_js` → `…_is_skipped_not_js`
(P-S1 bu kararı P-S'ye bırakmıştı), `test_p15a_cikis.py` iki iletisi yeni metne. **Mutant** `ps4_k5_*` 7/7.

## Kalem 3 — BICIM-09 + BORU-08: `.app` ana bileşeni (`c7e6a4e`)
**Önce:** ana bileşen = en çok fonksiyonlu başarılı bileşen. Gerçek Fiddle `.app` (`k3_fiddle_bilesen.py`,
`k3_fiddle_bilesen.json`): 6 bileşen — 5 Mach-O (`electron-fiddle`, Electron Framework 177 MB, Mantle,
ReactiveObjC, Squirrel) + 1 Electron (`app.asar`). ElectronAnalyzer fonksiyon saymaz (gerçek koşuda sayaç
anahtarı yok → 0); dolayısıyla Ghidra'lı koşuda en az bir fonksiyonu olan her yerel bileşen Electron'u
geçer, uygulamanın JS'i hiç yeniden kurulmaz. APP_BUNDLE deobfuscation'ı hep 'atlandı' olduğu için Electron
seçilse bile JS reconstruct'ı düşerdi. Ana bileşen JAR ise reconstruct "Bilinmeyen bilesen tipi: java_jar".
**Onarım:** `app_bundle.py` `component_tier` (uygulama kodu: electron_app / js_bundle > JAR >
Contents/MacOS ikilisi > çerçeve / dylib; katman içinde en çok fonksiyon); `bundle_analysis.json`'a
`main_component_type`, `main_selection_reason`, bileşen başına `role`; static aşaması gerekçeyi ve bileşen
listesini yazar. `stages.py`: DeobfuscationStage APP_BUNDLE'da ana bileşen Electron/JS → derin JS hattı,
JAR → analizcinin deobfuscate'i (bileşen hedefiyle); reconstruct'ta JAR / managed dalı.
**Sonra:** Fiddle katmanları: Electron App 0, electron-fiddle 2, dört çerçeve 3 → seçim Electron App.
**Uçtan uca Ghidra'lı `.app` koşusu yapılmadı** (Electron Framework'ü Ghidra'ya vermek saatler; BICIM-09 (4)
"her çerçeve Ghidra'ya" bütçesizliği bu paketin kapsamı dışında, açık). **Test:** `tests/test_ps4_app_bundle.py`
4 test (eski kodda 4/4 kırmızı); app bundle + yönlendirme takımları 73/73. **Mutant** `ps4_k3_*` 5/5.

## Kalem 4 — BICIM-10 (stages) + MEK-09 (c) evrensel dilim (`0208a62`)
- Tek `.pyc`, cx_Freeze → P19'dan beri PYTHON_PACKED (bu pakette değişiklik yok); wheel / nupkg / IPA → kalem 5.
- **Evrensel Go / Bun:** P19 dilim işaretini yazıyor, tür UNIVERSAL kalıyor; akışta görünmüyordu. Artık static
  aşaması `go_hatti_status` / `bun_hatti_status: desteklenmiyor` + neden ("yalnız yerel hat seçilen dilimde
  koştu"), aşama kısmi. Gerçek evrensel Go / Bun örneği yok (sentetik test).
- **Seçilen dilim** (`k4_dilim.py` → `k4_dilim.json`; worktree kodu, Ghidra yok): /usr/bin/ssh, /usr/sbin/sshd,
  /usr/sbin/ioreg → dilimler arm64e + arm64_sub12, seçilen **arm64e**, ince dosya çıkarıldı, hata 0; /bin/ls →
  arm64e (P16a sonucu korunuyor). Gerekçe kayıtta yoktu → **yama** `yamalar/P-S4__macho.py.patch`
  (`selection_rule` kayda ve `stats.universal_slice_rule`'a; `git apply --check` temiz).
- MEK-09 (c) `karadul info`'nun dilim göstermemesi `cli.py`'de (bu paketin dosyası değil); yapılmadı.
- **Test:** `tests/test_ps4_evrensel.py` 3 test (eski kodda 2/3 kırmızı; düz evrensel bekçisi iki kodda yeşil).
  **Mutant** `ps4_k4_*` 2/2.

## Ek — `73d8530`: atlanan ana bileşenin nedeni bundle hatasında
Kalem 1'den sonra Electron ana bileşeninde JS kaynağı yoksa `_execute_js` 'atlandı' döner; bundle
reconstruct'ı bunu nedensiz başarısızlık olarak gösteriyordu ("aşama başarısız (neden bildirilmedi)"). `_merge`
artık "Ana bileşen (<ad>) yeniden kurulmadı: <neden>" yazar. Test 1 (eski kodda kırmızı), mutant 1/1.
(Bu commit ürün koşusunun `agac_sonra/` kopyasında yok; yalnız APP_BUNDLE'a değer, ölçülen girdilerin hiçbiri `.app` değil.)

## Ürün koşusu — C / Mach-O / ELF ad haritası (kabul ölçütü)
`urun_kos.py --paralel 1 --yalniz debian/tree/tree --yalniz mac/htop --yalniz debian/coreutils/expr`,
`PYTHONHASHSEED=0`, ayrı `KARADUL_CACHE_DIR`; taban (`agac_taban/`, 0984090) ve sonra (`agac_sonra/`, 0208a62)
SIRALI. Karşılaştırma `karsilastir.py` → `urun_karsilastirma.json`.

| ikili | `out/naming_map.json` | eşleme / aday | `out/src` dosya | `out/src` farkı | gnulib aday kaydı | ad kökeni (`naming_provenance.json`) | birleştirici köken |
|---|---|---|---|---|---|---|---|
| mac/htop | **bayt bayt aynı** | 0 / 196 | 845 = 845 | yalnız `compile_commands.json` | aynı | aynı | ikisi de yok |
| debian/tree/tree | **bayt bayt aynı** | 3 / 69 | 275 = 275 | yalnız `compile_commands.json` | aynı | aynı | aynı |
| debian/coreutils/expr | **bayt bayt aynı** | 9 / 58 | 331 = 331 | yalnız `compile_commands.json` | aynı | aynı | aynı |

`compile_commands.json` farkı yalnız `"directory"` satırı (koşu kökünün mutlak yolu: `urun_taban/…` ↔ `urun_sonra/…`).
`reconstruct` istatistiklerinde fark yalnız ağaç yolu (`flirt_data_root`, `sigdb_data_root`, `sigdb_path`,
`ngram_db_dizini`) ve süre (`flirt_load_seconds`, `pipeline_iteration_details[].duration`). İkinci ön ad tohumunun
kaldırılması (kalem 6) bu üç ikilide ad haritasını, ad kökenini ve gnulib aday kaydını değiştirmedi.

## Native olmayan 11 gerçek örnek — önce / sonra (kabul ölçütü)
`kos_native.py` (taban = `agac_taban/`, sonra = `agac_sonra/` = 0208a62); son iki satır çifti ek gösterim
girdisi (Fiddle'ın iki gerçek webpack paketi). Sütunlar: aşama durumu (✓ başarılı, ✗ başarısız, atl atlandı;
parantezde aşama hata satırı sayısı), reconstruct'ın hattı (`reconstruction_mode` / analizci / kapsayıcı),
JS kaynağı, `reconstructed/` altındaki dosya sayısı, `node --check`'ten geçen `.js` (node_modules hariç) ve
bunun proje dizinindeki kısmı. Ham: `native_taban/ozet.json`, `native_sonra/ozet.json`, `js_*/ozet.json`,
tablo `native_tablo.md`.

| örnek | tür | kol | static | deobf | reconstruct | hat | kaynak | yeniden kurulan dosya | JS ayrışan / JS | proje JS ayrışan |
|---|---|---|---|---|---|---|---|---|---|---|
| commons-cli-1.6.0.jar | java_jar | önce | ✓ (1 h) | ✓ | ✓ | analizci | — | 1 | 0/0 | 0/0 |
| commons-cli-1.6.0.jar | java_jar | sonra | ✓ (1 h) | ✓ | ✓ | analizci | — | 1 | 0/0 | 0/0 |
| google-java-format-2.0.0-all-deps.jar | java_jar | önce | ✓ (1 h) | ✓ | ✓ | analizci | — | 1 | 0/0 | 0/0 |
| google-java-format-2.0.0-all-deps.jar | java_jar | sonra | ✓ (1 h) | ✓ | ✓ | analizci | — | 1 | 0/0 | 0/0 |
| de.markusfisch.android.binaryeye_182.apk | android_apk | önce | ✓ (1 h) | ✓ | ✓ | analizci | — | 1 | 0/0 | 0/0 |
| de.markusfisch.android.binaryeye_182.apk | android_apk | sonra | ✓ (1 h) | ✓ | ✓ | analizci | — | 1 | 0/0 | 0/0 |
| org.fossify.notes_13.apk | android_apk | önce | ✓ (1 h) | ✓ | ✓ | analizci | — | 1 | 0/0 | 0/0 |
| org.fossify.notes_13.apk | android_apk | sonra | ✓ (1 h) | ✓ | ✓ | analizci | — | 1 | 0/0 | 0/0 |
| newtonsoft.json.13.0.3.nupkg | unknown | önce | ✗ (1 h) | atl | atl | kapsayıcı | — | 0 | 0/0 | 0/0 |
| newtonsoft.json.13.0.3.nupkg | unknown | sonra | ✗ (1 h) | atl | atl | kapsayıcı | — | 0 | 0/0 | 0/0 |
| humanizer.core.2.14.1.nupkg | unknown | önce | ✗ (1 h) | atl | atl | kapsayıcı | — | 0 | 0/0 | 0/0 |
| humanizer.core.2.14.1.nupkg | unknown | sonra | ✗ (1 h) | atl | atl | kapsayıcı | — | 0 | 0/0 | 0/0 |
| yt-dlp_macos | python_packed | önce | ✓ | atl | ✓ | analizci | — | 1724 | 2/2 | 2/2 |
| yt-dlp_macos | python_packed | sonra | ✓ | atl | ✓ | analizci | — | 1724 | 2/2 | 2/2 |
| yt-dlp.exe | python_packed | önce | ✓ | atl | ✓ | analizci | — | 4239 | 2/2 | 2/2 |
| yt-dlp.exe | python_packed | sonra | ✓ | atl | ✓ | analizci | — | 4239 | 2/2 | 2/2 |
| extractthis.asar | electron_app | önce | ✗ (1 h) | ✗ (8 h) | ✓ (2 h) | project_builder | 01_beautified.js | 8 | 0/3 | 0/1 |
| extractthis.asar | electron_app | sonra | ✗ (1 h) | atl | atl | — | — | 0 | 0/0 | 0/0 |
| fiddle_app.asar | electron_app | önce | ✓ | ✗ (8 h) | ✓ (2 h) | project_builder | 01_beautified.js | 10 | 0/3 | 0/1 |
| fiddle_app.asar | electron_app | sonra | ✓ | ✗ (8 h) | ✓ (3 h) | project_builder | 01_beautified.js | 10 | 0/3 | 0/1 |
| six-1.16.0-py2.py3-none-any.whl | unknown | önce | ✗ (1 h) | atl | atl | kapsayıcı | — | 0 | 0/0 | 0/0 |
| six-1.16.0-py2.py3-none-any.whl | unknown | sonra | ✗ (1 h) | atl | atl | kapsayıcı | — | 0 | 0/0 | 0/0 |
| fiddle_renderer_816.js | js_bundle | önce | ✓ | ✓ (11 h) | ✓ | project_builder | 03_enhanced_renamed.js | 30 | 21/22 | 17/18 |
| fiddle_renderer_816.js | js_bundle | sonra | ✓ | ✓ (11 h) | ✓ | project_reconstructor | 03_enhanced_renamed.js | 72 | 65/65 | 43/43 |
| fiddle_main.js | js_bundle | önce | ✓ | ✗ (8 h) | ✓ (2 h) | project_builder | 01_beautified.js | 10 | 0/3 | 0/1 |
| fiddle_main.js | js_bundle | sonra | ✓ | ✗ (8 h) | ✓ (3 h) | project_builder | 01_beautified.js | 10 | 0/3 | 0/1 |

Okuma:
- **JAR ×2, APK ×2** (jadx kurulu değil): taban ve 0208a62'de reconstruct hatasız ✓, tek dosya
  (`java_project/build.gradle`), kayıtta "reconstructed: true". Sonraki ek commit (aşağıda) ile:
  `decompiler_status: arac_yok`, `decompiler_reason` "jadx bulunamadi …", `source_files_recovered: 0`, aşama
  hatası "Kaynak kod kurulmadı (…); yalnız proje iskeleti yazıldı." (worktree koşusu `k5b_sonra/`, 4/4).
- **nupkg ×2, wheel:** hat aynı (kapsayıcı, yeniden kurma yok); değişen ileti (kalem 5): üç aşama da
  kapsayıcı türü + P19 nedeni ("Analyzer bulunamadi" / "Hedef türü tanınmadı" 3/3 → 0/3).
- **yt-dlp_macos** (PyInstaller, Python 3.14) ve **yt-dlp.exe** (Python 3.11): tablo aynı (1 724 / 4 239
  dosya). Manifest: yt-dlp_macos'ta decompile zincirine giren 1 338 .pyc'nin **1 338'i çözülemedi**
  (decompiled / partial / disasm 0, pycdc var; aşama hatasız ✓, sayı yalnız manifest notunda); yt-dlp.exe'de
  1 336'nın 20'si kısmi, 1 132'si disasm, 184'ü çözülemedi (taban ve sonra aynı). Ek commit: `failed_count` +
  hiçbiri çözülemediyse aşama hatası (aşağıda).
- **extractthis.asar:** taban çöp "proje" (ikili arşivin beautify'ı, 8 dosya, 0/3 JS ayrışıyor) → sonra
  deobfuscate + reconstruct 'atlandı', 0 dosya.
- **Fiddle app.asar / main.js:** hat ve dosyalar aynı (derin adım beautify sonrası ayrıştıramıyor: P20b);
  sonra kayıtta `deobfuscation_status: failed` + uyarı (reconstruct hata satırı 2 → 3).
- **Fiddle renderer/816:** `project_builder` → `project_reconstructor`; 30 → 72 dosya; JS 21/22 → 65/65,
  proje JS 17/18 → 43/43.
- Ayrıştırılabilir modül oranı: JS hattında sonra 65/65 (816), Fiddle main / app.asar 0/3 (deobfuscation
  kusuru, değişmedi); öbür hatlarda JS yok.

## Ek — `c790e67`: decompiler yok / hiçbir .pyc çözülemedi → 'başarılı' değil
- **JVM / .NET:** static `decompiled` False ise reconstruct'a `decompiler_status` (`arac_yok` / `basarisiz`),
  `decompiler_reason`, `source_files_recovered: 0` ve "Kaynak kod kurulmadı (…); yalnız proje iskeleti
  yazıldı." (iskelet kalır, aşama kısmi). JAR ×2 + APK ×2: 0/4 → 4/4 (`k5b_sonra/`). `java_binary.py` /
  `dotnet_binary.py`'ye dokunulmadı (stages tarafında, analizcinin kendi `decompiled` bayrağından).
- **Python:** `python_binary.py` `failed_count`; zincire giren .pyc'lerin hiçbiri kurtarılamadıysa aşama
  hatası. yt-dlp_macos (3.14): "1338 .pyc'nin hiçbiri çözülemedi". yt-dlp.exe (3.11) pycdc'li ortamda 20 kısmi +
  1 132 disasm → hata satırı yok. **Ölçüm notu:** `k5c_sonra/` worktree'den koşuldu ve worktree'de `vendor/`
  bağı o an yoktu → pycdc bulunamadı, yt-dlp.exe'de de 1 336 / 1 336 çözülemedi (ortam yapıtı; doğru ortam
  `native_*`).
- Test: `tests/test_ps4_durumlar.py` +2, `tests/test_ps4_python_decompile.py` 3 (eski kodda 4/5 kırmızı, 1 bekçi);
  mutant 5/5.

## Tam takım
Worktree kökünden `PYTHONDONTWRITEBYTECODE=1 python -m pytest -q -p no:cacheprovider` (73d8530 üstünde;
makine çok yüklü, 932 sn): **10 031 geçti, 37 atlandı, 152 seçilmedi, 4 kaldı.** Dördü de bu paketin
değişikliğinden değil:
- `test_ps3b_full_write`, `test_ps3b_gnulib_varlik`, `test_ps3b_ic_ad` — `vendor/gnulib-ref/…` yok (worktree'de
  `vendor` bağı yoktu). Bağ kurulunca (gitignore'lu, commit'lenmedi) 3/3 geçti.
- `test_ps2_olu_kod::…dongu_ve_ulasilamaz_raise_icermez` — koşu sürerken `stages.py`'ye `c790e67` düzenlemesi
  yapıldı; test `inspect.getsource` ile diskteki yeni dosyayı, bellekteki eski sınıfın satırlarıyla okudu
  (yapıt). Son kodla tek başına geçti.
Son commit'ten (`c790e67`) sonra `stages` / `python_binary` / `app_bundle` / `reconstruct-project`'e değen 47
test dosyası + `test_ps1_kapsayici` + `test_p15a_cikis`: **1 038 geçti, 6 atlandı, 0 kaldı.**

## Mutasyon
`scripts/measurement/mutation_specs_ps4.json` — 28 mutant, son kodda tek koşuda **28/28 öldü** (k1 5, k2 3,
k5 7 + 5, k3 5 + 1, k4 2). Her mutantın metni özgününden farklı uzunlukta; find metni dosyada tekil.

## Yamalar
- `yamalar/P-S4__macho.py.patch` — evrensel dilim seçiminin gerekçesi (`selection_rule`) `universal_slice.json`'a
  ve `stats.universal_slice_rule`'a (kalem 4). `git apply --check` temiz.

## Özet
| kalem | durum | önce → sonra | test | mutant | commit |
|---|---|---|---|---|---|
| 6 yamalar + silme | onarıldı | P20 yaması uygulandı; `_collect_all_algorithms` silindi (çağıran-yok); ikinci tohum kalktı; ad haritası 3/3 bayt bayt aynı | 84 ilgili | — | `0a5d555` |
| 1 BICIM-02 | onarıldı | extractthis çöp proje 8 dosya → atlandı 0; Fiddle app.asar / main.js durumu kayıtta (`failed` + uyarı) | 5 (5/5 kırmızı) | 5/5 | `fd6751b` |
| 2 BICIM-13 | onarıldı | renderer/816 `project_builder` → `project_reconstructor`, modül 17/17 ayrışıyor, JS 21/22 → 65/65; mjs sentetik 3 ayrışmayan → 0 | 3 | 3/3 | `140f765` |
| 5 dürüst durumlar | onarıldı | kapsayıcıda "Analyzer bulunamadi" / "Hedef türü tanınmadı" 3/3 → 0/3; koşucu düşünce `reconstruct_status` | 6 + 2 test çevrildi | 7/7 | `90361c1` |
| 3 BICIM-09 + BORU-08 | onarıldı (uçtan uca Ghidra'lı .app koşusu yok) | Fiddle .app seçimi yerel çerçeve → Electron App; JAR "Bilinmeyen bilesen tipi" → analizci hattı | 4 + 1 | 5/5 + 1/1 | `c7e6a4e`, `73d8530` |
| 4 BICIM-10 + MEK-09 c | kısmen (stages tarafı) | evrensel Go / Bun 'desteklenmiyor' + neden; ssh/sshd/ioreg arm64e (P16a korunuyor); gerekçe yaması | 3 | 2/2 | `0208a62` |
| ek: decompiler / .pyc | onarıldı | JAR/APK `arac_yok` 0/4 → 4/4; yt-dlp_macos 1338/1338 çözülemedi artık aşama hatası | 5 | 5/5 | `c790e67` |

## Ana oturumun bilmesi gerekenler
1. **Davranış değişiklikleri:** (a) UNKNOWN hedef hiçbir koşulda JS hattına girmez (uzantısız JS de: `.js`
   uzantısıyla verilmeli, iletide yazıyor); (b) yerel `.app`'te ana bileşen artık en büyük çerçeve değil
   Contents/MacOS ikilisi; (c) JS reconstruct deobfuscation çıktısı yoksa 'atlandı' (eskiden özgün ya da
   güzelleştirilmiş dosyadan "proje"); (d) JAR / APK / .NET decompiler yokken ve hiçbir .pyc çözülemeyen
   Python paketinde çıkış kodu 0 → 3 (kısmi).
2. **Electron `.app` uçtan uca koşulmadı.** Seçim ve yönlendirme birim testli; bundle'da Electron bileşeninin
   deobfuscation girdisi üst workspace'e taşınan `raw/asar_extracted`'tan (en büyük node_modules dışı .js)
   seçilir — static'in `main_js` seçimiyle aynı olmayabilir. BICIM-09 (4) (her çerçeve / dylib Ghidra'ya,
   bütçesiz) açık.
3. **JS hattı kusurları (P20b):** Fiddle `main_window/index.js` ve `main/index.js`'te derin adım beautify sonrası
   ayrıştıramıyor (`Unexpected token, expected ","`); bu iki girdide yeniden kurulan JS'in 0/3'ü ayrışıyor.
4. **Python decompile:** yt-dlp_macos (3.14) 1 338 / 1 338 çözülemedi (pycdc var) — kök neden araştırılmadı
   (pycdc'nin 3.14 desteği / disasm yolunun sürüm uyumu).
5. `macho.py` yaması (gerekçe alanı) ana oturumun uygulamasını bekliyor; MEK-09 (c) `karadul info`'nun dilim
   göstermemesi `cli.py`'de, yapılmadı.
6. Worktree'de `scripts/node_modules` ve `vendor` symlink'i var (commit'lenmedi; `git status`'ta `??`).
7. Ölçüm kökü 1,8 GB (`fiddle_app_zip/` 282 MB, iki ağaç kopyası, koşu çalışma alanları); silme kararı ana oturumun.

## PAKET BİTTİ
