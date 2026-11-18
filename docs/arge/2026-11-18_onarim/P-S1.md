# P-S1 — `stages.py` ve tarama adımlarında dürüst durum (Dalga 2; `stages.py` serisinin 1. turu)

- **Taban:** `main` 5caa091 (P03 dahil); worktree `agent-ab1a56905599226fb`.
- **Kalemler:** (1) IMZA-15 + P03 yaması (durum alanları), (2) ARAYUZ-17 kayıt kısmı (YARA isabetleri yapılandırılmış), (3) P19 yaması (tanınan kapsayıcı → atlandı), (4) capa tüketicileri K-1 altında (bayrak, öntanımlı kapalı), (5) BORU-05 (`reconstruct` başarı bayrağı).
- **Ölçüm düzeni:** "önce" kolu bu worktree'de 5caa091 koduyla, kaynak değişmeden koşuldu (`~/karadul_olcum/runs/onarim-2026-11-18/P-S1/once/`): `debian/coreutils/true`, `debian/coreutils/echo`, `mac/htop` (`urun_kos.py --paralel 1`; `--taban-mac /Users/apple/Black_Widow/workspaces/olcum_mac/runs/ol7-c-b7faeac`, çünkü öntanımlı yol worktree'ye göre çözülüyor ve orada yok) + distlib `w32.exe` (PE; capa'nın gerçekten çalıştığı tek biçim; `python -m karadul analyze … --skip-dynamic`) + iki tanınan kapsayıcı (six wheel, humanizer nupkg). PE koşusunda BSim deposu başka bir ajandaydı ("Database already in use"), lite'a düştü; ad karşılaştırması aynı koşul altında yapıldı. "sonra" kolu aynı girdilerle.

## İlerleme

| Kalem | Durum | Commit |
|---|---|---|
| 1 — IMZA-15 + P03 yaması | bitti | cc452bc |
| 2 — ARAYUZ-17 kayıt | bitti | c248ad2 |
| 3 — P19 yaması | bitti | 8e46604 |
| 4 — capa K-1 bayrağı | bitti | 7b05980 |
| 5 — BORU-05 | bitti | 5e7e193 (+ 30d9a70 kalem 1 eki) |

## Ortak durum sözlüğü (P-S1; P03 ile aynı dizgiler)

`karadul/pipeline/steps/anti_debug.py` `SCAN_*` (paketleyici adımı ve `stages.py` buradan alır; `yara_scanner.STATUS_*` / `capa_scanner.STATUS_*` ile eşitliği testle kilitli). Ad `SCAN_` çünkü `deobfuscators/deep_pipeline.py`'de `STATUS_PARTIAL = "partial"` başka bir sözlük (tutarlılık kancası çakışmayı yakaladı).

| Değer | Anlamı |
|---|---|
| `calisti` | Tarama tamamlandı, dosyanın tamamı tarandı. 0 bulgu = "tarandı, temiz". |
| `kismi` | Tarama yapıldı ama eksik: bir katman hata verdi ya da okuma sınırı dosyadan küçük. Bulunanlar gerçek, sayı alt sınırdır. |
| `hata` | Tarama yapılamadı (dosya yok / okunamadı, dedektör kurulamadı, bütün katmanlar düştü). |
| `arac_yok` | Dedektör / tarayıcı modülü yüklenemedi (capa: araç ya da kural dizini yok). |
| `desteklenmiyor` | Girdi aracın kapsamı dışında (capa: Mach-O, x86 dışı; anti-debug bayt katmanı x86 dışı mimaride; aşama capa'yı bu hedef türünde çağırmıyor). |
| `kapali` | Ayarla kapatıldı. |

`calisti` dışındaki her durumda sayaç (`total_findings`, `total_fingerprints`, `yara_matches`) **0 değil `None`**; `anti_debug_total` / `packer_total` istatistikleri yazılmaz.

## Kalem 1 — IMZA-15 + P03 yaması: taramalarda durum

### a. Göster (önce, 5caa091)
- Gerçek çıktı (`once/`, 4 ikili): `static/anti_debug_findings.json` alanları yalnız `binary_path, total_findings, findings, summary`; `static/packer_fingerprints.json` yalnız `binary_path, total_fingerprints, fingerprints`. `pipeline_result.json` `static.stats`'ında YARA durumu yok; eşleşme yoksa (coreutils `true` / `echo`) hiçbir YARA alanı yok (genel tarama koşusunda, HEAD 14 ikili, 2'sinde `yara_backend` yok: "temiz" mi "taranmadı" mı bilinemiyor). capa durumu yok.
- Hata enjekte edilmiş deneme (gerçek dedektör, gerçek `w32.exe`; eski adım kaynağı `git show 5caa091:…`; betik ve çıktı `~/karadul_olcum/runs/onarim-2026-11-18/P-S1/hata_enjekte/anti_debug_w32.json`):

| Senaryo | Önce (JSON / stats) | Sonra |
|---|---|---|
| temiz | `total_findings: 3`, `anti_debug_status: ok` | `status: calisti`, `file_size = scanned_bytes = 91648`, 3 katman `calisti`, `total_findings: 3` |
| dizgi katmanı düşer | `total_findings: 3`, `ok` (hata yalnız uyarı günlüğünde) | `status: kismi`, neden `strings katmani: RuntimeError…`, `total_findings: null`, 3 bulgu yerinde |
| üç katman düşer | **`total_findings: 0`, `ok`** ("temiz" yalanı) | `status: hata`, üç katman nedeni, `total_findings: null` |

Kök neden: `AntiDebugDetector.detect()` her katmanı `except Exception: logger.warning` ile yutuyor; adım yalnız `detect()`'in kendisi istisna atarsa `error` yazıyordu ve o durumda da JSON'a `total_findings: 0` gidiyordu. 50 MB (anti-debug) / 16 MB (paketleyici dizgi) kırpması hiçbir çıktıda yoktu.

### b. Onarım
- `karadul/pipeline/steps/anti_debug.py`: JSON her durumda yazılır (kapalı, ikili yok dahil): `status`, `status_reason`, `file_size`, `scanned_bytes`, `layers{imports,strings,bytes}`. Katman gözlemi: `detect()` orkestrasyonu dedektörde kalır (katman sırası, çok katman artırımı, sıralama); adım yalnız bu örneğin katman yöntemlerini sarar ve hangisinin istisna attığını kaydeder (`_observe_layers`). Bayt katmanı x86 dışı mimaride `desteklenmiyor` + neden (dedektörün yerleşim önbelleği `_code_layout()` ve `_X86_ARCHES` okunur; ikisi de analizörün iç adı — bkz. riskler). Okunabilirlik taramadan önce denetlenir (`probe_readable`): dedektörler `OSError`'ı yutup boş veriyle "temiz" dönüyordu. Kırpma: `scanned_bytes = min(file_size, detector.max_bytes_scan)`; küçükse `kismi`.
- `karadul/pipeline/steps/packer_fingerprint.py`: aynı sözleşme; `scanned_bytes` (`MAX_READ_BYTES`, 200 MB) ve `string_scan_bytes` (`MAX_STRING_SCAN_BYTES`, 16 MB) dedektörün kendi sabitlerinden. Dedektörün `detect()`'i katman istisnasını yutmaz; biri düşerse `hata`.
- `karadul/stages.py`: YARA ve capa blokları `_run_yara_scan` / `_run_capa_scan` yardımcılarına taşındı (P03 yamasının içeriği, şu farklarla):
  - `yara_matches` yalnız `calisti`da sayı; `hata` / `arac_yok`da `None` (P03 yaması her durumda `len(matches)` yazıyordu → hata durumunda "0 eşleşme").
  - capa'nın çağrılmadığı hedef türünde de durum yazılır: `desteklenmiyor` + "aşama capa'yı bu hedef türünde çağırmıyor: <tür>" (P03 yaması o durumda sessizdi).
  - İçe aktarma hatası `arac_yok`, başka istisna `hata` + tür adı ve ileti.
- Eski durum değerleri (`ok` / `disabled` / `no_binary` / `module_missing` / `error`) yeni sözlüğe geçti; bunları okuyan üretim kodu yok (`grep anti_debug_status|packer_fingerprint_status`: yalnız adımlar ve `stages.py`'nin P-S2'nin sileceği ölü monoliti).

### c. Yeniden say (sonra)
Hata enjekte tablosu yukarıda (sonra sütunu). Gerçek koşu sonuçları kalem sonu ölçümünde (bkz. "Ölçüm").

### d. Test / mutasyon
- Yeni `tests/test_ps1_tarama_durumu.py` (30 test): gerçek dedektöre hata enjeksiyonu (bir katman → `kismi`, üçü → `hata`, çalışan katmanın bulgusu korunur), kırpma (`max_bytes_scan=100` → `kismi`, neden sayıları içerir), modül yok → `arac_yok`, okunamayan dosya → `hata`, kapalı → `kapali` JSON'u, x86 dışı → bayt katmanı `desteklenmiyor` (sentetik + Debian AArch64 `true`), **bulgu kümesi `detector.detect()` ile aynı** (w32.exe, /bin/ls, /usr/bin/true, Debian true); paketleyici: kırpma, hata, `arac_yok`, okunamaz, kapalı; YARA bloğu: isabet, temiz (`0`), istisna (`None`), tarayıcı hata sonucu, içe aktarma; capa bloğu: kapalı, hedef türü, istisna, gerçek Mach-O → `desteklenmiyor`; sözlüğün P03 tarayıcılarıyla eşitliği.
- `tests/test_step_anti_debug.py`, `tests/test_step_packer_fingerprint.py`: durum değerleri yeni sözlüğe; taklit dedektörler gerçeği gibi katmanları çağırıyor ve okuma sınırlarını gerçek sınıftan alıyor; kapalıyken JSON yazılması beklenir.
- Mutasyon `scripts/measurement/mutation_specs_ps1.json`: kalem 1'in 15 mutantı **15/15 öldü** (ilk koşuda `ad_okuma_denetimi_yok` yaşadı: mutant yalnız `read(1)`'i siliyordu, `open()` izin hatasını yine veriyordu; mutant `open` dahil bütün denetimi silecek biçimde düzeltildi → öldü).
- İlgili takım (11 dosya, 185 test) geçti.

## Kalem 2 — ARAYUZ-17 (kayıt kısmı): YARA isabetleri yapılandırılmış

### a. Göster (önce)
YARA isabetleri `static.stats.detected_tech`'e yalnız düz dizgi olarak gidiyordu (`"MSVC_Compiler (compiler,msvc)"`; `once/pe/w32`). Kuralın meta'sı (P03'ün `condition` alanı, önem), eşleşen dizgi ve ofsetler hiçbir çıktıda yoktu; SARIF dizgi dalı `tech_type="unknown"` atıyor, paketleyici isabetini KRDL004 yerine KRDL003'e düşürüyordu (taban 119 SARIF: bütün sonuçlar KRDL003, rapordaki sayım). `yara_matches` int; `sarif_report.py:360` liste bekliyor (ölü dal).

### b. Onarım (`karadul/stages.py` `_yara_hit_record`, `_run_yara_scan`)
`static.stats.yara_hits` — liste; her öğe:

| Alan | Tip | Anlamı |
|---|---|---|
| `rule` | str | kural adı |
| `tags` | list[str] | kuralın etiketleri (`packer`, `compiler`, `antidebug` …) |
| `meta` | dict | kuralın meta'sı (P03: `condition` = hükmün okunur koşulu, `description`, `severity` …); değerler JSON'a uygun (bytes → onaltılık) |
| `namespace` | str | YARA ad alanı |
| `strings` | list | en çok 8 eşleşme; her biri `offset` (dosya ofseti, int), `identifier` (`$s0`, `$b1` …), `length` (eşleşmenin tam boyu), `data_hex` (ilk en çok 64 bayt, onaltılık), `data_text` (o baytlar yazdırılabilir ASCII ise metin, değilse `null`) |
| `strings_total` | int | toplam eşleşme sayısı (8'den fazlaysa kayıt kırpılmıştır) |

Durum ilişkisi: `yara_status == "calisti"` → `yara_hits` liste (boş = tarandı, temiz), `yara_matches == len(yara_hits)`; başka durumda ikisi de `null`.

**Geçiş:** `detected_tech` (düz dizgi) aynı isabetlerden, aynı sırayla yazılmaya devam ediyor. Okuyanlar: `karadul/reporting/sarif_report.py:392` (P07), `scripts/measurement/masum_kapi.py` `cikti_yara`, `scripts/measurement/saglamlik_denetle.py:1468`. **P07 için:** SARIF `yara_hits`'i okumalı ve `detected_tech`'in YARA kökenli öğelerini ayrıca saymamalı (aynı isabet iki kez çıkar); `yara_matches` artık int ya da `null` (liste değil). Paketleyici ayrımı `tags`'ten (`packer`), kanıt `strings[].data_text` / `offset`'ten, hükmün gerekçesi `meta.condition`'dan. `detected_tech`, P07 ve ölçüm betikleri `yara_hits`'e geçtikten sonra kaldırılabilir (o zaman masum kapının `cikti_yara`'sı da güncellenmeli).

### c. Yeniden say
Sentetik UPX PE ve gerçek `w32.exe`: `yara_hits` öğesi kural, etiket, `meta.condition`, dizgi ofsetleri (dosya içinde) taşıyor; gerçek koşu sayıları "Ölçüm"de.

### d. Test / mutasyon
- Yeni `tests/test_ps1_yara_kayit.py` (6 test): alanlar ve kırpma (12 eşleşme → 8, 160 bayt → 64), ikili veri → `data_text` null, bytes meta → onaltılık, aşamada `yara_hits` ↔ `detected_tech` eşliği (aynı sıra), temiz → `[]`, hata → `null`, gerçek PE'de ofsetler dosya içinde.
- Mutasyon: 4 mutant (kayıt yok, dizgisiz, kırpmasız, ham meta) **4/4 öldü**.

## Kalem 4 — capa tüketicileri K-1 altında (koda besleme bayrağı, öntanımlı kapalı)

### a. Göster (önce, 5caa091 = P03 main'de, `stages.py` eski blok)
Gerçek PE koşusu (`once/pe/w32`, distlib `w32.exe`, `python -m karadul analyze --skip-dynamic`; sayım betiği ürünün kendi `rank_capabilities` + `capability_to_function_name`'iyle capa'nın üreteceği adı hesaplayıp ad haritasında aynı adreste arar):
- capa çalıştı (`api:vivisect`, 23 kural, 35 fonksiyon); `static/capa_capabilities.json` yazıldı; `reconstruct.stats.capa_names_added = 35`.
- Son ad haritası (`reconstructed/src/naming_map.json`, `global`) **15 girişin 14'ü capa'dan**: `link_function_at_runtime_on_windows`, `process_terminate`, `create_process_on_windows`, `accept_command_line_arguments`, `allocate_thread_local_storage`, `set_thread_local_storage_value`, **`parse_pe_header` (0x405180), `enumerate_pe_sections` (0x4051c0)** (P03: bunlar MSVC CRT'nin `_IsNonwritableInCurrentImage`'ı; kitaplık süzgeci yok), `write_file_on_windows`, `read_file_on_windows`, `query_environment_variable`, `link_many_functions_at_runtime` …
- `@capability` yorumu: 0 (yorum enjektörü bu koşuda adres → ad eşlemesini kuramadı; kanal yine açık).
Yani P03 main'e girdiği andan beri capa, ölçülmeden, PE'lerde ürünün adlarının çoğunu üretiyor. K-1'e aykırı ve yanlış adlar içeriyor.

### b. Onarım
- Bayrak: `binary_reconstruction.enable_capa_code_feed`, **öntanımlı kapalı**. `config.py`'de alan yok (P15'in dosyası; yama bırakılmadı, gerekmiyor): `karadul/pipeline/steps/capa_annotation.py` `CAPA_CODE_FEED_DEFAULT = False` + `capa_code_feed_enabled(config)` — alan eklenince otomatik okunur; yalnız gerçek `True` açar (YAML "true" dizgisi, 1 ya da taklit nesne açmaz).
- `stages.py` `_run_capa_scan`: tarayıcının tam sonucu **her zaman** `static/capa_scan.json`'a (rapor için; `code_feed: {enabled, flag, note}` alanıyla) yazılır; `static/capa_capabilities.json` (ad birleştiricinin `run_capa_merge`'ünün ve `capa_annotation`'ın tek girdisi) **yalnız bayrak açıkken**. Stats: `capa_code_feed` (bool). Kapı veri kaynağında: ad birleştiricinin dosyası (P13a) değişmeden capa adı üretemez.
- `capa_annotation.py`: bayrak kapalıyken veri gelse bile yorum yazmaz; `stats.capa_comments_skipped` nedeni yazar.
- İkinci kilit, yama: `yamalar/P-S1___confidence_helpers.py.patch` (`run_capa_merge` bayrağı da denetlesin; eski bir çalışma alanından ya da başka bir yazıcıdan gelen `capa_capabilities.json` ad üretmesin). Yama `tests/test_step_confidence_filter.py::TestCapaMerge::test_adds_name_when_empty_slot`'a bayrağı ekliyor (yoksa o test kırmızı). `git apply --check` temiz; uygulanmış hâliyle ilgili 61 test geçti, sonra geri alındı.
- Ölü ağırlık: `config.py:387` `capa_capability: 0.85` hiçbir yerde okunmuyor (grep); dokunulmadı.

**Bayrağın açılış koşulu (önerim; karar Berke'nin, K-1):**
1. CRT / kitaplık süzgeci: capa'nın FLIRT imzaları ya da Karadul'un kendi kitaplık eşlemesi (K-5 imza veritabanı) statik bağlı CRT fonksiyonlarını capa adlandırmasından çıkarmalı (`parse_pe_header` → `_IsNonwritableInCurrentImage` türü yanlışlar).
2. Kural kusuru süzgeci: capa isabetinin eşleşen dizgisi Karadul tarafında sözcük sınırıyla yeniden doğrulanmalı (P03'ün 12 kesin yanlışı: "Friday" ~ `/frida/i`, Ghidra `DecompileAt` ~ `/decompile/i`).
3. Ön kayıtlı ölçüm: PDB'li (GT'li) x86/x64 PE seti üzerinde capa kaynaklı adların kesinliği ve yanlış oranı ürünün öbür ad kanallarının eşiğinden kötü olmamalı; `@capability` yorumu için aynı ölçüm ayrı satırda; masum kapının capa katmanı geçmeli.
4. Açıldığında `capa_scan.json` ve `capa_capabilities.json` aynı sonucu taşır; ölçüm koşusu `code_feed.enabled` alanından okunur.

### c. Yeniden say
"Ölçüm" bölümündeki sonra koşusu (`sonra/pe/w32`): capa yine çalışıyor, sonuç `capa_scan.json`'da; ad haritasında capa adı ve `capa_names_added` beklenen 0.

### d. Test / mutasyon
- Yeni `tests/test_ps1_capa_k1.py` (12 test): bayrak öntanımlısı ve katı okuma (None / False / "true" / 1 / taklit → kapalı, yalnız `True` açık); statik blok gerçek `Workspace`'e yazar, ad birleştiricinin capa kaynağı (`run_capa_merge`) aynı çalışma alanından okur → bayrak kapalıyken **0 ad, 0 yetenek**, açıkken 2 ad; capa `calisti` olmayan durumda bayrak açık olsa da besleme yok; **gerçek capa + gerçek `w32.exe`** (taklit yok): yetenekler `capa_scan.json`'da, `capa_capabilities.json` yok, ad birleştirici 0 ad.
- `tests/test_step_capa_annotation.py`: bayrak açıkken yorum, kapalıyken (öntanımlı) yazılmıyor.
- Mutasyon: 5 mutant (kapı yok, öntanımlı açık, gevşek bayrak okuması, yorumda bayrak yok, rapor kaydı yok) **5/5 öldü**.

## Kalem 3 — P19 yaması: tanınan kapsayıcı reconstruct'ta "atlandı"

### a. Göster (önce)
Gerçek kapsayıcılar (K-8 seti; `once/kapsayici/`, `python -m karadul analyze --skip-dynamic`): six 1.16.0 wheel ve humanizer.core 2.14.1 nupkg — ikisinde de `reconstruct: success=False`, hata **"Deobfuscate edilmis dosya bulunamadi"** (2/2): kapsayıcı tanındığı hâlde (P19: `UNKNOWN` + `metadata.container`) JS hattına düşüyordu.

### b. Onarım
`yamalar/P19__stages.py.patch` gözden geçirildi ve temiz uygulandı (`ReconstructionStage.execute`, JS dalından önce): `UNKNOWN` + `metadata["container"]` → `StageResult(success=False, skipped=True)`, `stats`: `skip_reason` (kapsayıcı türü + `unsupported_reason`), `container`, `container_executables`. Ek: `container_executables_total` (liste `core/target.py`'de ilk 50 ile sınırlı; toplam ayrıca yazılmazsa analist kırpılmış listeyi tam sanabilir).

### c. Yeniden say (sonra, `sonra/kapsayici/`)
İki gerçek kapsayıcıda da `reconstruct: skipped=True`, hata yok, neden "Kapsayici tanindi (python_wheel / nuget_package) ama dogrudan analiz hatti yok: …" (2/2). Kalan (bu kalemin dışı; `stages.py`'nin başka bölgeleri / başka aşamalar): `static` aşaması aynı kapsayıcıda "Analyzer bulunamadi: No analyzer registered for TargetType.UNKNOWN" hatası, `deobfuscate` "Hedef türü tanınmadı" diyor; kapsayıcı tanındığı için ikisi de aynı "atlandı" düzenine geçmeli (P-S2 ya da P19 izleme).

### d. Test / mutasyon
- Yeni `tests/test_ps1_kapsayici.py` (4 test): sentetik wheel (gerçek `TargetDetector`) → atlandı, JS hattı çağrılmadı, hata listesi boş; gerçek six wheel + humanizer nupkg → atlandı; kapsayıcı kanıtı olmayan düz zip eski yolu izler.
- Mutasyon: 2 mutant (JS hattına düşer, "başarılı" görünür) **2/2 öldü**.

## Kalem 5 — BORU-05: `reconstruct` başarı bayrağı

### a. Göster (önce)
- Gerçek çıktıda kusur görünmez: taban 119 koşunun 119'u `reconstruct.success=True`, 119'unda `project_dir` yapıtı var, 0 hata (sayıldı); bayrak ancak bir şey bozulunca yalan söyler. Kod: `stages.py` Faz 3 sonu `_stage_result.success = len(_stage_result.artifacts) > 0` ve `finalize.py` `success = len(artifacts) > 0`; anti_debug adımı JSON'unu her koşulda yapıt olarak kaydettiği için (kalem 1'den sonra kapalıyken bile) bu fiilen hep True. `project_build` kurulum başarısızken de `project_dir` yolunu döndürüyordu (yapıt kaydetmeden); kurucu nedensiz `success=False` dönerse hiçbir hata yazılmıyordu.
- Hata enjekte (Ghidra'sız uçtan uca: `_execute_binary`'nin gerçek üç fazı, sahte koşucular, GERÇEK `project_build` + `finalize` adımları, kurucu `success=False` döndürecek biçimde taklit): eski kodda (mutant `basari_yapit_sayisi_asama` / `_finalize`) `reconstruct.success=True`; yeni kodda `False`, `reconstruct_status="basarisiz"`, `reconstruct_project_built=False`, `project_build_status="hata"`. Adlandırma sonucu yok (`naming_result=None`, C adlandırma açık) → eskiden True, şimdi False.

### b. Onarım
- `karadul/pipeline/steps/finalize.py` `reconstruct_outcome(...)` (tek ölçüt): başarı = `project_dir` yapıtı VAR **ve** C adlandırma hatasız (`naming_result.success is True`; adlandırma ayarla kapalıysa başarıyı düşürmez, `kapali` yazar). Başarılı ama `errors` boş değilse `partial`. `stats`'a: `reconstruct_status` (`tam` / `kismi` / `basarisiz`), `reconstruct_failure_reasons`, `partial` (bool), `partial_reasons` (tekil, en çok 20; tam liste `errors`'ta), `reconstruct_error_count`, `reconstruct_project_built`, `reconstruct_naming_status` (`calisti` / `hata` / `kapali`). `FinalizeStep` bunu Faz 3 görünümüyle uygular (`naming_result` Faz 2 tohumundan gelir).
- `karadul/stages.py` `_finalize_binary_outcome`: Faz 1/2 hataları ve yapıtları birleştikten sonra aynı ölçütü yeniden uygular (`len(artifacts) > 0` satırı kalktı). Başarısızsa uyarı günlüğüne nedenler.
- `karadul/pipeline/steps/project_build.py`: proje yolu yalnız kurulum başarılıysa döner ve yapıt olur; başarısızsa `None`, `project_build_status="hata"` + neden; kurucu neden bildirmediyse hata listesine "C project build basarisiz (kurucu neden bildirmedi)". Başarıda `project_build_status="calisti"`.
- Sonuç: `PipelineResult.success` (`core/result.py`: başarısız aşama yoksa True) artık yarım koşuda False olur; CLI'ın sonuç çerçevesi sarıya döner. `karadul analyze`'ın çıkış kodu başarıya bağlı değil (`cli.py`'de `result.success`'e bağlı `sys.exit` yok), ölçüm koşucusu etkilenmez. `ReportStage` yalnız `identify`'a bağlı; reconstruct başarısız olsa da rapor üretilir.

### c. Yeniden say
Hata enjekte tablosu yukarıda. Gerçek koşu: "Ölçüm" bölümü (sağlıklı 4 koşuda `reconstruct.success` True kalmalı, `reconstruct_status` ve `partial` yazılmalı).

### d. Test / mutasyon
- Yeni `tests/test_ps1_basari.py` (18 test): ölçütün saf işlevi (tam, kısmi + tekilleştirme/20 sınırı, yalnız anti_debug yapıtı → başarısız, adlandırma yok / başarısız / kapalı, bayrak okuması), `FinalizeStep` (yapıt var proje yok → False), `ProjectBuildStep` (nedensiz başarısız → `None` + hata + durum; kurucunun hatası tekrarlanmaz; istisna; başarı), `_finalize_binary_outcome` (Faz 1/2 hatası → `partial`; Faz 2 adlandırma hatası → False), **`_execute_binary` uçtan uca** (kurulum başarısız → False; adlandırma çöktü → False; sağlıklı → True).
- Eski semantiği kodlayan testler güncellendi: `tests/test_step_finalize.py` (fixture'a `project_dir` yapıtı ve `naming_result`; `partial` beklentisi), `tests/test_produce_artifact.py` (aynı), `tests/test_rapor_sayaclari.py` (üç faz koşum kalıbına `naming_result` ve `project_dir`; testlerin konusu sayaçlar, başarı yalnız koşum denetimi).
- Mutasyon: 7 mutant (aşamada eski ölçüt, finalize'da eski ölçüt, proje aranmaz, adlandırma yokluğu nedeni, kısmi yok, kapalı adlandırma hata sayılır, nedensiz kurulum hatası yazılmaz) **7/7 öldü**.
- Bu pakette değişmeyen ilgili kusur: `karadul/batch.py:223` toplu koşuda `pipeline_result.success or any(sr.success …)` — herhangi bir aşama başarılıysa ikili "başarılı" sayılıyor (BORU-05'in "toplu çalıştırma" etkisi orada sürüyor; dosya bu paketin değil).

## Kalem 1 eki (30d9a70): sonucun okunması da korumalı
Tam takımda 1 kırmızı: `test_flirt_loading_regression::test_static_stage_does_not_load_or_count_flirt`. Taklit YARA tarayıcısı alanı eksik bir sonuç döndürüyor; kalem 1'de tarama çağrısı `try` içindeydi ama alanlar dışarıda okunuyordu → `AttributeError` bütün statik aşamayı düşürdü (eski blok her şeyi yutuyordu). Onarım: `_run_yara_scan` sonucu yerel sözlükte toplar, hepsi tek `try` içinde; hata olursa yalnız `yara_status=hata` + neden, yarım sayaç yok. capa'da `to_dict()` tarama bloğuna alındı. Yeni test (eksik alanlı sonuç → `hata`, `AttributeError` nedeni, sayaç yok); yeni mutant (yalnız `ImportError` yakalanır) öldü; değişen biçim için iki mutantın arama metni güncellendi.

## Mutasyon özeti
`scripts/measurement/mutation_specs_ps1.json`: **34 mutant, 34/34 öldü** (kalem 1: 16, kalem 2: 4, kalem 3: 2, kalem 4: 5, kalem 5: 7). Koşum: `PYTHONDONTWRITEBYTECODE=1 python scripts/mutation_probe.py --spec scripts/measurement/mutation_specs_ps1.json`.

## Tam takım (30d9a70, worktree kökünden)
`PYTHONDONTWRITEBYTECODE=1 python -m pytest -q -p no:cacheprovider` → **8 875 geçti, 10 atlandı, 0 kaldı** (225 sn; günlük `~/karadul_olcum/runs/onarim-2026-11-18/P-S1/tam_takim_2.log`). Koşu sırasında `scripts/node_modules` ana ağaca sembolik bağlıydı (JS testleri için; brif §2.4), sonra kaldırıldı. İlk tam koşuda (5e7e193) 1 kırmızı vardı: yukarıdaki ek onarımla kapandı.

## Ölçüm (önce / sonra, gerçek koşular)

Kökler `~/karadul_olcum/runs/onarim-2026-11-18/P-S1/`: `once/` (5caa091, kaynak değişmeden), `sonra_v2/` (ELF / Mach-O; 30d9a70, temiz ağaç), `sonra/pe/w32` (PE; 5e7e193, temiz ağaç — 30d9a70 yalnız bozuk biçimli tarayıcı sonucu yolunu değiştirdi, gerçek tarayıcıyla davranış aynı), `sonra/kapsayici/`. `sonra/` altındaki ELF koşusu sırasında `stages.py`'de commit'lenmemiş değişiklik vardı; ölçüm `sonra_v2`'den. Karşılaştırma betikleri `scratchpad`'te; çıktı `kiyas.json`, `kiyas_sonra_v1.json`, `saglamlik_once/`, `saglamlik_sonra/`.

### Ad haritası (ad davranışı değişmemeli; capa bayrağı kapalı)

| İkili | `naming_map.json` önce ↔ sonra | global ad | yerel ad | Not |
|---|---|---|---|---|
| debian/coreutils/true | **bayt bayt aynı** (sha 67f1d6dd…) | 13 = 13 | 187 aynı | C çıktısında 3 dosya adı farklı (aşağıda) |
| mac/htop | **bayt bayt aynı** (sha 6b9b2238…) | 0 = 0 | 2 519 aynı | `src/` 792 dosya bayt bayt aynı |
| debian/coreutils/echo | farklı | 13 = 13, **aynı** | 175 aynı, 26 yalnız sonek numarası (`result_13` → `result_15`), 2 yeni (`fileno`, `strcmp` dış taslaklarında `iVar1` → `result`) | **Benim değişikliğim değil:** Ghidra'nın aynı adlı iki fonksiyona (thunk ↔ dış taslak) dosya adı dağıtımı koşudan koşuya değişiyor; aşağıda kanıt |
| pe/w32 (PE) | farklı (**bilinçli**, kalem 4) | 15 → 1: yalnız capa'nın 14 adı düştü, kalan 1 aynı | 750 aynı | `src/`'de 4 dosya: capa adının geçtiği yorum / çağıran sırası |

**echo farkının kökü (ölçüldü):** `static/ghidra_decompiled.json`'da aynı adlı fonksiyonların dosya adları. Önce: `fileno@00101758 → fileno.c`, `fileno@00121060 → fileno_00121060.c`; sonra: tersi. Bu dağıtım aynı kodla iki "sonra" koşusu (`sonra/` ↔ `sonra_v2/`) arasında da değişiyor (`lseek`, `__cxa_atexit`, `__fpending`); `true`'da da `__fprintf_chk` için önce ↔ sonra değişti (orada ad haritasını etkilemedi). Değişen tek şey Ghidra aşamasının çıktısı (Java tarafı, bu paketin dokunduğu Python adımlarından önce); `ghidra_functions.json`, `call_graph`, `xrefs`, `strings` üç koşuda bayt bayt aynı. Ayrı bir belirlenimcilik kusuru olarak bildiriyorum (aşağıda risk 9).

### Durum alanları (sonra)

| İkili | anti-debug | paketleyici | YARA | capa | reconstruct |
|---|---|---|---|---|---|
| true (ELF AArch64) | `calisti`, 68 048 / 68 048 bayt, bayt katmanı `desteklenmiyor` ("elf/arm64 …"), 0 bulgu | `calisti`, 0 | `calisti`, 0 eşleşme, `yara_hits: []` | `desteklenmiyor` ("ELF e_machine=183 …"), `capa_scan.json` | `tam`, proje var, adlandırma `calisti` |
| echo | aynı | aynı | aynı | aynı | `tam` |
| htop (Mach-O arm64) | `calisti`, 236 672 / 236 672, bayt `desteklenmiyor` ("macho/arm64"), 1 bulgu (`sysctl_import`, önceyle aynı) | `calisti`, 0 | `calisti`, 0 | `desteklenmiyor` ("Mach-O …") | `tam` |
| w32.exe (PE x86) | `calisti`, 91 648 / 91 648, üç katman `calisti`, 3 bulgu (önceyle aynı) | `calisti`, 0 | `calisti`, 1 (`MSVC_Compiler`, `yara_hits` dizgi + ofsetle) | `calisti`, `api:vivisect`, 23 kural / 35 fonksiyon, `capa_code_feed: false`, yalnız `capa_scan.json` | `tam`; `capa_names_added` yok (önce 35) |

Önce: dört ikilinin hiçbirinde JSON'da durum alanı yok; true / echo / htop'ta `static.stats`'ta hiçbir YARA / capa alanı yok (eşleşme yoktu → "taranmadı" ile ayırt edilemez). Bulgu kümeleri (anti-debug teknikleri, paketleyici, YARA kuralları) önce ↔ sonra aynı. `pipeline_result.json` boyutu: +918 … +1 254 bayt (durum alanları + `yara_hits`).

### Sağlamlık denetimi (`scripts/measurement/saglamlik_denetle.py`, 3 ELF / Mach-O)
Önce ↔ sonra aynı kusur türleri ve sayıları; tek fark `yerel_ad_uygulanmamis_fonksiyon` 28 → 30 (echo'daki iki yeni yerel ad; yukarıdaki Ghidra dosya adı kökü). Yeni kusur türü yok. `bsim_yedege_dustu` iki kolda da 2 (BSim deposu ortak; ada yazmıyor).

## Ana oturumun bilmesi gerekenler (riskler, açık uçlar)

1. **capa K-1 kapısı veri kaynağında.** `static/capa_capabilities.json` artık yalnız `enable_capa_code_feed` açıkken yazılıyor; ad birleştiricinin (`_confidence_helpers.run_capa_merge`, P13a) dosyası değişmedi. İkinci kilit için `yamalar/P-S1___confidence_helpers.py.patch` (test düzeltmesiyle birlikte) uygulanmalı. 5caa091'den bu commit'e kadar main'de PE koşuları capa adları üretiyor (w32.exe: haritanın 15 girişinin 14'ü); bu aralıkta alınmış PE ölçümleri geçersiz sayılmalı.
2. **Rapor tarafı (P07):** "taranamadı" artık JSON'da ve `static.stats`'ta var ama Markdown / HTML rapor bulgu yoksa bölümü hiç basmıyor (`markdown_report.py:469-471`, `html_report.py:388-391`); "tarandı: temiz / taranamadı: neden" satırı P07'nin işi. Okunacak alanlar: `anti_debug_findings.json` / `packer_fingerprints.json` `status`, `status_reason`, `file_size`, `scanned_bytes` (+ `layers`, `string_scan_bytes`); `static.stats` `yara_status`, `yara_status_reason`, `yara_hits` (şema kalem 2), `capa_status`, `capa_status_reason`, `capa_code_feed`; capa yetenekleri `static/capa_scan.json` (`capa_capabilities.json` DEĞİL; o yalnız bayrak açıkken). `total_findings`, `total_fingerprints`, `yara_matches` artık `null` olabilir; `ui/server.py:204` `None`'u zaten işliyor.
3. **Adım analizörün iç adlarına dayanıyor:** anti-debug adımı katman durumunu dedektör örneğinin `detect_by_*` yöntemlerini sararak, bayt katmanının kapsamını `_code_layout()` ve `_X86_ARCHES` ile okuyor (`anti_debug_detector.py`, bu paketin dosyası değil). Adlar değişirse testler (`test_ps1_tarama_durumu.py`) kırmızı olur. Temiz çözüm: `AntiDebugDetector.detect()` katman durumunu ve okunan bayt sayısını kendisi döndürsün (P02b ya da analizörün sahibi); o zaman adım sarmalamayı bırakır.
4. **Durum değerleri değişti:** `anti_debug_status` / `packer_fingerprint_status` `ok / disabled / no_binary / module_missing / error` → `calisti / kismi / hata / arac_yok / kapali`. Üretim kodunda okuyan yok; dış betik / pano varsa güncellenmeli. `anti_debug_total` / `packer_total` yalnız tam taramada yazılıyor. Kapalıyken de JSON yazılıyor (yapıt sayısı +1; BORU-05 sonrası başarıyı etkilemiyor).
5. **BORU-05 sonrası:** yarım koşuda `reconstruct.success=False` → `PipelineResult.success=False`, CLI çerçevesi sarı; çıkış kodu değişmedi. `karadul/batch.py:223` toplu koşuda hâlâ "herhangi bir aşama başarılıysa başarılı" sayıyor (başka paket). Ölü monolitteki `_run_anti_debug_and_packer` (P-S2'nin sileceği bölge) eski şemayı yazıyor; etkin yolda çağrılmıyor.
6. **Kapsayıcı (kalem 3):** reconstruct "atlandı" diyor, ama aynı koşuda `static` "Analyzer bulunamadi" hatası, `deobfuscate` "Hedef türü tanınmadı" diyor (yanıltıcı; kapsayıcı tanındı). İzleme kalemi.
7. **Ölçüm koşulları:** BSim deposu ortak ve başka ajanlar kullanıyordu: iki kolda da 3 ELF / Mach-O koşusunun 2'sinde, önce kolunun PE koşusunda "Database already in use" → lite. BSim gölge kipte, ada yazmıyor; ad karşılaştırması etkilenmez ama süreler karşılaştırılamaz.
8. **Belirlenimcilik kusuru (yeni bulgu, bu paketin dışı):** Ghidra decompile aşaması aynı adlı fonksiyonlara (PLT thunk ↔ dış taslak: `fileno`, `strcmp`, `lseek`, `__cxa_atexit`, `__fpending`, `__fprintf_chk`) dosya adını koşudan koşuya farklı dağıtıyor (`fileno.c` ↔ `fileno_00121060.c`). Sonuç: echo'da yerel ad sonekleri kayıyor ve iki taslağa yerel ad verilip verilmemesi değişiyor (ad haritası bayt bayt aynı değil; global adlar aynı). Aynı kodla iki koşu arasında da görüldü. Kök büyük olasılıkla Ghidra betiğindeki ad çakışması çözümünün yineleme sırası; `urun_olc` karşılaştırmalarında yerel ad farkının bir kısmı bu gürültü olabilir.
9. **Eşik önerisi (masum kapı):** bu paket kapı eşiğini değiştirecek bir iddia katmanına dokunmadı; `cikti_yara` hâlâ `detected_tech`'i okuyor (aynı içerik). Kapı `yara_hits`'e geçirilirse `detected_tech` kaldırılabilir. capa çıktı kipi için kapı `capa_scan.json`'u okumalı (bugün çıktı kipinde capa katmanı yok).

## PAKET BİTTİ
