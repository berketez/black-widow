# P-S1 — `stages.py` ve tarama adımlarında dürüst durum (Dalga 2; `stages.py` serisinin 1. turu)

- **Taban:** `main` 5caa091 (P03 dahil); worktree `agent-ab1a56905599226fb`.
- **Kalemler:** (1) IMZA-15 + P03 yaması (durum alanları), (2) ARAYUZ-17 kayıt kısmı (YARA isabetleri yapılandırılmış), (3) P19 yaması (tanınan kapsayıcı → atlandı), (4) capa tüketicileri K-1 altında (bayrak, öntanımlı kapalı), (5) BORU-05 (`reconstruct` başarı bayrağı).
- **Ölçüm düzeni:** "önce" kolu bu worktree'de 5caa091 koduyla, kaynak değişmeden koşuldu (`~/karadul_olcum/runs/onarim-2026-11-18/P-S1/once/`): `debian/coreutils/true`, `debian/coreutils/echo`, `mac/htop` (`urun_kos.py --paralel 1`; `--taban-mac /Users/apple/Black_Widow/workspaces/olcum_mac/runs/ol7-c-b7faeac`, çünkü öntanımlı yol worktree'ye göre çözülüyor ve orada yok) + distlib `w32.exe` (PE; capa'nın gerçekten çalıştığı tek biçim; `python -m karadul analyze … --skip-dynamic`) + iki tanınan kapsayıcı (six wheel, humanizer nupkg). PE koşusunda BSim deposu başka bir ajandaydı ("Database already in use"), lite'a düştü; ad karşılaştırması aynı koşul altında yapıldı. "sonra" kolu aynı girdilerle.

## İlerleme

| Kalem | Durum | Commit |
|---|---|---|
| 1 — IMZA-15 + P03 yaması | bitti | cc452bc |
| 2 — ARAYUZ-17 kayıt | bitti | c248ad2 |
| 3 — P19 yaması | bekliyor | |
| 4 — capa K-1 bayrağı | bitti | (bu commit) |
| 5 — BORU-05 | bekliyor | |

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
- Gerçek çıktı (`once/`, 4 ikili): `static/anti_debug_findings.json` alanları yalnız `binary_path, total_findings, findings, summary`; `static/packer_fingerprints.json` yalnız `binary_path, total_fingerprints, fingerprints`. `pipeline_result.json` `static.stats`'ında YARA durumu yok; eşleşme yoksa (coreutils `true` / `echo`) hiçbir YARA alanı yok (taban 1.22.1'de de 119'un 2'si: `yara_backend` yok). capa durumu yok.
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
