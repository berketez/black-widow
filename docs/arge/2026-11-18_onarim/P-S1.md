# P-S1 — `stages.py` ve tarama adımlarında dürüst durum (Dalga 2; `stages.py` serisinin 1. turu)

- **Taban:** `main` 5caa091 (P03 dahil); worktree `agent-ab1a56905599226fb`.
- **Kalemler:** (1) IMZA-15 + P03 yaması (durum alanları), (2) ARAYUZ-17 kayıt kısmı (YARA isabetleri yapılandırılmış), (3) P19 yaması (tanınan kapsayıcı → atlandı), (4) capa tüketicileri K-1 altında (bayrak, öntanımlı kapalı), (5) BORU-05 (`reconstruct` başarı bayrağı).
- **Ölçüm düzeni:** "önce" kolu bu worktree'de 5caa091 koduyla, kaynak değişmeden koşuldu (`~/karadul_olcum/runs/onarim-2026-11-18/P-S1/once/`): `debian/coreutils/true`, `debian/coreutils/echo`, `mac/htop` (`urun_kos.py --paralel 1`; `--taban-mac /Users/apple/Black_Widow/workspaces/olcum_mac/runs/ol7-c-b7faeac`, çünkü öntanımlı yol worktree'ye göre çözülüyor ve orada yok) + distlib `w32.exe` (PE; capa'nın gerçekten çalıştığı tek biçim; `python -m karadul analyze … --skip-dynamic`) + iki tanınan kapsayıcı (six wheel, humanizer nupkg). PE koşusunda BSim deposu başka bir ajandaydı ("Database already in use"), lite'a düştü; ad karşılaştırması aynı koşul altında yapıldı. "sonra" kolu aynı girdilerle.

## İlerleme

| Kalem | Durum | Commit |
|---|---|---|
| 1 — IMZA-15 + P03 yaması | bitti | cc452bc |
| 2 — ARAYUZ-17 kayıt | bitti | (bu commit) |
| 3 — P19 yaması | bekliyor | |
| 4 — capa K-1 bayrağı | bekliyor | |
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
