# Kulvar IMZA — bulgular
Kapsam: Okunan (hedefli, giriş noktası + riskli bölgeler): `binary_intelligence.py` (sınıf + desen tabloları), `anti_debug_detector.py`, `packer_fingerprint.py`, `yara_scanner.py` (kural tablosu, üretici, tarama yolları), `capa_scanner.py` (`is_available`, API yolu), `signature_db.py` (`__init__`, LMDB başlatma, yerleşik birleştirme, dış yükleme, `_match_by_symbol`, platform süzgeci), `sigdb_builtin/*` (AST + birleştirme betiği), `rust_demangler.py` / `go_demangler.py` (deneme), adımlar `anti_debug.py`, `packer_fingerprint.py`, `byte_pattern.py` (toplama), `ghidra_metadata.py` (imza adımı), `type_recovery_consumer.py`, `_feedback_naming_candidates.py`, `_feedback_naming_merger.py` (çağrı sözleşmesi); `stages.py:307-379` (YARA/capa), rapor tüketicileri (`html_report.py`, `markdown_report.py`, `sarif_report.py`, `hacker_cli.py`). Denemeler: masum sistem ikilileri (`/bin/ls`, `/usr/bin/true`, `vim`, `dyld`, `ssh`, depo dışı masum PE'ler: pip distlib başlatıcıları, makensis araçları, pnpm fastlist) ve gerçek 1.22.1 çıktısı `~/karadul_olcum/runs/urun-yeni2-f30ac9a/` (119 ikili). Okunamayanlar: "Bakamadıklarım" bölümünde.
Özet: 16 bulgu (KRİTİK 4, YÜKSEK 6, ORTA 5, DÜŞÜK 1). Bu kulvarın "bu ikili şunu yapıyor" iddiaları masum ikililerde sistematik olarak yanlış pozitif üretiyor:
(1) `binary_intelligence` her ikiliye Bluetooth/Encryption/OpenGL/SHA-256 ve redis'e kernel düzeyli "SIP"/"Kernel Extension" yazıyor (IMZA-01; 119/119); (2) yerleşik YARA kuralları coreutils `ls`'i MPRESS, `tree`'yi ASPack ile paketli, redis'i Delphi ile derlenmiş sayıyor ve bunlar SARIF'e `warning` olarak gidiyor (IMZA-05); anti-debug dedektörü x86 işlem kodlarını AArch64 ikililerde arayıp coreutils `pwd`'ye "Anti-Debug [MED]" veriyor, pip'in başlatıcısına "[HIGH]" (IMZA-02/03); paketleyici dedektörü tek `0xBB` baytıyla masum PE'lerin 10/11'ine FSG diyor (IMZA-04).
(3) LMDB imza veritabanı glibc fonksiyonlarını `opencv_python_headless`/`cffi`/`psycopg2_binary` kitaplığına 0,98 güvenle bağlıyor (IMZA-07; Debian'da 2 955 eşleşme); protobuf kısmi eşleşmesi `Init`/`Get`/`Next` gibi genel adları Google protobuf'a bağlıyor (IMZA-09).
(4) capa hiç çalışmıyor (`backend="auto"` capa 9.4'te geçersiz; IMZA-06); PDB/BN/TRex/DWARF/Rust/Go ad kanalları etkin akışa bağlı değil (IMZA-13); "taranamadı" ile "temiz" hiçbir çıktıda ayrılmıyor (IMZA-11, IMZA-15).

## IMZA-01 — `binary_intelligence` her ikiliye "Bluetooth", "Encryption", "OpenGL", "SHA-256" yapıştırıyor: büyük harfli kısa belirteçler sınırsız ve büyük/küçük harf duyarsız alt dizgi olarak aranıyor
- Önem: KRİTİK
- Tür: sahte/yanlış gösterim
- Yer: `karadul/analyzers/binary_intelligence.py:1554` (alt sistem desenleri `re.IGNORECASE`), `:1797` (algoritma desenleri her zaman `re.IGNORECASE`), `:1827`, `:1856`; desenler `:269` (`r"der"`), `:287` (`r"sign"`), `:710` (`r"DOM"`), `:752` (`r"BLE"`, `r"HID"`), `:831` (`r"copy"`), `:1088` (OpenGL `\bgl[A-Z]\w+`), `:1192` (SIP), `:1227` (ASLR `pie`), `:1261` (NTP), `:1263` (IPsec `IKE`)
- Etkin mi: evet (çağıran: `karadul/analyzers/macho.py:362-397`, ELF/Mach-O/PE/Bun için her koşuda; çıktı `static/intelligence_report.json` → `karadul/reporting/html_report.py:181,648` "Architecture Analysis / Algorithms & Cryptography / Security Mechanisms")
- Ne: Desenler büyük harfli kısaltma olarak yazılmış (`BLE`, `HID`, `DOM`, `IKE`, `NTP`, `SIP`, `der`, `pie`, `quic`) ama hepsi `re.IGNORECASE` ile ve sözcük sınırı olmadan derleniyor. Sonuç: `_ITM_deregisterTMCloneTable` → Bluetooth (BLE) + Encryption (der); `stderr` → Encryption; `bindtextdomain` → Browser Engine (DOM); `GLIBC_2.17` / `Global options:` → OpenGL (`\bgl[A-Z]` harf duyarsız olunca `GLI…` tutuyor); `like` → IPsec (IKE); `copied`, `pieces` → ASLR (pie); `Gossip`, `siphash` → "SIP (System Integrity)" (risk düzeyi **kernel**); `maskModuleConfigFlags` → "Kernel Extension" (kmod, risk **kernel**); `quicklist` → HTTP/3 (QUIC). `AES` ve `RSA` girdilerindeki `"case_sensitive": True` alanı yalnız fonksiyon başına yoldaki (`:1436`) ön derlemede okunuyor; üst düzey `_detect_algorithms` (`:1797`) bu alanı yok sayıp her deseni harf duyarsız derliyor. Ayrıca `SHA-256` / `SHA-512`, coreutils yardım metnindeki `sha256sum` sözcüğünden her coreutils ikilisine "kripto algoritması" olarak düşüyor.
- Kanıt: Gerçek 1.22.1 çıktısı (`~/karadul_olcum/runs/urun-yeni2-f30ac9a/`, 119 `intelligence_report.json`) üzerinde sayım:
  ```
  ALG OpenGL 119/119, SHA-256 107, SHA-512 105 ; SUB Bluetooth 119/119, Encryption 119/119, Licensing 109, Browser Engine 31
  PRO HTTPS 112, IPsec 46, NTP 9, HTTP/3 4 ; SEC ASLR 15, "SIP (System Integrity)" 5, Anti-Tampering 5, TCC 4, "Kernel Extension" 3
  debian/coreutils/true: ALG OpenGL ['GLIBC_2.17','GLIBC_2.34'], ALG SHA-256 ['sha256sum'], SUB Bluetooth ['_ITM_deregisterTMCloneTable', ...]
  redis-cli: SEC SIP ['siptlw','siphash'] ; redis-check-rdb: SEC Kernel Extension ['maskModuleConfigFlags', ...], PRO HTTP/3 ['__quicklistCompress']
  coreutils/split: SEC ASLR ['Output pieces of FILE ...'] ; tree: PRO IPsec ['Follow symbolic links like directories.']
  ```
  Yerel deneme (`/usr/bin/vim`, macOS): `SEC ASLR ['# Bar lines, copied verbatim:']`, `PRO HTTP/3 ['[Quickfix List]']`, `PRO NTP ['CurrentPC']`, `PRO IPsec ['strikethrough', 'Vi mode (like "vi")']`.
- Etki: Zararlı yazılım analisti HTML raporunda masum `true` ikilisi için "Bluetooth", "Encryption", "OpenGL", "SHA-256" görüyor; redis için **kernel** risk düzeyli "SIP" ve "Kernel Extension" güvenlik mekanizmaları listeleniyor. Bunlar "bu ikili şunu yapıyor" iddiası; her ikilide görünen etiket, gerçek sinyali (gerçekten kripto kullanan ikili) gürültüye gömüyor.
- Güven: kesin (gerçek çıktıda saydım; desen ↔ dizgi eşleşmesini Python'da tek tek gösterdim)
- Onarım kapsamı: `binary_intelligence.py`; kısaltma desenlerine `\b`/`_` sınırı ve harf duyarlılığı (desen başına `case_sensitive` alanını iki yolda da okumak), yardım metni / sürüm dizgisi (`GLIBC_`, `sha256sum`) gibi bilinen gürültünün dışlanması; tek kanıtla hüküm verilmemesi (en az iki bağımsız kanıt). M. Tehlike: desen sıkılaştırınca doğru tespitler de düşebilir; openssl/redis/vim gibi gerçek pozitiflerle birlikte sınanmalı.
- Nasıl sınanır: 119 ikilinin `strings`+simge girdisiyle yeniden koşu: coreutils `true`/`basenc` için Bluetooth/Encryption/OpenGL/SHA-256 boş; openssl için AES/RSA/ECDH korunur; `case_sensitive` alanı olan desenle küçük harfli girdinin eşleşmediğini gösteren birim testi.

## IMZA-02 — Anti-debug dedektörü x86 işlem kodlarını (RDTSC `0F 31`, RDTSCP, INT3) mimariye bakmadan bütün dosyada arıyor: AArch64 coreutils ikilileri "Anti-Debug [MED]" alıyor
- Önem: KRİTİK
- Tür: sahte/yanlış gösterim
- Yer: `karadul/analyzers/anti_debug_detector.py:295-297` (desenler), `:616-690` (`detect_by_bytes`), `:271-292` (`_BYTE_PATTERNS`, PEB), `:195-226` (tek içe aktarım → hüküm: `prctl`, `sysctl`)
- Etkin mi: evet (adım `karadul/pipeline/steps/anti_debug.py`; çıktı `static/anti_debug_findings.json` → `karadul/reporting/markdown_report.py:105,445` "Anti-Debug Findings", `karadul/reporting/sarif_report.py:97` KRDL003)
- Ne: `detect_by_bytes` dosyanın tamamını (başlıklar, `.rodata`, simge tabloları dahil) ham bayt olarak tarıyor; iki baytlık `0F 31` dizisini "rdtsc" sayıyor. Mimari (ELF `e_machine`, Mach-O `cputype`) ve bölüm (yalnız yürütülebilir kod) denetimi yok; dosyada `aarch64`/`arm`/`machine` geçmiyor. İki baytlık rastgele dizi her ~64 KB'de bir beklenir, yani her orta boy ikilide "RDTSC" çıkar; 5 tanesi güveni 0,45'e çıkarır. Aynı şekilde PEB desenleri (`64 A1 30 00 00 00`) ELF/Mach-O'da da aranıyor ve bulunursa `platform="windows"` diye raporlanıyor. İçe aktarım katmanında tek bir `sysctl` içe aktarımı (htop, top, vim gibi süreç listeleyen her araç) 0,55 güvenle "P_TRACED kontrolü" hükmüne dönüşüyor; `prctl` içe aktarımı (coreutils `timeout`) "PR_SET_DUMPABLE" diye adlandırılıyor, oysa argümana bakılmıyor.
- Kanıt: Gerçek çıktı (`urun-yeni2-f30ac9a`, 119 ikili): `RDTSC_Timing` 14 ikilide (0,45 ×7, 0,30 ×5, 0,20 ×2), hepsi Debian coreutils/redis gibi masum ikililer. `debian/coreutils/pwd` → `file` çıktısı "ELF 64-bit LSB pie executable, ARM aarch64"; aynı ikilinin `report.md` satırı 36-43:
  ```
  ## Anti-Debug Findings [MED]
  - **Severity:** medium (score: 0.45)
  | RDTSC_Timing | timing | 0.45 | rdtsc x0, rdtscp x5 |
  ```
  Yerel deneme (macOS, `AntiDebugDetector(binary_path=...).detect()`): `/usr/lib/dyld` → `RDTSC_Timing 0.45 'rdtsc x8, rdtscp x12'`; `/usr/bin/ssh` → `RDTSC_Timing 0.45`; `/usr/bin/top`, `/usr/sbin/sysctl`, `/usr/bin/vim` → `sysctl_kinfo_proc 0.55 'import: _sysctl'`. Gerçek çıktıda `mac/htop` → `sysctl_kinfo_proc 0.55`.
- Etki: Analist masum bir AArch64 ikilisinde "orta düzey anti-debug" görür; zararlı yazılım triyajında bu, ikiliyi şüpheli sınıfa iter. Gerçekten RDTSC kullanan x86 zararlısını masumdan ayıran bilgi (kod bölümünde mi, hangi fonksiyonda) çıktıda yok.
- Güven: kesin (gerçek çıktı + yerel deneme)
- Onarım kapsamı: `anti_debug_detector.py`; işlem kodu taramasını yalnız x86/x86-64 hedefte ve yalnız yürütülebilir bölümlerde (ya da Ghidra'nın komut akışında) yapmak; PEB desenlerini yalnız PE için; `sysctl` / `prctl` için argüman kanıtı (KERN_PROC + P_TRACED / PR_SET_DUMPABLE sabiti) yoksa güveni bilgi düzeyine indirmek. M.
- Nasıl sınanır: Debian AArch64 coreutils `pwd`/`printf` ve macOS `/usr/lib/dyld` için `RDTSC_Timing` çıkmamalı; x86-64 bir ikilide `.text` içindeki gerçek `rdtsc` bulunmalı, `.rodata`'daki rastgele `0F 31` bulunmamalı.

## IMZA-03 — PE'de MSVC çalışma zamanının olağan içe aktarımları ve 0xCC dolgusu anti-debug sayılıyor; puan "teknik sayısı × 0,05" ile şişiyor: pip'in başlatıcısı `w32.exe` "[HIGH]" alıyor
- Önem: YÜKSEK
- Tür: sahte/yanlış gösterim
- Yer: `karadul/analyzers/anti_debug_detector.py:420-470` (`summary`: `score = max_conf + 0.05 * (teknik sayısı - 1)`), `:669-689` (8+ ardışık `0xCC` → `INT3_Cluster`), `_WINDOWS_APIS` sözlüğü (`IsDebuggerPresent` 0,55; `QueryPerformanceCounter` 0,25; `GetTickCount` 0,20)
- Etkin mi: evet (adım `pipeline/steps/anti_debug.py`; `markdown_report.py:434-442` eşikleri: ≥0,7 `[HIGH]`, ≥0,4 `[MED]`)
- Ne: MSVC ile derlenen hemen her PE, CRT'nin `__security_init_cookie` / `__report_gsfailure` yolları yüzünden `IsDebuggerPresent`, `QueryPerformanceCounter`, `GetTickCount` içe aktarır; MSVC fonksiyon aralarını `0xCC` ile doldurur. Dedektör bunların her birini ayrı "teknik" sayıyor, sonra özet puanına teknik başına +0,05 ekliyor. Böylece hiçbir anti-debug davranışı olmayan sıradan bir Windows aracı "high" eşiğine ulaşıyor. Kanıtların hiçbiri çağrı yerine (ör. `IsDebuggerPresent` sonucunun dallanmada kullanılması) bakmıyor.
- Kanıt: Yerel deneme, depo dışı masum PE'ler:
  ```
  pip/_vendor/distlib/w32.exe          anti_debug_score 0.7  ['GetTickCount','INT3_Cluster','IsDebuggerPresent','QueryPerformanceCounter']
  pnpm/vendor/fastlist-0.3.0-x64.exe   anti_debug_score 0.85 [... 7 teknik ...]
  makensis/Bin/GenPat.exe, MakeLangId.exe, zip2exe.exe, makensisw.exe → INT3_Cluster 0.25 (hepsi)
  ```
  `w32.exe` için markdown raporu `## Anti-Debug Findings [HIGH]` başlığını basar (eşik `score >= 0.7`).
- Etki: Zararlı yazılım analistinin en sık baktığı biçimde (PE) "anti-debug: HIGH" etiketi ayırt edici değil; masum ve zararlı aynı puanı alıyor. Sayaç yalan değil ama hüküm yanıltıcı.
- Güven: kesin (yerel deneme; eşik koddan)
- Onarım kapsamı: `anti_debug_detector.py`; CRT kaynaklı bilinen içe aktarım kümesini (IsDebuggerPresent + QPC + GetTickCount + GetCurrentProcessId birlikte) "derleyici çalışma zamanı" diye ayırıp puandan düşmek; INT3 dolgusunu yalnız fonksiyon içinde (Ghidra fonksiyon sınırı) saymak; puan formülünde zayıf (≤0,3) kanıtları toplamamak. S–M.
- Nasıl sınanır: distlib `w32.exe`/`t64.exe` ve makensis araçları için puan < 0,4; içinde `IsDebuggerPresent` çağrısından sonra `ExitProcess`'e dallanan küçük bir deneme PE'si için ≥ 0,4.

## IMZA-04 — Paketleyici dedektörü tek bir `0xBB` baytını "FSG" giriş imzası sayıyor: masum PE'lerin 10/11'inde FSG çıkıyor (ARM64 PE dahil)
- Önem: YÜKSEK
- Tür: sahte/yanlış gösterim
- Yer: `karadul/analyzers/packer_fingerprint.py:281` (`_EntryRule(b"\xbb", 0x2000, "FSG", ...)`), `:277` (`b"\x60\xbe"` → UPX, iki bayt), `:283` (`b"\x66\x9c\x60"` → Petite), `:661-697` (`detect_by_entry_pattern`: giriş noktası hiç hesaplanmıyor, dosyanın ilk N baytında herhangi bir yer)
- Etkin mi: evet (adım `pipeline/steps/packer_fingerprint.py`, bayrak `enable_packer_fingerprint` öntanımlı `True`; çıktı `static/packer_fingerprints.json` → `sarif_report.py:483` KRDL004, markdown "Detected Packer")
- Ne: "Giriş noktası" katmanı PE'nin `AddressOfEntryPoint` alanını okumuyor; desen dosyanın ilk 0x2000/0x4000 baytında (DOS başlığı, PE başlığı, bölüm tablosu, kodun başı) herhangi bir yerde aranıyor. FSG kuralı tek baytlık `0xBB` (x86 `mov ebx, imm32`), x86 kodda ve rastgele veride son derece sık. Mimari denetimi de yok: ARM64 PE (`t64-arm.exe`) de FSG alıyor. Güven 0,30 olduğu için SARIF'te `note` düzeyinde kalıyor ama `packer_top_name` istatistiği ve rapordaki "Detected Packer" bölümü FSG'yi gösteriyor; aynı paketleyici başka katmanda zayıf bir dizgiyle (`FSG!`, 0,65) eşleşirse çok katman artırımıyla güven yükseliyor.
- Kanıt: Yerel deneme (`PackerFingerprintDetector(f).detect()`):
  ```
  fastlist-0.3.0-x86.exe [('FSG', 0.3, ['entry pattern @0x80: bb'])]
  distlib/w32.exe [('FSG', 0.3, ['entry pattern @0xd8e: bb'])]   ; t32/w64/t64 aynı
  distlib/t64-arm.exe [('FSG', 0.3, ['entry pattern @0x121a: bb'])]
  makensis GenPat.exe, zip2exe.exe, makensisw.exe → FSG 0.3 ; MakeLangId.exe → []
  ```
- Etki: Analist paketlenmemiş her PE için "FSG ile paketli olabilir" görüyor; gerçek bir paketleyici tespiti bu gürültüden ayırt edilemiyor. Paketleyici hükmü sonraki adımları da etkileyebilir (adım belgesi "downstream component'ler bunu metadata olarak kullanabilir" diyor).
- Güven: kesin (yerel deneme)
- Onarım kapsamı: `packer_fingerprint.py`; PE başlığından giriş RVA → dosya ofsetini hesaplayıp deseni yalnız orada (ilk ~64 bayt) aramak; 1–2 baytlık desenleri silmek ya da en az 6 baytlık maskeli desene çevirmek; makine türü x86 değilse x86 desenlerini atlamak. S.
- Nasıl sınanır: distlib/makensis/pnpm PE'lerinde boş liste; UPX ile paketlenmiş bir PE'de UPX ≥ 0,9 korunur.

## IMZA-05 — Yerleşik YARA kuralları `nocase` + `any of them` ile tek alt dizgiye hüküm veriyor: coreutils `ls` "MPRESS ile paketli", redis "Delphi ile derlenmiş", `tree` "ASPack ile paketli" çıkıyor
- Önem: KRİTİK
- Tür: sahte/yanlış gösterim
- Yer: `karadul/analyzers/yara_scanner.py:254-266` (ASPack: `\.adata` ya da 6 baytlık `60 E8 00 00 00 00`), `:278-287` (MPRESS: `MPRESS` dizgisi), `:390-399` (Delphi: `TObject`), `:444-453` (AntiDebug_Timing: `clock_gettime`), `:457-466` (AntiDebug_SysctlCheck: `sysctl\b`, severity high), `:565-576` (Stack_String_Construction: iki baytlık `C6 45`), `:203-209` (RSA OID); üretici `:710-780` (her dizgi `/.../ nocase`, koşul `any of them`); çağıran `karadul/stages.py:307-330`
- Etkin mi: evet (statik aşama her ikili hedefte koşuyor; gerçek çıktıda 119 ikilinin 31'inde `static.stats.detected_tech` dolu; `karadul/reporting/sarif_report.py:391-418` bunları KRDL003 `warning` olarak yazıyor)
- Ne: Kural üretici her dizgiyi harf duyarsız düzenli ifadeye çeviriyor ve kural koşulu "herhangi biri". Böylece `MPRESS` → `compress`/`uncompress` içinde; `TObject` → `tObject` (redis'in `createStringObject` türü adları) içinde; `sysctl\b` → redis'in "sysctl vm.overcommit_memory" uyarı metninde; `clock_gettime` → her Linux ikilisinde eşleşiyor. Bayt desenleri dosyanın tamamında (bölüm/mimari ayrımı olmadan) aranıyor: iki baytlık `C6 45` her ikilide, `60 E8 00 00 00 00` AArch64 `tree`'de bulunuyor. Format kısıtı (`formats`) yalnız MSVC kuralında var; paketleyici kurallarında yok. macOS'ta Apple kod imzası sertifikasındaki rsaEncryption OID'i her imzalı ikiliye "RSA_Public_Key_Constants" verdiriyor. Ayrıca `stages.py:314-315` yalnız eşleşme varsa istatistik yazıyor: "tarandı, temiz" ile "taranmadı/kural derlenemedi" ayırt edilemiyor (`yara_result.errors` hiçbir yere yazılmıyor).
- Kanıt: Gerçek çıktı sayımı (119 ikili, `pipeline_result.json` → `stages.static.stats.detected_tech`): `MPRESS_Packed` 13 (coreutils `sort`, `dircolors`, `dir`, `ls`, `vdir`, redis-check-rdb/aof, htop…), `ASPack_Packed` 1 (`tree`), `Delphi_Compiler` 2 (redis), `AntiDebug_Timing` 23, `Stack_String_Construction` 19, `AntiDebug_SysctlCheck` 4. Yerel deneme (`YaraScanner().scan_file`, yara-python 4.5.4):
  ```
  debian ls        [('MPRESS_Packed',[b'mpress']), ('AntiDebug_Timing',[b'clock_gettime']), ('Stack_String_Construction',[b'\xc6E'])]
  redis-check-rdb  [..., ('Delphi_Compiler',[b'tObject',...]), ('AntiDebug_SysctlCheck',[b'sysctl',...]), ...]
  debian tree      [('ASPack_Packed',[b'`\xe8\x00\x00\x00\x00', ...]), ...]
  macOS /usr/bin/true [('RSA_Public_Key_Constants',[b'\x06\t*\x86H\x86\xf7\r\x01\x01\x01', ...])]
  ```
  Debian `ls` SARIF'i: `KRDL003 warning Teknoloji tespit edildi: MPRESS_Packed (packer,mpress) (unknown)`.
- Etki: SARIF'i bir SIEM/triyaj aracına besleyen analist masum coreutils için "paketli" ve "anti-debug" uyarıları alıyor. Paketleyici ve derleyici hükmü (Delphi ↔ C) analizin yönünü değiştirir.
- Güven: kesin (gerçek çıktı + yerel deneme)
- Onarım kapsamı: `yara_scanner.py` kural tablosu (paketleyici kurallarını bölüm adı + format kısıtına bağlamak, `nocase`'i yalnız gerçekten gereken dizgilerde, kısaltmalara sözcük sınırı, 2 baytlık desenleri kaldırmak, `clock_gettime`/`sysctl` gibi olağan API'leri anti-debug kuralından çıkarmak); `stages.py:307-330` tarama durumunu (backend, kural sayısı, hata) her koşulda yazmak. M.
- Nasıl sınanır: Debian coreutils `ls`/`sort`, redis, `tree` ve macOS `/bin/ls` için paketleyici/derleyici/anti-debug eşleşmesi yok; UPX/MPRESS ile paketlenmiş birer deneme ikilisinde ilgili kural korunur; yara-python yokken ve kural derlenemezken istatistikte durum görünür.

## IMZA-06 — capa hiç çalışmıyor: Python API yolu `backend="auto"` ile capa 9.4'te her girdide `ValueError` veriyor, CLI yolu güvenli dizin listesi yüzünden bulunmuyor; durum yalnız `debug` günlüğüne düşüyor
- Önem: YÜKSEK
- Tür: hiç çalışmayan özellik / sessiz hata
- Yer: `karadul/analyzers/capa_scanner.py:651-657` (`capa.loader.get_extractor(..., backend="auto", ...)`), `:295-340` (`is_available`: CLI `resolve_tool("capa")`), `karadul/core/safe_subprocess.py:52-60` (beyaz liste), `karadul/stages.py:333-379` (başarısızlık yalnız `logger.debug`)
- Etkin mi: evet (`enable_capa` öntanımlı `True`, `config.py:541`; kural dizini `~/.cache/karadul/capa-rules` makinede var; ölçüm Python'unda (`/opt/anaconda3`) capa 9.4.0 kurulu)
- Ne: capa 9.4'ün `capa/loader.py` dosyasında geçerli arka uçlar `vivisect`, `dotnet`, `binja`, `pefile`, … (`:60-69`); `"auto"` yok ve `:486` `raise ValueError("unexpected backend: " + backend)`. Karadul'un API yolu her zaman `"auto"` geçiyor; hata "format desteklenmiyor olabilir" diye yorumlanıp `success=False` dönüyor. CLI yolu ise conda/pip ile kurulan `capa` ikilisini (`/opt/anaconda3/bin/capa`) beyaz listede olmadığı için hiç görmüyor. `stages.py` başarısızlığı `logger.debug` ile yazıyor, istatistiğe "capa denendi / başarısız / kurulu değil" bilgisi koymuyor. Sonuç: capa ne PE'de ne ELF'te sonuç üretiyor; `capa_capabilities.json` hiç yazılmıyor; ona bağlı `_capa_comment_inject.py`, `_confidence_helpers.py:244-` (capa'dan ad önerisi) ve `capa_annotation` adımı her koşuda boş geçiyor. Testler `_scan_via_api`'yi taklit (monkeypatch) ettiği için (`tests/test_capa_funcname_mapping.py:220,242`) bu kırık yakalanmıyor.
- Kanıt: Yerel deneme (ölçüm Python'u):
  ```
  capa 9.4.0 ; avail True None          # is_available True, CLI yolu None → API yolu
  w32.exe (x86 PE):     success False rules 0 errors ['CAPA extractor hatasi (format desteklenmiyor olabilir): unexpected backend: auto']
  debian/coreutils/true: success False rules 0 errors [... aynı ...]
  ```
  Gerçek çıktı: 119 ikilinin hiçbirinde `capa_*` istatistiği ya da `static/capa_capabilities.json` yok.
- Etki: Zararlı yazılım analistinin en değerli yetenek tespiti (capa: "keylogger", "anti-VM", "C2 iletişimi" vb.) belgelenmiş ve öntanımlı açık görünüyor ama hiç çalışmıyor; rapor "capa bulgusu yok" ile "capa çalışmadı" arasında ayrım yapmıyor, yani analist temiz sanabilir.
- Güven: kesin (yerel deneme + capa kaynağında sabitler)
- Onarım kapsamı: `capa_scanner.py` (`backend` değerini biçime göre `vivisect`/`dotnet` seçmek ya da capa'nın kendi `get_extractor` öntanımlısını kullanmak; desteklenmeyen mimaride (AArch64 ELF, Mach-O) açık "desteklenmiyor" durumu), `stages.py` (durum ve hata metnini istatistiğe yazmak), gerçek capa ile en az bir tümleşik test (pytest `skipif` capa yoksa). S–M.
- Nasıl sınanır: distlib `w32.exe` üzerinde `success True`, `total_rules_matched > 0`; AArch64 ELF'te `success False` ve istatistikte `capa_status="unsupported_arch"`; capa kurulu değilken `capa_status="not_installed"`.

## IMZA-07 — LMDB imza veritabanı her ada tek kitaplık tutuyor ve bu kitaplık "o adı içe aktaran Python paketi" olabiliyor: glibc `__printf_chk` → `opencv_python_headless`, `__assert_fail` → `cffi`, libselinux `fgetfilecon` → `psycopg2_binary`; hepsi 0,98 güvenle
- Önem: KRİTİK
- Tür: sahte/yanlış gösterim
- Yer: `karadul/analyzers/signature_db.py:2004-2038` (LMDB yedek araması; güven sabit 0,98/0,97), `karadul/analyzers/sigdb_lmdb.py` (`lookup_symbol`: ad → tek kayıt), veri `~/.karadul/signatures.lmdb` (9 217 381 simge); çıktı `pipeline/steps/ghidra_metadata.py:208-242` → `reconstructed/signature_matches.json`, `naming_map.json` `candidates[*].library`, `report.html` "recovered … signature_db (<lib>)"
- Etkin mi: evet (`perf.use_lmdb_sigdb` öntanımlı `True`, `config.py:783`; LMDB dosyası makinede var)
- Ne: LMDB anahtarı yalnız simge adı; aynı ad onlarca kitaplıkta geçtiğinde inşa sırasında hangisi en son yazıldıysa o kalıyor, diğerleri kayboluyor. Katalog, PyPI tekerleklerindeki yerel `.so` dosyalarının **içe aktardığı** simgeleri de "tanım" gibi kaydetmiş (`category: 'pypi_native'`). Sonuç: glibc'nin kendi fonksiyonları "opencv_python_headless", "cffi", "psycopg2_binary", "BrokenLocale", "secure" kitaplığına; `printf`/`memcpy`/`strlen` "Kernel" kitaplığına; `malloc` "c++" kitaplığına bağlanıyor. Güven, kaynağın ne olduğuna bakılmadan 0,98. Platform süzgeci (`_is_platform_compatible`, `:259-305`) bu kitaplık adlarını tanımadığı için "çapraz platform" sayıp geçiriyor.
- Kanıt: Yerel LMDB sorgusu:
  ```
  {'symbols': 9217381, 'string_sigs': 0, 'call_sigs': 0, 'byte_sigs': 0}
  __printf_chk {'lib': 'opencv_python_headless', 'category': 'pypi_native'}   __assert_fail {'lib': 'cffi', ...}
  printf {'lib': 'Kernel', 'category': 'Kernel'}   malloc {'lib': 'c++', 'category': 'memory'}   memcpy {'lib': 'Kernel', ...}
  ```
  Gerçek çıktı (117 Debian ikilisi, 33 310 imza eşleşmesi): bu tür kitaplık adıyla 2 955 eşleşme; en sık `('__fprintf_chk','opencv_python_headless') 349`, `('__errno_location','cffi') 345`, `('__ctype_get_mb_cur_max','BrokenLocale') 320`, `('fgetfilecon','psycopg2_binary') 36`. `debian/tree/tree/out/report.html`: `<td class="original">__printf_chk</td><td class="recovered">printf_chk</td><td>signature_db (opencv_python_headless)</td> … 98%`.
- Etki: Analist "bu ikili OpenCV / psycopg2 / cffi kullanıyor" sonucuna varabilir; kitaplık bağımlılığı zararlı yazılım sınıflamasında doğrudan kullanılan bir kanıttır. Gerçek kitaplık (glibc, libselinux) hiçbir yerde görünmüyor.
- Güven: kesin (LMDB sorgusu + gerçek çıktı sayımı)
- Onarım kapsamı: `scripts/build_sig_lmdb.py` (ya da LMDB'yi kuran betik; bu oturumda okumadım) — yalnız **dışa aktarılan / tanımlanan** simgeleri kaydetmek, ad başına çoklu kitaplık listesi tutmak; `signature_db.py` — çok kitaplıklı adda kitaplık hükmü vermemek ya da hedefin gerçek içe aktarım tablosundaki DT_NEEDED / LC_LOAD_DYLIB ile kesiştirmek; güveni kaynağa göre (`pypi_native` < `homebrew` < derlenmiş referans) ayarlamak. L (veritabanı yeniden kurulumu).
- Nasıl sınanır: `lookup_symbol('__printf_chk')` glibc (ya da kitaplıksız) döner; Debian `tree`/`tee` `signature_matches.json`'unda `pypi_native` kategorili kitaplık yok; birim testi: aynı ad iki kaynaktan eklenince ikisi de saklanır.

## IMZA-08 — ELF'te imza eşleşmesi adın baştaki bütün alt çizgilerini siliyor: `__printf_chk` → `printf_chk`, `__cxa_atexit` → `cxa_atexit` (var olmayan adlar) "kurtarılan ad" olarak raporlanıyor
- Önem: ORTA
- Tür: hata
- Yer: `karadul/analyzers/signature_db.py:1973` ve `:2015` (`matched_name=func_name.lstrip("_")`)
- Etkin mi: evet (aynı çağrı yolu; `naming_map.json` `candidates`, `report.html`)
- Ne: `lstrip("_")` Mach-O'nun C ön ekini (tek `_`) kaldırmak için yazılmış; ama hedef platformdan bağımsız ve baştaki **bütün** alt çizgileri siliyor. ELF/PE'de `__printf_chk`, `__assert_fail`, `__cxa_atexit`, `__errno_location` gerçek adlardır; silinmiş biçimleri hiçbir kitaplıkta yok. Mach-O'da da `___stack_chk_fail` (C adı `__stack_chk_fail`) `stack_chk_fail` olur. Kod içine uygulanmıyor (`naming_map` gerekçesi `not_in_code`), ama rapordaki "recovered" sütununda ve aday listesinde %98 güvenle görünüyor.
- Kanıt: Gerçek çıktı (117 Debian ikilisi): 33 310 eşleşmenin 5 556'sında `matched == original.lstrip("_")` ve `original` `__` ile başlıyor; örnekler `('__assert_fail','assert_fail')`, `('__ctype_b_loc','ctype_b_loc')`, `('__cxa_begin_catch','cxa_begin_catch')`.
- Etki: Analist doğru adın yerine uydurma bir ad görüyor; adı arattığında hiçbir belge bulamıyor. Ad doğruluğu ölçümüne giren bir kayıt değilse bile raporun güvenilirliğini düşürüyor.
- Güven: kesin (gerçek çıktı sayımı + kod)
- Onarım kapsamı: `signature_db.py` iki satır; yalnız `target_platform == "macho"` iken ve yalnız tek `_` kaldırmak; ELF/PE'de adı olduğu gibi bırakmak. S.
- Nasıl sınanır: ELF hedefte `_match_by_symbol('__printf_chk').matched_name == '__printf_chk'`; Mach-O'da `_malloc` → `malloc`, `___stack_chk_fail` → `__stack_chk_fail`.

## IMZA-09 — Protobuf "kısmi eşleşmesi" `Get`, `Set`, `Init`, `Next`, `Reset`, `Clear`, `Skip`, `Map` gibi 55 genel yöntem adını Google protobuf fonksiyonuna bağlıyor (0,85)
- Önem: YÜKSEK
- Tür: hata
- Yer: `karadul/analyzers/signature_db.py:2042-2072` (`:2052` `_PROTOBUF_BASENAME_INDEX` araması), `:423-438` (dizin kurulumu)
- Etkin mi: evet (`_match_by_symbol`, `match_all` → `ghidra_metadata` adımı; C++ simgeli ya da çözülmüş adlı her hedef)
- Ne: Fonksiyon adı `::` içeriyorsa son parçası, içermiyorsa adın tamamı protobuf temel ad dizininde aranıyor; bulunursa koşul `"::" in sym_name and func_name.endswith(basename)` her zaman doğru, çünkü temel ad zaten adın sonu. Dizinde `Get`, `Set`, `Init`, `Next`, `Reset`, `Clear`, `Skip`, `Map`, `Swap`… gibi her C++ kod tabanında bulunan adlar var. Kanıt olarak yalnız ad sonu kullanılıyor; hedefte protobuf'un varlığına (ör. `google::protobuf` simgeleri, `.proto` dizgileri) bakılmıyor.
- Kanıt: Yerel deneme (`SignatureDB(Config(), target_platform='elf')._match_by_symbol(...)`):
  ```
  MyCache::Get   -> ('google::protobuf::internal::ArenaStringPtr::Get', 'protobuf', 0.85)
  Parser::Init   -> ('google::protobuf::Arena::Init', 'protobuf', 0.85)
  Init           -> ('google::protobuf::Arena::Init', 'protobuf', 0.85)
  Timer::Reset   -> ('google::protobuf::Arena::Reset', 'protobuf', 0.85)
  std::map::Clear-> ('google::protobuf::Message::Clear', 'protobuf', 0.85)
  ```
  Dizinde 55 temel ad var.
- Etki: C++ zararlısında kendi `Init`/`Next`/`Get` yöntemleri "Google protobuf" olarak etiketlenir; analist bunları "kitaplık kodu, atla" diye geçebilir — zararlı mantık tam da bu tür yöntemlerde olur.
- Güven: kesin (yerel deneme)
- Onarım kapsamı: `signature_db.py`; kısmi eşleşmeyi ad alanı önekinin (`google::protobuf::`) bulunmasına bağlamak ya da tamamen kaldırmak. S.
- Nasıl sınanır: `MyCache::Get`, `Init` → `None`; `google::protobuf::Message::Clear` (tam ad) → protobuf.

## IMZA-10 — İmza veritabanının süreç düzeyindeki önbelleği yalnız `project_root` ile anahtarlanıyor; platform süzgeciyle yüklenen dış imzalar sonraki farklı platformlu hedefe yanlış küme olarak geçiyor
- Önem: ORTA
- Tür: hata / belirlenimsizlik
- Yer: `karadul/analyzers/signature_db.py:1501-1511` (önbellek anahtarı `str(project_root)`), `:1634-1645` (`_load_external_auto(target_platform=...)` sonucu önbelleğe yazılıyor), `:1765-1777` (dosya adına göre platform süzgeci)
- Etkin mi: LMDB kapalıyken ya da yokken (`perf.use_lmdb_sigdb=False`, `lmdb` modülü yok, `~/.karadul/signatures.lmdb` yok) — taze kurulumda olağan durum; aynı süreçte birden çok hedef çözümlendiğinde (`karadul batch analyze` → `karadul/batch.py:298` `ProcessPoolExecutor` işçileri yeniden kullanır)
- Ne: İlk `SignatureDB` örneği `sigs/` altındaki `linux_*`, `windows_*`, `macos_*` dosyalarını kendi hedef platformuna göre süzüp yüklüyor ve sonucu sınıf düzeyi `_full_cache`'e `project_root` anahtarıyla koyuyor. Aynı süreçteki sonraki örnek başka platform için olsa da önbellekten bu süzülmüş kümeyi alıyor; kendi platformunun dosyaları hiç yüklenmiyor. Önbellek ayrıca LMDB açık/kapalı durumunu da anahtara katmıyor. Sonuç sırası çözümleme sırasına bağlı.
- Kanıt: Geçici `project_root` ile deneme (LMDB kapalı):
  ```
  sigs/linux_test.json {only_linux_fn}, sigs/windows_test.json {only_win_fn}
  pe  : only_linux_fn False, only_win_fn True
  elf : only_linux_fn False, only_win_fn True, _match_by_symbol('only_linux_fn') -> None      # önbellekten
  elf (soğuk önbellek): only_linux_fn True -> liblinuxonly
  ```
- Etki: Toplu çözümlemede bir ELF hedefi, önce bir PE çözümlendiyse Linux imzalarını kaybediyor; aynı ikili iki koşuda farklı ad/kitaplık alıyor.
- Güven: kesin (deneme)
- Onarım kapsamı: `signature_db.py`; önbellek anahtarına `target_platform` ve LMDB durumunu eklemek ya da süzgeci yükleme yerine eşleme anında (zaten `_platforms` alanıyla yapılıyor) uygulamak. S.
- Nasıl sınanır: Yukarıdaki deneme `pe`→`elf` sırasında `only_linux_fn` eşleşir; sıra değişince sonuç değişmez.

## IMZA-11 — İmza veritabanının kapsamı depoda olmayan yerel dosyalara bağlı ve hiçbir çıktı hangi veritabanıyla koşulduğunu söylemiyor: taze kurulumda 9,2 M yerine ~7,7 bin ad, "eşleşme yok" ile "veritabanı yok" ayırt edilemiyor
- Önem: YÜKSEK
- Tür: sessiz hata / eksik özellik
- Yer: `karadul/analyzers/signature_db.py:1440-1488` (LMDB yoksa `logger.info` ile sessiz geri düşüş), `:1719-1806` (`sigs/`, `signatures_*.json`), `.gitignore:19-25` (`sigs/`, `signatures_homebrew*.json`, `sigs_macos_system.json` depo dışı), `pipeline/steps/ghidra_metadata.py:218` (yalnız `signature_matches` sayısı yazılıyor)
- Etkin mi: evet
- Ne: Bu makinede LMDB 9 217 381 ad içeriyor; yerleşik sözlük (`_symbol_db`) 7 674 ad. LMDB dosyası (`~/.karadul/signatures.lmdb`) ve `sigs/` dizini depoda yok (`git check-ignore sigs` → yok sayılıyor); GitHub'dan kuran kullanıcıda bunlar olmaz ve veritabanı sessizce 7 674 ada iner. Adım istatistiğine ne arka uç (LMDB / sözlük), ne ad sayısı, ne de LMDB'nin açılamama nedeni yazılıyor; `SignatureDB.stats()` var ama hiçbir adım çağırmıyor. Analist "imza eşleşmesi: 12" gördüğünde bunun 9 M'lik veritabanına mı, 7 bin adlık yedeğe mi karşı olduğunu bilemiyor; ölçümler de (Debian/Mac) bu yerel veritabanına bağlı, yani başka makinede yeniden üretilemez.
- Kanıt: `git check-ignore -q sigs && echo "sigs ignored"` → `sigs ignored`; `.gitignore` satır 19 `sigs/`, 22-25 `signatures_homebrew*.json`, `sigs_macos_system.json`. Yerel deneme: `SignatureDB(Config(), 'elf')` → `lmdb True symdb 7674`; `LMDBSignatureDB.total_entries` → `{'symbols': 9217381, 'string_sigs': 0, 'call_sigs': 0, 'byte_sigs': 0}`. `grep -rn "lmdb_backend\|sigdb_backend\|signature_db_size" karadul/pipeline/steps/*.py karadul/stages.py` → boş.
- Etki: Aynı ikili iki makinede çok farklı ad/kitaplık sonucu verir ve rapor bunu açıklamaz; "imza bulunamadı" sonucu "temiz/özgün kod" diye yorumlanabilir.
- Güven: yüksek (kodu izledim; taze kurulumu kurmadım)
- Onarım kapsamı: `ghidra_metadata.py` + `signature_db.py`; `sigdb_backend`, `sigdb_symbol_count`, `sigdb_lmdb_error` istatistiklerini her koşuda yazmak, rapora bir satır eklemek; veritabanının nasıl edinileceğini README/kurulumda belgelemek. S.
- Nasıl sınanır: LMDB yolu yanlış verilerek koşulduğunda istatistikte `sigdb_backend="dict"`, `sigdb_symbol_count≈7674` ve neden görünür.

## IMZA-12 — Yerleşik imza sözlükleri birleştirilirken sonraki sözlük öncekini ezer: 28 temel POSIX adı (`_open`, `_read`, `_write`, `_close`, `_stat`, `_getpid`, `_snprintf`…) MSVC CRT kaydıyla ezildiği için Mach-O'da hiç eşleşmiyor (B-C7'nin ölçülmüş etkisi)
- Önem: ORTA
- Tür: tutarsızlık / hata
- Yer: `karadul/analyzers/signature_db.py:1513-1626` (`for db in (...): self._symbol_db.update(db)`; `_MEGA_BATCH_1_SIGNATURES` ve `_MSVC_CRT_SIGNATURES` POSIX sözlüklerinden sonra), kaynaklar `sigdb_builtin/game_ml.py` (`mega_batch_1_signatures`), `sigdb_builtin/pe_runtime.py` (`msvc_crt_signatures`)
- Etkin mi: evet; görünür etki LMDB yokken/kapalıyken (taze kurulum). LMDB varken eşleşme LMDB'ye düşüyor ve oradaki tek kayda bağlı kalıyor (IMZA-07).
- Ne: Betikle tarama (birleştirme sırası kaynaktan okunarak, 100 sözlük): 8 084 girdi, 7 588 benzersiz ad; **472 ad birden çok sözlükte**, bunların **247'sinde lib/category çelişiyor**, 162'sinde kitaplık farklı. Sözlük literalleri içinde tekrarlı anahtar **yok** (AST taraması: 0). Çelişkilerin çoğu zararsız adlandırma farkı (`go-fmt` ↔ `fmt`), ama 28 adda son yazan kayıt yalnız PE'ye uygun (`msvcrt`, `win_crt`) ve önceki POSIX kaydı kayboluyor; `_is_platform_compatible` bu kaydı Mach-O/ELF için reddediyor, yerleşik sözlükte yedek kalmıyor.
- Kanıt: LMDB kapalı, boş `project_root`:
  ```
  hist['_open'] = [('_POSIX_FILE_IO_SIGNATURES','libc','file_io'), ('_MEGA_BATCH_1_SIGNATURES','msvcrt','win_crt'), ('_MSVC_CRT_SIGNATURES','msvcrt','win_crt')]
  ezilen 28 ad: _access _chdir _chmod _close _dup _dup2 _exit _fstat _getcwd _getpid _lseek _mkdir _open _pclose _pipe _popen _putenv _read _rmdir _snprintf _stat _strdup _unlink _write memcmp memcpy memmove memset
  macho _open None ; macho _read None ; macho _write None ; macho _close None ; macho _malloc ('libc','memory')
  ```
- Etki: LMDB'siz kurulumda Mach-O ikilisinin en temel G/Ç çağrıları imza eşleşmesi almıyor; dosya/süreç davranışı özetinde eksik kalıyor.
- Güven: kesin (betik + deneme)
- Onarım kapsamı: `signature_db.py` (birleştirmede ad başına platform listesi tutmak: aynı ad için POSIX ve MSVC kayıtlarını `_platforms` ile ayrı saklamak ya da PE kayıtlarını ayrı sözlükte tutup platforma göre seçmek), 247 çelişkinin kitaplık adlarını tekleştirmek (`go-fmt`/`fmt`). M.
- Nasıl sınanır: LMDB kapalıyken `_match_by_symbol('_open', target_platform='macho')` → libc/libSystem; `target_platform='pe'` → msvcrt; birleştirmede çelişen kayıt sayısını izleyen birim testi.

## IMZA-13 — PDB, Binary Ninja, TRex, DWARF, Rust ve Go demangler ad kanalları etkin akışta hiç beslenmiyor: tek çağıran `binary_path`/`pdb_symbols`/`bn_functions`/`trex_structs` geçmiyor, `consumed_symbols`'u okuyan kimse yok
- Önem: YÜKSEK
- Tür: ölü kod / hiç çalışmayan özellik
- Yer: `karadul/pipeline/steps/_feedback_naming_candidates.py:18-24` (parametreler öntanımlı `None`), `:80-91` (`if binary_path is not None …: _add_dwarf / _add_rust_demangler / _add_go_demangler`; `if pdb_symbols: …`), tek çağıran `karadul/pipeline/steps/_feedback_naming_merger.py:129-146` (bu dört argümanı geçmiyor); `karadul/pipeline/steps/type_recovery_consumer.py:1-40` (belge "`_feedback_naming_merger` ve `c_type_recoverer` bu artifact'leri okur" diyor)
- Etkin mi: ölü (adımlar `pdb_symbol_recovery`, `binaryninja_analysis`, `trex_struct_recovery`, `type_recovery_consumer` koşuyor ve JSON yazıyor; ama ürettikleri ada/ türe dönüşmüyor)
- Ne: v1.15-B7'de "dead pipeline" kapatıldı denmiş, ama `type_recovery_consumer`'ın ürettiği `consumed_symbols` / `consumed_types` artifact'lerini depoda okuyan tek satır yok (`grep -rn "consumed_symbols\|consumed_types" karadul` yalnız üreticinin kendisini buluyor). `collect_candidates`'ın 2026-05-13'te eklenen kanalları (DWARF, Rust/Go demangle, PDB, BN, TRex) yalnız `binary_path` ya da ilgili listeler verilirse çalışıyor; `_feedback_naming_merger` bunları hiç geçmiyor. Gerçek çıktıda `rust_demangler_status` / `go_demangler_status` istatistiği 119 ikilinin hiçbirinde yok (kanal hiç girilmemiş). Yani PE + PDB hedefinde derleyicinin kendi yazdığı adlar (en güvenilir kaynak) ada dönüşmüyor.
- Ek (kanal açıldığında patlayacak gizli hata): `_add_rust_demangler` her `_ZN…` simgesini Rust demangler'a veriyor; bu, C++ Itanium adlarını da kapsar. Yerel deneme: `_ZN3foo3barEi` ve `_ZN3foo3barEd` → ikisi de `'foo::bar'` (aşırı yükleme kaybı), `_ZN7MyClassC2Ev` (yapıcı) ve `_ZN7MyClassD1Ev` (yıkıcı) → ikisi de `'MyClass'`; aday kaynağı "rust_demangler", güven 0,95.
- Kanıt: `grep -rn "consumed_symbols\|consumed_types" karadul --include=*.py | grep -v type_recovery_consumer.py` → boş. `_feedback_naming_merger.py:129-146` argüman listesi: `extracted_names, naming_result, bindiff_confidence_map, refdiff_naming, fid_json, computation_result, pcode_naming_candidates, iter_index, stats, bsim_shadow, bsim_fusion_min_similarity, bsim_fusion_max_candidates, decompiled_dir, functions_json` — `binary_path`, `pdb_symbols`, `bn_functions`, `trex_structs` yok. Gerçek çıktı: `(rust_demangler_status, rust_candidates_added, go_demangler_status)` 119/119 `(None, None, None)`.
- Etki: Belgelerde ve adım listesinde "PDB/BN/TRex/DWARF/Rust/Go ad kurtarma" var; analist PDB'li bir PE verdiğinde bu adların kullanıldığını sanıyor, kullanılmıyor. Ölçümlerdeki ad kapsamı bu kanalların katkısını hiç içermiyor.
- Güven: yüksek (çağrı zincirini ve tüketicisizliği grep ile gösterdim; PDB'li gerçek bir PE ile uçtan uca koşmadım)
- Onarım kapsamı: `_feedback_naming_merger.py` (dört argümanı `ctx.artifacts`'tan geçirmek) ya da `consumed_symbols`'u okuyan bir tüketici; `_add_rust_demangler`'da Itanium C++ adlarını ayırmak (Rust legacy adı `17h<16 hex>E` ile biter; C++ adı `E`'den sonra parametre türü taşır). M. Tehlike: kanallar açılınca ad doğruluğu ölçümü değişir; açılmadan önce IMZA-14'teki demangler hataları giderilmeli.
- Nasıl sınanır: PDB'li küçük bir PE (ya da sahte `pdb_symbols` artifact'i) ile `naming_map.json`'da `source: pdb` adı; C++ simgeli bir ELF'te `rust_demangler` kaynaklı aday yok.

## IMZA-14 — Rust legacy demangler `$…$` kaçışlarını çözmüyor: her kapanış (`{{closure}}`) ve her `<impl X for Y>` adı yarı bozuk çıkıyor; v0'da punycode, geri başvuru ve sabit jenerik yer tutucuyla "tam ad" gibi dönüyor
- Önem: ORTA
- Tür: hata / sahte gösterim
- Yer: `karadul/analyzers/rust_demangler.py:286-350` (legacy ayrıştırıcı; dosyada `$LT$`, `$u7b$`, `..` → `::` dönüşümü yok), `:453-470` (punycode çözülmüyor, ham metin), v0 geri başvuru `B<n>_` → `_B<n>` yer tutucusu, sabit jenerik → `_const`; `:131-136` (`rustfilt` yoksa yerel ayrıştırıcı; bu makinede `rustfilt` yok)
- Etkin mi: dolaylı — tek etkin çağıran yok (IMZA-13: ad kanalı ölü); `karadul/analyzers/rust_binary.py` de içe aktarıyor (bu oturumda o yolun etkin olup olmadığını izlemedim)
- Ne: Rust legacy adlarında `<`, `>`, `{`, `}`, boşluk `$LT$`, `$GT$`, `$u7b$`, `$u7d$`, `$u20$` olarak, `::` ise `..` olarak kodlanır. Ayrıştırıcı bunları çözmüyor; ayrıca bu bileşenlerin başındaki `_`'yi de bırakıyor. Sonuç tam ad gibi dönüyor; çağıran "çözülemedi" ile "çözüldü" ayrımını yapamıyor.
- Kanıt: Yerel deneme (`rust_demangler.demangle`):
  ```
  _ZN4core3ops8function6FnOnce9call_once28_$u7b$$u7b$closure$u7d$$u7d$17h…E -> 'core::ops::function::FnOnce::call_once::_$u7b$$u7b$closure$u7d$$u7d$'   (beklenen …::{{closure}})
  _ZN4core3fmt3num52_$LT$impl$u20$core..fmt..Debug$u20$for$u20$usize$GT$3fmt17h…E -> 'core::fmt::num::_$LT$impl$u20$core..fmt..Debug$u20$for$u20$usize$GT$::fmt'
  _RNvCs4fqI2P2rA04_11utf8_identsu30____7hkackfecea1cbdathfdh9qlzbm -> 'utf8_idents::___7hkackfecea1cbdathfdh9qlzbm'
  _RNvMNtCs1234_7mycrate3fooNtB2_3Bar3baz -> '<_B3::Bar>::baz'      ; _RINvC7mycrate3fooKj7b_E -> 'mycrate::foo<_const>'
  _RINvNtC3std3mem8align_ofjE -> 'std::mem::align_of<usize>'   (beklenen align_of::<usize>)
  ```
  Kötü niyetli girdi denemesi (5 000 derin geri başvuru, 10^20 uzunluk alanı, 100 000 karakterlik sabit): hepsi < 0,01 sn, istisna/özyineleme hatası yok — sağlamlık sorunu görmedim.
- Etki: Rust zararlıları (giderek yaygın) için kapanış ve trait gerçekleştirme adları okunmaz; kanal açıldığında bu bozuk adlar 0,95 güvenle aday olur.
- Güven: kesin (deneme)
- Onarım kapsamı: `rust_demangler.py`; legacy kaçış tablosu (`$SP$ $BP$ $RF$ $LT$ $GT$ $LP$ $RP$ $C$ $uXX$`, `..`→`::`, baştaki `_$` kuralı), punycode çözümü (Python `codecs` "punycode" + Rust'ın `_` ayırıcı farkı), v0 geri başvuruların çözümü ya da çözülemezse `None`. M. Alternatif: `rustc-demangle` mantığının birebir taşınması.
- Nasıl sınanır: rustc-demangle test takımındaki legacy ve v0 örnekleri (yukarıdakiler dahil) birebir.

## IMZA-15 — Anti-debug, paketleyici ve YARA taramalarında "taranamadı" ile "temiz" aynı görünüyor: hata ya da kısmi tarama durumunda JSON "0 bulgu" yazılıyor, rapor bölümü hiç basılmıyor
- Önem: ORTA
- Tür: sessiz hata
- Yer: `karadul/analyzers/anti_debug_detector.py:390-414` (üç katmanın her biri `except Exception: logger.warning` ile yutuluyor), `:717-735` (`max_bytes_scan` 50 MB'den büyük dosyada yalnız baş kısım, `logger.info`); `karadul/pipeline/steps/anti_debug.py:130-150` (`:135` `status="error"` yalnız `ctx.stats`'a; ardından `:142-146` aynı `anti_debug_findings.json` `total_findings: 0` ile yazılıyor, durum alanı yok); `karadul/pipeline/steps/packer_fingerprint.py:113-128` (aynı kalıp); `karadul/analyzers/packer_fingerprint.py:501-503` (200 MB okuma, dizgi taraması ilk 16 MB); `karadul/reporting/markdown_report.py:465-471`, `:619-630` (bulgu yoksa bölüm `[]`); `karadul/stages.py:307-330` (YARA: eşleşme yoksa hiçbir istatistik yok, `yara_result.errors` atılıyor)
- Etkin mi: evet
- Ne: Dedektör içindeki bir katman hata verirse (ör. bozuk başlıklı kasıtlı bir ikili `lief`'i düşürürse) o katmanın bulguları sessizce boş kalıyor. Adım düzeyinde istisna olursa istatistiğe `error` yazılıyor ama analistin gördüğü iki yüzey — `static/*.json` ve rapor — "0 bulgu"dan ayırt edilemiyor; rapor bölümü bulgu yoksa hiç yazılmıyor. 50 MB'yi (anti-debug) / 16 MB'yi (paketleyici dizgileri) aşan dosyada taramanın kısmi olduğu hiçbir çıktıda yok; PyInstaller'ın `PYZ-00.pyz` TOC kaydı gibi dosya sonundaki işaretler bu yüzden kaçabilir. YARA'da `yara-python` derleme hatası `regex-fallback`'e düşüyor, durum yalnız eşleşme varsa `yara_backend` olarak görünüyor.
- Kanıt: `anti_debug.py` akışı: `except Exception as exc: … ctx.stats["anti_debug_status"] = "error"` → hemen ardından `payload = {"binary_path": …, "total_findings": len(findings_dicts), "findings": findings_dicts, …}` (`findings_dicts` boş). `markdown_report.py:469-471`: `findings = data.get("findings") or []; if not findings: return []`.
- Etki: Zararlı yazılım analizinde "anti-debug yok / paketli değil" sonucu, hatanın ya da kısmi taramanın sonucu olabilir; analist bunu bilemez. Kötü niyetli girdi bilerek ayrıştırıcıyı düşürüp temiz görünebilir.
- Güven: yüksek (kod akışını izledim; hatayı tetikleyen bir girdi üretmedim)
- Onarım kapsamı: iki adım + `stages.py` YARA bloğu; JSON'a `status`, `errors`, `scanned_bytes`/`file_size` alanları; rapor bölümünü bulgu olmasa da "tarandı: temiz / taranamadı: neden" satırıyla basmak. S.
- Nasıl sınanır: `AntiDebugDetector.detect_by_imports`'u istisna atacak biçimde taklit eden test: JSON'da `status: error`, raporda "taranamadı" satırı; 60 MB'lik dosyada `scanned_bytes < file_size` görünür.

## IMZA-16 — `enable_rtti_recovery` ayarı hiçbir yerde okunmuyor; C++ RTTI kurtarma analiz akışına bağlı değil, yalnız ayrı `karadul rtti` komutuyla erişilebiliyor
- Önem: DÜŞÜK
- Tür: okunmayan ayar / ölü kod
- Yer: `karadul/config.py:558` (`enable_rtti_recovery: bool = False`); `karadul/analyzers/cpp_rtti.py` (1 553 satır) yalnız `karadul/cli.py:1962-1983` (`rtti` komutu) tarafından içe aktarılıyor
- Etkin mi: ölü (analiz akışında)
- Ne: `grep -rn "enable_rtti_recovery"` yalnız tanımı buluyor. Ayarı `True` yapan kullanıcı hiçbir değişiklik görmez; RTTI'den sınıf adı / vtable kurtarma `analyze` akışında hiç koşmaz.
- Kanıt: `grep -rn "enable_rtti_recovery\|cpp_rtti" karadul --include=*.py | grep -v analyzers/cpp_rtti.py` → `config.py:558` ve `cli.py:1983`.
- Etki: C++ zararlılarında sınıf adları (RTTI, sıyrılmış ikilide bile kalır) analize girmiyor; ayar yanıltıcı.
- Güven: kesin (grep)
- Onarım kapsamı: ya ayarı kaldırmak ya da bir adım olarak bağlamak (o zaman kötü niyetli girdiye karşı sağlamlık denetimi gerekir; `cpp_rtti.py`'yi bu oturumda hostile girdi açısından denetlemedim). S/M.
- Nasıl sınanır: ayar açıkken C++ bir ikilide RTTI sınıf adları çıktıda görünür ya da ayar silinmiştir.

## Küçükler
- `karadul/hacker_cli.py:351-400` `_show_intelligence_alerts` `security_mechanisms` / `algorithms` / `subsystems` anahtarlarını kökte arıyor; `intelligence_report.json` bunları `architecture` altında tutuyor (`binary_intelligence.py:129-136`) → "!! ALERT" / ">> CRYPTO" satırları hiç basılmıyor (ölü; IMZA-01 düzelmeden açılırsa sahte alarm basar).
- `karadul/reporting/sarif_report.py:360-388` `yara_matches`'ı liste bekliyor, `stages.py:315` ise sayı (int) yazıyor → dal ölü; `detected_tech` girdileri düz dizgi olduğundan `tech_type="unknown"` → YARA paketleyici eşleşmeleri KRDL004 yerine KRDL003 ve mesajda "(unknown)".
- `binary_intelligence.py:1761` alt sistem eşiği `len(evidence) < 2 and confidence < 0.1` — tek kanıtlı alt sistem desen oranı ≥ 1/7 ise geçiyor (IMZA-01'i büyütüyor).
- `signature_db.py` dizgi katmanı Debian coreutils'te `FUN_` fonksiyonlarına `copy_buffer` (77), `read_env_var` (50), `parse_elf` (23; `nice`, `df`, `du`, `runcon`) gibi adlar veriyor (güven 0,55–0,79). Gerçek çıktıda 359 eşleşmenin 0'ı `naming_map`'e uygulanmış, yani bugün yalnız `reconstructed/signature_matches.json`'da duruyor; bir tüketici okumaya başlarsa sahte ad olur.
- `anti_debug_detector.py:262-263` `(?i)vmtoolsd|vmware`, `(?i)qemu-ga|QEMU` dizgileri herhangi bir yardım metninde geçen "qemu"/"vmware" sözcüğünü anti-VM sayar (şüphe: gerçek çıktıda rastlamadım).
- `packer_fingerprint.py:281` dışında `:277` `b"\x60\xbe"` (UPX, 2 bayt) ve `:283` `b"\x66\x9c\x60"` (Petite, 3 bayt) aynı "giriş noktası hesaplanmıyor" sorununu taşıyor (IMZA-04 onarımına dahil edilmeli).
- `signature_db.py:1634-1645` önbelleğe yalnız sembol/dizgi/çağrı sözlükleri giriyor; `load_flirt_signatures` ile `.pat`'tan gelen bayt imzaları önbellekten kurulan örneklerde yok (şüphe: `load_and_inject`'in bayt imzalarını hangi yapıya yazdığını izlemedim).

## Bilinenlerin durumu
| Kimlik | Durum | Kanıt |
|---|---|---|
| B-C7 (`sigdb_builtin`'de tekrarlı anahtarlar) | kısmen | AST taraması: sözlük literalleri içinde tekrarlı anahtar **0**. Sözlükler arası: 100 sözlük, 8 084 girdi, 7 588 benzersiz ad; 472 ad birden çok sözlükte, 247'sinde lib/category çelişiyor; 28 POSIX adı MSVC kaydıyla ezilip Mach-O'da eşleşmez oluyor (IMZA-12). `data_flow.py` kısmına bakmadım (kulvar dışı). |
| B-D3 (FLIRT bayt imzaları seçici değil, bilerek kapalı) | duruyor | `pipeline/steps/byte_pattern.py:207-214` yorum: imza kökü yalnız `project_root`, `--output-dir` ile bulunmuyor (bilinçli). Gerçek çıktıda 119 koşunun 117'sinde `flirt_signatures_loaded=0`, 2'sinde 1; `flirt_functions_named` 119/119 0. |
| B-B6 (rapor yazılmayan `static/signature_matches.json`'ı okuyor) | duruyor | Yazan: `pipeline/steps/ghidra_metadata.py:220-222` → `"reconstructed", "signature_matches"`; okuyan: `reporting/html_report.py:570`, `markdown_report.py:708` → `"static", "signature_matches"`. |
| B-D2 (BSim adayları ortak depodan) | bakılmadı | `bsim_match.py` adımını yalnız çağrı sözleşmesi açısından açtım; aday deposu sızıntısını incelemedim. |
| B-B9 (`bsim_yedege_dustu` vb.) | bakılmadı | — |

## Bakamadıklarım
- `flirt_parser.py`, `byte_pattern_matcher.py` (eşleşme tekilliği, joker oranı, PIE/thumb ofset hesabı): FLIRT etkin akışta fiilen 0 imza yüklediği için (B-D3) önceliği düşürdüm; satır satır okumadım.
- `bindiff.py`, `cfg_analyzer.py`, `pcode_analyzer.py`, `inline_detector.py`, `assembly_analyzer.py`: çağıranlarını buldum (hepsi bir adım ya da `_feedback_naming_bindiff.py` üzerinden etkin), eşik/tekillik mantığını okumadım.
- `pdb_parser.py`, `dwarf_extractor.py`, `cpp_rtti.py`: kötü niyetli girdi (uzunluk alanı, özyineleme) denetimi yapmadım; PDB ve DWARF ad kanalının etkin akışta ölü olduğunu gösterdim (IMZA-13), RTTI analiz akışında hiç koşmuyor (IMZA-16). `go_demangler.py` için yalnız kötü niyetli girdi denemesi yaptım (sorun yok), doğruluk denetimi yapmadım.
- `trex_adapter.py`, `typeforge_adapter.py`, `binaryninja_adapter.py`: araç yok / başarısız durum bildirimini okumadım; çıktılarının ada dönüşmediğini gösterdim (IMZA-13).
- `sigdb_lmdb.py` ↔ JSON yolu eşdeğerliği: LMDB'yi kuran betiği okumadım; LMDB'de `string_sigs`, `call_sigs`, `byte_sigs` sayısının 0 olduğunu gördüm (LMDB açıkken dizgi/çağrı imzaları yalnız yerleşik sözlükten geliyor).
- `signature_db.py`'nin bayt katmanı (`_match_by_bytes`, FindCrypt sabitleri) ve çağrı deseni katmanı: okumadım.
- `binary_intelligence.analyze_decompiled` (`_VULNERABILITY_PATTERNS`, fonksiyon başına "zafiyet" etiketi): okumadım; aynı desen sorunu orada da olabilir.
- `yara_scanner.load_rules` (harici `.yar` dizinleri): depo dışı kural bağımlılığı var mı, bakmadım; etkin çağıran yalnız yerleşik kuralları yüklüyor (`stages.py:311-312`).

## KULVAR BİTTİ
