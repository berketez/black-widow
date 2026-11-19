# HIZ defteri (2026-11-19)

Sahip: perf-optimizer (Opus), HIZ plan paketi. Ürün kodu salt okur; Ghidra ve `karadul analyze` koşulmuyor.

## 12:38 — başlangıç durumu

- Gösteri koşusu (pid 74835, `kos2.sh`) **sürüyor**: `~/karadul_olcum/runs/gosteri-2026-11-19/ollama/CIKIS` yok. Elde dosya zamanlarıyla çalışılacak; bitince okunacaklar PLAN'a yazılacak.
- Makine yüklü: yük ortalaması 43 / 37 / 37 (`uptime`, 12:38). Aynı anda: kimlik hattının Ghidra koşusu (tmuxO0), P12d yeniden oynatmaları (6 süreç), ÖLÇEK envanter betiği.
- Ürün kodu gösteri koşusundan beri değişmedi: `git diff --stat b4be6f3 HEAD -- karadul/` boş. Yani okuduğum kod = gösteri koşusunun kodu.
- Makine: `sysctl` → perflevel0 10 mantıksal çekirdek, perflevel1 4, toplam 14; 36 GiB; L2 16 MiB (P kümesi) / 4 MiB (E kümesi); önbellek satırı 128 B; sayfa 16 KiB. macOS 27.2.1. Python 3.12.7 (Anaconda, arm64), JPype 1.6.0, pyghidra 3.0.0. JVM: Homebrew OpenJDK 21.0.13.1 arm64 (`lsof -p 74835`).
- Not: `kos2.sh` gösteri koşusunu `commit` dosyası `b4be6f3` olarak kaydediyor (deneme 1'in dosyası); HIZ.md "main 2381dce" diyor. İki commit de yalnız belge; ürün kodu aynı.

## İlk okumalar

- `ghidra_output/bsim_matches.json`: `ingest_s` 1152,1; `query_s` 789,4; `known_executables` 1; `excluded.self` 43 442; `matches` boş. Veritabanı koşuya özel (`KARADUL_CACHE_DIR=$D/cache`, `cache/bsim/karadul_bsim.mv.db` 16 MB). Yani sorgu, veritabanında hedefin kendisinden başka program yokken koştu → eşleşme çıkamazdı.
- `ghidra_status.json`: Ghidra 3815,4 sn; 13 559 fonksiyon (13 160 program + 399 thunk); decompile 13 554 / 13 559.
- `ghidra_log.txt`: otomatik analiz 226,4 sn.
- `macho.py:434-438`: Ghidra'nın bütün çıktıları (`scripts_output`) `static/ghidra_<ad>.json` olarak ikinci kez serileştiriliyor (ör. 128 MB `cfg.json` → `static/ghidra_cfg.json`). Gösteride 12:14:38 → 12:14:50.
- `headless.py:713` `analyzer_times` sonuç sözlüğüne giriyor; `macho.py:1124-1146` `ghidra_status.json`'a yazmıyor → çözümleyici başına süre kayboluyor (ölçüm açığı).
- Taban koşusu (`urun-onarim-a62f15e`): 3 paralel, 119 ikili, BSim deposu koşular arası ORTAK (`runs/urun-onarim-a62f15e/cache/bsim`; tmux günlüğünde kilit bekleme satırı). Ürün adım süresini `reports/pipeline_result.json` → `stages.*.duration_seconds`, `stages.reconstruct.stats.*_duration_s` (üst düzey adım, `runner.py:263`) ve `timing_*` (iç) olarak yazıyor.

## 12:42 — ana oturumdan kapsam düzeltmesi (Berke)

"Sadece M4 Max için değil; gelecekte M5 Max, M6 Max alırım; tek işlemci için değil, genel." Bağlayıcı sonuçlar:
- Hiçbir öneri çekirdek sayısına, bellek boyutuna, çip adına sabitlenmez; değer çalışma anında algılanan donanımdan türetilir (macOS `hw.perflevel0.physicalcpu` / `hw.perflevel1.physicalcpu` / `hw.memsize`, perflevel sayısı değişebilir; öbür platformlarda `os.cpu_count()` ve bellek). Türetme kuralı PLAN'da formül; sabitler tek yerde (`karadul/config.py`).
- Bugünkü türetmenin farklı donanımda davranışı ölçülecek (8 GB / 4+4; 128 GB / 16+4; verim çekirdeksiz; Linux; Windows) ve sabitlenmiş her sayı dosya:satır ile listelenecek.
- Kabul ölçütleri oranla (aynı makinede önce / sonra); her ölçüm kaydına donanım künyesi.
- Öneriler ikiye ayrılacak: her platformda kazandıran / yalnız başarım-verim çekirdekli işlemcide anlamlı.

## 12:41 — gösteri ilerleme

- `static/ghidra_output/decompiled/*.c`: 13 554 dosya, 11:17:24 → 11:26:06 (ortanca 11:21:07).
- `deobfuscated/decompiled/*.c`: 13 554 dosya, 12:33:45 → 12:40:39 — dosyalar yeniden yazılıyor (copytree `copy2` mtime'ı korurdu; yani deobfuscate adımı her dosyayı yeniden yazıyor). ~7 dk. tmux'ta deobfuscate 5,2 sn / 2 821 dosya idi.
- 12:29:36 (capa) → 12:33:45 arası ~4 dk boşluk: ne koştuğu koddan çıkarılacak.

## 12:50 — kalem 1 yöntemi (sayılara bakmadan önce)

- Betik: `scripts/arge/hiz/zaman_cizelgesi.py` (salt okur; ürün kodunu içe aktarmaz).
- Ghidra iç adım süresi = `ghidra_output/<adım>.json` mtime farkı (adım bitince yazılır, `headless.py:359-606`). Ghidra başlangıcı = max(`static/lief_analysis.json` mtime, `combined_results.json` − `ghidra_status.duration_seconds`).
- Taban koşusu boyut sınıfları (Ghidra fonksiyon sayısı, sayılara bakmadan): küçük < 1 000; orta 1 000–4 999; büyük ≥ 5 000. Gösteri (13 559) ayrı "çok büyük" satırı.
- Taban koşusu 3 paralel + başka yükle koştu, BSim deposu ortak (kilit bekleme ayrı kalem). Mutlak süre güvenilmez; pay ve sıra okunacak.

## 13:05 — kalem 1 sonuçları (betik çıktıları)

- Gösteri zaman çizelgesi: `python scripts/arge/hiz/zaman_cizelgesi.py gosteri --kok ~/karadul_olcum/runs/gosteri-2026-11-19/ollama --cikti ~/karadul_olcum/runs/arge-2026-11-19/hiz/zaman` → `gosteri_zaman.md`. Ghidra 3 815 sn içinde: BSim 1 951,9 sn (%51,2; ingest 1 152,1 + sorgu 789,4), CFG 600,9 (%15,7), decompile 523,9 (%13,7), xref 348,7 (%9,1), JVM+içe aktarma+otomatik analiz+fonksiyon listesi 320,6 (otomatik analiz 226,4), çağrı grafı 55,6. Ghidra sonrası: ikinci serileştirme 12:14:43→12:14:50 (~7 sn), istihbarat 879,8 sn, YARA+capa 6,1 sn, statik kapanış + copytree 249,6 sn, deobfuscate dosya döngüsü ≥ 414,0 sn.
- Taban 119 ikili: `zaman_cizelgesi.py taban` + `taban_ayrinti.py`. Baskın kalem `feedback_loop` (küçük %30,5 / orta %34,3 / büyük %27,4 duvar payı); onun içinde `c_naming` iter0+iter1 %41,9, `type_recovery` %20,3, `ngram_naming` %15,2, `name_merger` %12,7. Küçük ikilide ikinci kalem JVM başlatma + içe aktarma (%11,8, ikili başına ~9 sn sabit).
- Ölçekleme (log-log eğim, taban): CFG 1,53; xref 1,35; pcode 1,33; çağrı grafı 1,27; decompile 1,24; BSim 0,96; feedback_loop 0,67. Ollama'da fonksiyon başına: CFG 44,3 ms (taban 0,5–5,2), xref 25,7 ms (0,6–4,7), BSim ingest 85 ms (5–20).
- Yorum: küçük / orta / büyük (≤ 5 700 fn) ikilide baskın kalem Python yeniden kurma (`feedback_loop`); 13 559 fn'lik ikilide baskın kalem Ghidra köprüsü (BSim + dökümler). Baskın aşama boyutla DEĞİŞİYOR.

## 13:10 — kalem 2/4 ara bulgular

- JSON: CPython 3.12 `indent` verilince saf Python kodlayıcı (doğrulandı, `json/encoder.py`). Ürün kodunda 76 `indent=2`. Ölçüm (`json_olcum.py`): 128 MB cfg.json `indent=2` 3,42 sn, orjson `OPT_INDENT_2` 0,12 sn, **bayt bayt aynı** (5 / 5 dosya). Ama CFG adımının 600,9 sn'sinin yalnız ~3,4 sn'si serileştirme → JSON küçük kalem.
- Geçiş sayısı (`gecis_sayimi.py`, alt sınır): Ollama 115,4 M (pcode seçici 42,9; çağrı grafı 17,1; xref 17,0; decompile xref 16,3; CFG 11,2; disassembly 10,8). Gövde adresi toplamı 5 417 829 — adres başına `getReferencesFrom` döngüsü ÜÇ kez koşuyor (çağrı grafı `headless.py:909-913`, decompile `:1062-1065`, xref `:1737-1741`).
- Zımni geçiş maliyeti CFG'de: Ollama ~53 µs (11,2 M / ~597 sn), mac/tmux ~4 µs, openssl ~2,6 µs. Yük tek başına (40–60 / 14) bu 13–20× farkı açıklamıyor → büyüklüğe bağlı ek maliyet var (hipotezler: Python döngüsel çöp toplayıcı büyük yığında; JPype başvuru kuyruğu; Ghidra DB önbelleği). Ghidra'sız JPype mikro deneyiyle sınanacak.
- İş parçacığı CPU (`is_parcacigi.py`, `ps -M`, müdahalesiz): gösteri sürecinde bir iş parçacığı 2 261 sn kullanıcı süresi (süreç toplamının %69,6'sı), Ghidra sonrası büyümüyor. Deneme 1 jstack'inde "Python Reference Queue" 1 661 sn'de 33,8 sn idi (çıkarım başlamadan). HIZ.md'deki "49. dk'da 1 714 sn" ile tutarlı: bu iş parçacığı çıkarım sırasında ~%60 çekirdek yiyor.

## 13:15 — donanım türetmesi (Berke'nin düzeltmesi)

- `sabit_tarama.py` → `~/karadul_olcum/runs/arge-2026-11-19/hiz/sabit_tarama.md`: sabit sayı 8 yer, türetilmiş + sabit kırpma 5+, türetilmiş 41.
- `donanim_turetme.py` (ürünün kendi işlevleri, işletim sistemi yanıtları yamalı): 
  - 8 GB / 4+4 Mac → yığın 4 096 MB = belleğin %50'si (taban 4 096 baskın).
  - 128 GB / 16+4 → yığın 32 768 MB. **Aynı JDK ile ölçüldü: `-Xmx32768m` ve `-Xmx32767m` → UseCompressedOops=false ("Max heap size too large for Compressed Oops"); `-Xmx31744m` → true.** Bugünkü tavan ≥ ~80 GB bellekli her makinede sıkıştırılmış göstericileri kapatıyor.
  - Windows → `os.sysconf` yok, `sysctl` yok → TOTAL_MEMORY_MB 8 192 yedeği → yığın her makinede 4 096 MB.
  - Verim çekirdeği olmayan / perflevel'siz makine → `max(2, int(cpu_count*0.7))`: 16 i.p. → 11; Linux melez 32 → 22 (P iş parçacığı 16'yı aşıyor); kapsayıcıda cgroup CPU kotası okunmuyor (64 → 44).
  - Tutarsızlık: `c_type_recoverer.py:1330,1455` `os.cpu_count()` (verim çekirdekleri dahil), öbürleri `CPU_PERF_CORES`.

## 13:00 — BSim koddan + JPype mikro deneyi

- BSim ingest `bsim.py:1260-1266`: her gerçek fonksiyon için Python'dan `gen.scanFunction(func)` → GenSignatures fonksiyonu KENDİ decompiler'ıyla yeniden decompile eder (tek iş parçacığı). Sorgu `bsim.py:1443-1449`: YENİ bir GenSignatures, bütün fonksiyonlar ÜÇÜNCÜ kez decompile. Gösteri: ingest 1 152 sn + sorgu 789 sn; decompile adımı (10 iş parçacığı) 524 sn.
- `javap` (BSim.jar, Ghidra 12.1.2): `GenSignatures.scanFunctions(Iterator<Function>, int, TaskMonitor)` var → `ParallelDecompileTask` → `DecompilerConcurrentQ` (Ghidra'nın paralel decompiler kuyruğu). Ürün kullanmıyor.
- BSim sonucu adlara GİRMİYOR: `config.py:728-751` `enabled=True`, `shadow_mode=True`, `use_bsim_fusion=False`; `_feedback_naming_merger.py:583-625` yalnız `use_bsim_fusion` açıkken okur. Gösteride depo koşuya özel ve boş (`known_executables: 1`).
- ÖLÇEK ÖL-2 BSim'in boş depoda sorgusunu atlıyor + ingest bütçesi koyuyor; HIZ'ın katkısı BSim KOŞTUĞUNDA hızlandırma: paralel `scanFunctions` + ingest'in DescriptionManager'ını sorguda yeniden kullanma (üçüncü decompile yok).
- JPype mikro deneyi (`jpype_gecis.py`, aynı libjvm, Ghidra yok, yük ~34): geçiş 0,73–2,02 µs; büyük Python yığını (5 M sözlük) ve `gc.freeze` etkisiz (Python gc bu döngülerde hiç tetiklenmedi: [0,0,0]); 1 M canlı sarmalayıcı etkisiz; Reference Queue kalıp başına ~0,001 sn. Toplamda Reference Queue 2,51 sn / ~50 sn koşu (boşta yoklama; deneme 1'de 33,8 / 1 661 sn ≈ %2).
  - Sonuç: yalın JPype geçişi Ollama'da gözlenen ~53 µs/geçişi ve 2 261 sn Reference Queue işlemcisini AÇIKLAMIYOR. Neden Ghidra tarafında (program DB erişimi, BasicBlockModel, nesne üretimi) ya da Ghidra'nın JPype kullanımına özgü. → E1'de JFR (Java Flight Recorder, JDK 21'de yerleşik, `JAVA_TOOL_OPTIONS` ile kod değişikliksiz) ile sınanacak.
  - "Python ↔ Java geçişini azalt" önerisinin kazancı bu yüzden sayı × 1–2 µs ile sınırlı TAHMİN EDİLEMEZ; gözlenen adım süresi geçiş sayısıyla orantılıysa (adım süresi / geçiş ≈ sabit) kazanç orantılıdır. Ölçüt E1'de.

## 13:05 — decompile dengesi, ikinci tur, dosya açma

- `decompile_dengesi.py --is-parcacigi 10` (`.c` başlığındaki adres + mtime → parça bitişi): dengesizlik (en uzun parça / ideal) Ollama 1,05; mac/tmux 1,13; debian/tmux 1,36; redis-check-aof 1,18; zstd 1,60; htop 1,67; sqlite3 2,31; openssl 5,62 (tek parça 66 sn, öbürleri 4–8 sn). Statik ardışık parçalama (`headless.py:1226-1229`) küçük/orta ikilide decompile adımını şişiriyor; Ollama'da darboğaz dengesizlik değil.
- `tur_sayimi.py`: 119 / 119 ikili 2 tur koştu; 118'inde ikinci tur 0 yeni ad (tek istisna debian/tmux: 1 ad); 0 yeni adlı son turlar 1 326,0 sn = feedback_loop'un %36,7'si. `check_convergence` ilk turda hiç durmuyor (`_feedback_helpers.py:132`). Turun çıktıyı (tip, yorum) değiştirip değiştirmediği ölçülmedi → "çıktıyı değiştirebilir" sınıfı.
- Profil (seri kip, mac/tmux kopyası) A istihbarat: duvar 21,8 / işlemci 5,1 sn, `_io.open` 2 824 çağrı 15,3 sn. B deobfuscate: duvar 24,9 / işlemci 5,1 sn, `_io.open` 11 291 çağrı 20,1 sn; `copy2` 8,9 sn. İşlemci dışı sürenin tamamına yakını dosya açma.
- `acma_gecikmesi.py` (yük ~30): kendi kopyamdaki .c açma ortanca 2,83 ms (p90 11,8; p99 69,0); YENİ dosya oluşturma 0,047 ms; okuma+kapama 0,014 ms. Taban koşusunun 5 saatlik .c'leri ortanca 0,73 ms (p90 14,9); depodaki .py (karadul/reconstruction) ortanca 31,0 ms (p90 196); /usr/share/zoneinfo 0,51 ms; anaconda email .py 7,35 ms.
- `systemextensionsctl list`: **Avast Security (com.avast.Antivirus.SystemExtension) etkin.** Açma maliyeti erişimde taramayla (EndpointSecurity AUTH_OPEN) tutarlı: yeni oluşturma hızlı, var olanı açma yavaş, betik dosyası (.py) en yavaş. Nedensellik ölçülmedi (AV kapatılmadı / dışlama yok; Berke'nin kararı). Genel ders: erişimde tarayan her güvenlik yazılımında (Windows Defender dahil) on binlerce küçük dosyayı tekrar tekrar açan akış pahalı.
- İçe aktarma: `python -c "import karadul.reconstruction.c_namer"` 0,42 sn (importtime koşusunda 1,86 sn), `karadul.stages` 6,37 sn. `spawn` işçisi bunu her havuzda yeniden öder.

## 13:12 — ek okumalar

- `_extract_disassembly` yalnız `headless.py:1417`'de; sonuçtan yalnız `address`, `text`, uzunluk kullanılıyor (`:1487-1490`, `:1508`). `mnemonic` / `operands` (komut başına `getNumOperands` + işlenen başına çağrı) atılıyor → çıktıyı değiştirmeden kaldırılabilir (getMnemonicString'in istisna yolu korunmalı: `:989-993` `continue`).
- Çağrı grafı (`:890-930`), decompile fonksiyon xref'i (`:1029-1086`) ve xref dökümü (`:1737-1785`) aynı başvuru verisini üç kez, her adres için ayrı çağrıyla geziyor. Arayan / çağrılan listelerinin sırası üçünde de aynı kurala bağlı (getReferencesTo sırası; gövde adres sırası; ilk görülen tekilleştirme) → tek geçişte hesaplanıp üç yere verilebilir (bayt eşitliği beklenir; sınanacak).
- `javap` (SoftwareModeling.jar, Ghidra 12.1.2): `ReferenceManager.getReferenceSourceIterator(AddressSetView, boolean)`, `hasReferencesTo(Address)`, `Listing.getInstructions(AddressSetView, boolean)` var.
- `cfg_pcode_ortusme.py` (gösteri): `cfg.json` (blok, kenar, komut adı) ile `pcode.jsonl` (seçici op, yüksek düzey değişken) farklı içerik; ortak olan yalnız fonksiyon kimliği (13 553 / 13 559). Biçim israfı: `cfg.json` `indent=2` 128,3 MB ↔ sıkı 65,7 MB (oran 0,51). `static/ghidra_*.json` ikinci kopyaları 11 dosya 202,7 MB.
- `taban_ayrinti.py`: Ghidra köprüsü 119 ikilide toplam duvarın %36,5'i; ikili başına JVM + içe aktarma + fonksiyon listesi ortanca 8,2 sn (çeyrekler 6,7 / 10,0; en çok 22,9).
- `pyproject.toml`: orjson bağımlılık değil (ortamda 3.11.9 kurulu). Eklenmesi karar ister.
- Python 3.12 `os.PRIO_DARWIN_THREAD / PROCESS / BG` var; `taskpolicy -c` mevcut (QoS kıskacı).
- BULGULAR §0–§2 yazıldı (13:11); §3–§6 profil ve havuz / GC ölçümünü bekliyor.

## 13:20 — kalem 3: Ghidra'sız profil (seri kip, mac/tmux kopyası)

- Komut: `PYTHONHASHSEED=0 PYTHONDONTWRITEBYTECODE=1 python scripts/arge/hiz/profil_yeniden.py --kaynak ~/karadul_olcum/runs/urun-onarim-a62f15e/mac/tmux/ws/workspaces/tmux/20261119_052129 --hedef ~/karadul_olcum/runs/arge-2026-11-19/hiz/profil/mac_tmux_seri --seri --referans ~/karadul_olcum/runs/onarim-2026-11-19/P12d/yeniden_taban/mac/tmux/ws/workspaces/tmux/20261119_052129/reconstructed/src/naming_map.json` (12:59 → 13:16; yük ~34).
- Yöntem denetimi: P12d'nin `agac_taban` ağacı bugünkü `karadul/` ile aynı (`diff -rq`: yalnız `.DS_Store` ve izlenmeyen boş dizinler). Seri kipin ad haritası referansla **bayt aynı** (sha256 56233eb0…). Seri yürütücü çıktıyı değiştirmedi.
- A istihbarat 21,8 / 5,1 sn; B deobfuscate 24,9 / 5,1 sn; **C yeniden kurma 953,3 sn duvar / 746,8 sn işlemci**.
- C içinde: `feedback_loop` 780,3; `c_naming` iter0 427,8 + iter1 274,6 = 702,4 sn (%73,7); `deep_tracing` 36,2; `algorithm_id` 26,6; `binary_prep` 19,8 (soğuk önbellek: kendi `KARADUL_CACHE_DIR`'im boş; tabanda 0,48).
- **Düzenli ifade derlemesi 480,8 sn kümülatif** (`re._compile`; 3 681 079 gerçek derleme; 12,26 M `re.escape`). Çağıranlar (`profil_cagiranlar.py`): `c_namer._strategy_local_var_naming` (`:4409-4413`) 3,06 M derleme 298,0 sn; `_strategy_dataflow` (`:3902-3907`) 0,72 M / 61,2 sn; `api_param_db.reverse_propagate_function_names` (`:511-519`) 11 272 / 56,6 sn; `propagate_params` (`:396-399`) 6 775 / 51,6 sn. İlk ikisi her (değişken, desen) çifti için yeni desen kuruyor; son ikisi çağrıdan bağımsız sabit dev deseni her çağrıda kuruyor. `re` önbelleği (512) taşıyor.
- Satır araması: `_line_search` (`:4356`) 405 M `search` / 106,9 sn; (`:3873`) 92,6 M / 10,7 sn. `_LOCAL_VAR_USAGE_PATTERNS` 125 desenin hepsinde `PARAM` bir kez ve zorunlu konumda → "adı içeren satır" ön süzgeci çıktıyı değiştirmez (`_PARAM_USAGE_PATTERNS` için pakette ayrıca denetlenecek).
- Dosya: `_io.open` 122 041 çağrı 134,1 sn (%14,1). Okuma (`read_text`) 96 338 / 135,4 sn; yazma (`write_text`) 20 789 / 1,9 sn. `binary_prep._build_file_cache` (`binary_prep.py:130`) zaten bütün `.c`'leri okuyor (19,8 sn) ama çoğu adım diskten yeniden okuyor: `c_algorithm_id._analyze_file` 21,3; `engineering/analyzer._analyze_file` (3 × 2 821) 12,1; `stages._recover_main_from_entry` (`stages.py:1816`) 11,8; `c_namer._read_and_extract` 11,3 + `_rename_one` 7,1; `tarif/kesin.load_static` 8,3; `signature_db.match_all` 6,7; `c_type_recoverer` üç yer 11,9; `ngram` 4,8; …
- Paralel ↔ seri adım karşılaştırması (taban 10 işçi yük altında ↔ seri + cProfile yük altında; aynı koşul değil, yalnız yön): `project_build` 30,3 ↔ 3,0; `engineering_annotation` 15,4 ↔ 4,6; `semantic_naming` 12,7 ↔ 6,4 → paralel kipte havuz kurulumu işin kendisinden pahalı olabilir. Havuz sayacı koşusu (işçi 2) bunu ölçecek.

## 13:25 — gösteri koşusu bitti (CIKIS 3, BITTI 13:20:12)

- `zaman_cizelgesi.py gosteri` yeniden koşuldu (aşama payları bölümü eklendi). Toplam 7 729,1 sn (`pipeline_result`); `time -l`: real 7 761,62, user 8 050,11, sys 447,04 sn; azami RSS 4 680 646 656 B; tepe bellek ayak izi 5 827 663 560 B.
- Paylar: Ghidra köprüsü 3 815,4 (%49,4; BSim %25,3, CFG %7,8, decompile %6,8, xref %4,5, ilk adım %4,1); statik Ghidra dışı 897,0 (%11,6; istihbarat 879,8); deobfuscate 663,5 (%8,6); yeniden kurma 2 353,1 (%30,4): `feedback_loop` 1 315,8 (%17,0; `c_naming_iter0` 939,8 = %12,2; `xtride_typing` 150,5; `ngram` 117,6), `deep_tracing` 260,9, `project_build` 245,7, `kesin_anchors` 173,4, `parallel_algo_eng` 157,9, `binary_prep` 153,5 (dosya önbelleği kurulumu), `algorithm_id` 110,9, `ghidra_metadata` 95,6, `inline_detection` 92,8.
- `feedback_loop` TEK tur: tur 1 311,2 sn > `pipeline_iteration_timeout` 600 → `iteration_timeout`; 23 yeni ad.
- Çıkış 3 nedeni: evrensel ikilide Go dilimi tanındı ama Go analizcisi şişman dosyayı açmıyor (hızla ilgisiz; ÜST VERİ / yayın G4).
- Deobfuscate istatistiği: 13 554 dosya, `opaque_predicates_found` 10 060.

## 13:25 — havuz sayacı, düşük yükte açma, GC

- Havuz sayacı koşusu: `PYTHONHASHSEED=0 PYTHONDONTWRITEBYTECODE=1 KARADUL_CACHE_DIR=…/mac_tmux_havuz_cache python scripts/arge/hiz/profil_yeniden.py --kaynak <mac/tmux ws> --hedef ~/karadul_olcum/runs/arge-2026-11-19/hiz/profil/mac_tmux_havuz --havuz-say --isci 2 --asamalar C --referans <P12d naming_map>` (13:19 → 13:23; yük 2,6 → 4,9). Yeniden kurma 261,6 sn duvar / 144,8 sn ana süreç işlemcisi. **Ad haritası referansla aynı** (2 işçi ↔ 10 işçi: işçi sayısı çıktıyı değiştirmiyor).
- 25 havuz kuruldu (10 süreç havuzu: `engineering/analyzer.py:465` ×3, `c_namer.py:2285` ×2, `c_type_recoverer.py:1342` ×2, `:1471` ×2, `semantic_namer.py:2793` ×1); süreç havuzunda ilk sonuç gecikmesi 0,18–1,38 sn (2 işçi, düşük yük). `c_namer` havuzu tur başına yeniden kuruluyor (ömür 52,3 / 51,6 sn).
- `project_build` 36,2 sn (seride 3,0): `runner.py:332` iş parçacığı düzeyinde `deep_tracing` (36,9 sn) ile aynı anda koşup GIL paylaşıyor; aynı düzeyin havuzu "ilk sonuç 36,2 sn, ömür 36,88". Paralel adım düzeyleri işlemci yoğun Python adımlarında hız kazandırmıyor ve adım sürelerini birbirine karıştırıyor (taban koşusundaki `project_build` 30,3 sn aynı yapı). Ölçüm uyarısı: `*_duration_s` paralel düzeyde toplanamaz.
- `c_naming` 2 işçide iter0 64,6 + iter1 62,6 = 127,2 sn (yeniden kurmanın %49'u).
- Düşük yükte açma (yük 4,9; `acma_gecikmesi.py`): taban `debian/tree` .c ortanca 0,590 ms (p99 4,49); kendi kopyam 0,867 ms (p99 2,38); YENİ oluşturma 0,041 ms; depodaki .py 0,930 ms (yükte 31,0); zoneinfo 0,365 ms (yükte 0,51). Yük kuyruğu büyütüyor ama var olanı açma ↔ yeni oluşturma oranı (~15–20×) düşük yükte de sürüyor.
- GC (`gc_maliyeti.py --jsonl <gösteri pcode.jsonl>`): 13 553 fonksiyon, 9 022 399 izlenen kap; kurulumda gen2 15 kez 3,74 sn (kurulum 5,09 sn); tek tam toplama 0,82 sn; `gc.freeze()` sonrası ~0. Gösteri decompile adımına (523,9 sn) göre küçük (~%1, TAHMİN).

## 13:31 — kapanış

- Yazılanlar: `BULGULAR.md` (§0–§7), `PLAN.md` (HZ-0 … HZ-9; §5 çakışma, §6 kararlar), `BERKE.md`.
- Plan yolları mekanik denetlendi: `python scripts/arge/hiz/plan_yol_denetimi.py docs/arge/2026-11-19_mythos/hiz/PLAN.md` → var 50, yeni (işaretli) 33, işaretsiz eksik 0, satır aşımı 0.
- Kalem durumu: 1 zaman çizelgesi ✓ (gösteri bitti, tam kırılım); 2 sıcak noktalar ✓; 3 Ghidra'sız profil ✓ (seri + havuz sayacı; ad haritası iki koşuda da referansla aynı); 4 seçenekler ✓ (genel / melez çekirdek ayrımıyla; donanım benzetimi + oops ölçümü); 5 gereksiz iş ✓; 6 öncelik tablosu ✓; 7 PLAN ✓; 8 çakışma ✓.
- Yapılamayan / bilerek bırakılan: Ghidra koşusu gerektiren her ölçüm (işçi sayısı 6/9/12, JFR, çözümleyici süreleri, boş makine tabanı) → HZ-0. Avast dışlama denemesi → Berke'nin kararı (K-HZ-1). İkinci turun çıktıya etkisi → HZ-7c.
- Başka hat için notlar: (ÖLÇEK) gösteride `feedback_loop` 600 sn tur sınırına takılıp tek tur koştu — büyük ikilide tur sınırı fiilen bir bütçe; (ÖLÇEK / ÖLÇÜ) `*_duration_s` paralel düzeyde toplanamaz (`project_build` 30 sn GIL paylaşımı); (yayın G3) çözümleyici süreleri kaydedilmiyor, HZ-1 kaydeder.
- Neden olmadı / dikkat: JSON yazımı ilk şüpheydi (saf Python kodlayıcı) ama ölçünce küçük çıktı (128 MB 3,4 sn); JPype geçişinin kendisi de ucuz çıktı (0,7–2 µs). Asıl israf düzenli ifade derlemesi ve tekrar tekrar dosya açma.
