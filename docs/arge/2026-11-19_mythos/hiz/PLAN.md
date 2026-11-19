# HIZ — plan (tur 1 sonrası, 2026-11-19)

Bu belge kendi başına uygulanabilir yazıldı: uygulayan Opus ajanları bu turun oturumunu görmeyecek. Kanıt ve sayılar `BULGULAR.md`'de, çalışma günlüğü `DEFTER.md`'de. Araştırma betikleri `scripts/arge/hiz/`, çıktıları `~/karadul_olcum/runs/arge-2026-11-19/hiz/`.

## 0. Bir bakışta

**Soru.** "M silikonlarda daha nasıl hızlandırırız?" — Berke'nin kapsam düzeltmesiyle: **her makinede**, değerler o makinenin donanımından türetilerek. ÖLÇEK planı neyin hiç koşmayacağını / önbelleğe alınacağını ele alıyor; bu plan **koşan adımı aynı makinede hızlandırır**.

**Hipotez.** Bugünkü sürenin büyük kısmı hesaplamadan değil, hesaplamanın etrafındaki işten geliyor: (1) aynı işi birden çok kez yapmak (BSim'in iki ek decompile'ı, başvuru verisinin üç kez gezilmesi, sonuç üretmeyen ikinci `feedback_loop` turu, atılan disassembly alanları, iki kez yazılan JSON), (2) Python ↔ Java sınırını öğe başına geçmek (gösteride ≥ 115 M geçiş), (3) iş dağıtımının statik olması (ardışık decompile parçaları, her adımda yeniden kurulan süreç havuzları), (4) on binlerce küçük dosyanın tekrar tekrar açılması (bu makinede açma başına ortanca 0,6–2,8 ms). Bunların hepsi platformdan bağımsızdır; Apple silikona özgü kısım (başarım / verim çekirdeği, QoS, birleşik bellek) yalnız işçi sayısı ve yığın formülünde ve dengesizliğin büyüklüğünde ortaya çıkar.

**Literatürün beklediği cevap / aykırı öncül:** bu pakete uygulanmaz (`ORTAK_BRIF.md`, `HIZ.md`).

**Ölçüt ve doğrulayıcı.** Her paket için: (a) **aynı makinede** önce / sonra süre ORANI, boş makinede (tanım §1) üç tekrarın ortancası; (b) çıktı eşitliği: Ghidra çıktıları JSON-eşit (zaman ve mutlak yol alanları hariç, alan listesi pakette), `.c` dosyaları bayt-eşit, `naming_map.json` bayt-eşit; çıktıyı değiştirmesi beklenen pakette yerine `urun_olc` ad ölçümü (tam eşitlik ve tam + biçim; KARARLAR A-3) değişmedi. Her ölçüm kaydına donanım künyesi (§1).

**Paket sırası:**

```
Dalga 0  HZ-0 boş makinede taban ölçümü (E1)            [ÖLÇEK ÖLÇ-A koşucusuna yaslanır; ÖLÇ-1 ile birlikte koşulabilir]
Dalga 1  HZ-7a desen önbelleği (c_namer, api_param_db)   ║ HZ-1 ölçüm kancaları (headless, macho)
         [HZ-7a: ÖZ KOD ÖK-2 / ÖK-3 ve P12d ile c_namer.py'de SIRALI]
Dalga 2  HZ-5 donanım künyesi + formüller (config.py, headless.py JVM argümanları, sabit yerleri)
Dalga 3  HZ-2 BSim hızlı yol [ÖLÇEK ÖL-2'den SONRA]       ║ HZ-6 Ghidra sonrası dosya işleri
         (sonra) HZ-7b metin önbelleği [HZ-7a'dan SONRA]
Dalga 4  HZ-3 decompile hattı [HZ-5 ve HZ-1'den SONRA; headless.py]
Dalga 5  HZ-4a döküm tek geçiş [HZ-3'ten SONRA; ÖLÇEK ÖL-3 adım 2–3'ün yerine; KİMLİK PK-8 ile sıralı]
         ║ HZ-7d süreç havuzları [HZ-7b'den SONRA]
Dalga 6  HZ-7c ikinci tur ön sınaması (önce ölçüm)  ║  HZ-4b (KOŞULLU)  ║  HZ-8 (KOŞULLU)
Dalga 7  HZ-9 sonra ölçümü (HZ-0 ile aynı hedef, aynı koşucu)
```

`║` = paralel koşabilir (dosya kümeleri ayrık). Aynı anda en çok 2 kod paketi + 1 ölçüm; **aynı anda en çok 1 Ghidra koşusu**; ölçüm koşusu yapılırken başka ağır iş yok.

**İlk yapılacak kod paketi HZ-7a'dır:** en az emek (iki dosya, birkaç işlev), çıktı bayt eşit, her boyutta kazanç (TAHMİN uçtan uca −%6–10), Ghidra gerektirmeden yeniden oynatmayla ölçülür.

**Durma ölçütü (hat için).** HZ-2 + HZ-3 + HZ-4a + HZ-6 + HZ-7a/b/d sonrasında HZ-9'da üç hedefin üçünde de uçtan uca oran ≥ 0,85 ise (kazanç < %15) Python tarafı daha fazla zorlanmaz; kalan süre Ghidra'nın kendi işidir (otomatik analiz, decompiler) ve yalnız ÖLÇEK'in bütçe / tembel derinlik yoluyla azaltılır.

## 1. Ortak kurallar

- Depo kökünden `PYTHONDONTWRITEBYTECODE=1 python -m …` / `python scripts/…`. Kabuk zsh: komutu ya da listeyi değişkende tutma.
- Kilitli setler (`targets/test_seti/`, `targets/dogrulama_seti/` ve koşu çıktıları) açılmaz, listelenmez.
- Ön kayıt metni ölçümden ÖNCE commit'lenir: `docs/arge/2026-11-19_mythos/hiz/on_kayit_<paket>.md` (her pakette hazır metin var). Tutmayan beklenti silinmez.
- Sayılar betikten; kazanç öngörüsü TAHMİN etiketli ve aralıklı.
- Mutasyon: `PYTHONDONTWRITEBYTECODE=1 python scripts/mutation_probe.py --spec scripts/measurement/mutation_specs_<paket>.json`. Mutantın `find` metni dosyada tekil, `replace` metni farklı uzunlukta; aynı worktree'de eşzamanlı mutasyon yok.
- Tam takım: `python -m pytest -q` (0 hata).
- Bayraklar ve **bütün sayısal sabitler** `karadul/config.py`'de (proje kuralı: aynı sayı iki dosyada yazılmaz); okunmayan alan `INERT_SETTINGS`'e yazılır (`tests/test_p15a_etkisiz.py::test_every_unread_field_is_registered`).
- Git: commit'i ana oturum atar; `Co-Authored-By` satırı yok. Sürüm numarasını ana oturum belirler.
- **Boş makine tanımı:** ölçüm boyunca başka Karadul / Ghidra / ajan koşusu yok; koşu başında ve sonunda 1 dk yük ortalaması `< 0,25 × os.cpu_count()` (künyeye yazılır; aşılırsa tekrar geçersiz sayılır ve yinelenir).
- **Donanım künyesi** (her ölçüm kaydında; `scripts/arge/hiz/profil_yeniden.py` `_donanim()` alanları + fazlası): `machdep.cpu.brand_string`, `hw.nperflevels`, her düzey için `hw.perflevelN.physicalcpu` / `logicalcpu` / `l2cachesize`, `hw.memsize`, `sw_vers`, Python / JPype / pyghidra / JDK sürümü, Ghidra sürümü, etkin sistem uzantıları (`systemextensionsctl list`), yük ortalaması, ölçüm öncesi küçük dosya açma ortancası (`scripts/arge/hiz/acma_gecikmesi.py --oku <ws>/static/ghidra_output/decompiled --n 1000`). Başka platformda karşılıkları (`/proc/cpuinfo`, `lscpu`, `nproc`, `free -m`; Windows `wmic cpu`, `systeminfo`).
- **Kabul ölçütleri oranla:** "önce" = aynı makinede, aynı ürün ağacında (`git archive` ile `~/karadul_olcum/urun-<commit>`), aynı hedefte, değişiklik öncesi koşu. Mutlak saniye yalnız künye için.
- **S8 alt kümesi** (çıktı eşitliği; ÖLÇEK planıyla aynı küme): `~/karadul_olcum/runs/urun-onarim-a62f15e/{debian/coreutils/cat, debian/coreutils/sort, debian/tree/tree, debian/sqlite3/sqlite3, debian/htop/htop, debian/tmux/tmux, debian/zstd/zstd, mac/tmux}` çalışma alanlarının `raw/` kopyaları. Önce / sonra aynı `KARADUL_CACHE_DIR` düzeniyle (koşu başına boş). BSim'e dokunan paketlerde ek senaryo: S8 aynı sırayla **ortak** depoyla (taban koşusundaki gibi; ilk ikiliden sonra depo dolu).
- **HZ hedefleri:** K = `debian/coreutils/sort` (625 fn), O = `mac/tmux` (2 821 fn), B = gösteri dilimi `~/karadul_olcum/runs/gosteri-2026-11-19/ollama/girdi/Ollama` (arm64 dilimi otomatik; 13 559 fn; MIT). Hepsi makinede, indirme yok.

## 2. Paketler

### HZ-0 — Boş makinede taban ölçümü (E1; yalnız ölçüm)

**Amaç.** Öbür paketlerin "önce" sayısı; yük altında ayrılamayan üç sorunun cevabı: (i) büyük ikilide döküm adımlarının doğrusal üstü büyümesi yükten mi, (ii) "Python Reference Queue" iş parçacığının 2 261 sn'si neyle orantılı, (iii) küçük dosya açma maliyeti boş makinede ne.

**Önkoşul.** ÖLÇEK ÖLÇ-A (`scripts/measurement/olcek_kos.py`, ÖLÇEK'in yeni betiği) yazılmış ve testleri geçmiş olmalı. Yoksa bu paket bekler (koşucu iki kez yazılmaz).

**Dokunacağı dosyalar.** `scripts/arge/hiz/hz0_ek.py` (yeni: koşuya eşlik eden ek örnekleyici), `docs/arge/2026-11-19_mythos/hiz/HZ0.md`, `on_kayit_hz0.md` (yeni); veri `~/karadul_olcum/runs/hiz-taban-<commit>/<hedef>/<tekrar>/`.
**Dokunmayacağı.** Ürün kodu, testler, `scripts/measurement/*` (yalnız çağrılır).

**Adımlar.**
1. Ürün ağacını sabitle: `git archive <commit> | tar -x -C ~/karadul_olcum/urun-<commit>` (ÖLÇ-1 aynı ağacı kullanıyorsa onu kullan).
2. `hz0_ek.py` yaz: verilen PID için 30 sn'de bir `ps -M` iş parçacığı işlemci süreleri (`scripts/arge/hiz/is_parcacigi.py`'deki ayrıştırma içe aktarılır), koşu başında ve sonunda `acma_gecikmesi.py --oku … --n 1000` ve donanım künyesi; çıktı `<kök>/hz0_ek.json`. Ürünü sarmaz, yalnız izler.
3. Ön kaydı commit'let.
4. Boş makinede, her hedef 3 tekrar, sırayla K1 O1 B1 K2 O2 B2 K3 O3 B3: `olcek_kos.py --agac <ağaç> --hedef <hedef> --kok <kök>/<hedef>/<n> --duvar-sn 10800` + aynı anda `hz0_ek.py --pid <karadul pid>`. Her koşu boş `KARADUL_CACHE_DIR`.
5. Ek koşu (medyana girmez): B için bir kez `JAVA_TOOL_OPTIONS="-XX:StartFlightRecording=filename=<kök>/B_jfr/kayit.jfr,settings=profile,dumponexit=true -Xlog:gc*:file=<kök>/B_jfr/gc.log:time,uptime"`. Çözüm: `jfr print --events jdk.ExecutionSample <kayit.jfr>` → en sık 30 Java yığın çerçevesi (çağrı grafı, xref, CFG, BSim aralıklarında ayrı ayrı; aralıklar `ghidra_output/*.json` zamanlarından); `jdk.ThreadCPULoad` ile "Python Reference Queue" iş parçacığının yükü zamana göre. K ve O için ayrıca `scripts/measurement/p16c_sure.py kos --kok <kök>/p16c --etiket hz0 --yalniz debian/coreutils/sort --yalniz mac/tmux` (çözümleyici başına otomatik analiz süreleri; ürün kodu değişmez).
5b. AppCDS kolu (medyana girmez, kod değişmez): K için `JAVA_TOOL_OPTIONS="-XX:+AutoCreateSharedArchive -XX:SharedArchiveFile=<kök>/cds/karadul.jsa"` ile 4 koşu; ilki arşivi kurar, 2–4'ün ortancası ilk Ghidra adımının (JVM + içe aktarma + fonksiyon listesi − otomatik analiz) önce / sonra oranı için kullanılır. JDK 21'de bayrak var (`java -XX:+PrintFlagsFinal -version | grep AutoCreateSharedArchive`).
6. Zaman çizelgesi: `python scripts/arge/hiz/zaman_cizelgesi.py gosteri --kok <kök>/<hedef>/<n> --cikti <kök>/<hedef>/<n>/zaman` (betik `BASLADI` yoksa `kunye.json` başlangıcını kullanmalı; gerekirse küçük ek), `taban_ayrinti.py` ile ölçekleme eğimi (K, O, B üç nokta).
7. Berke onaylarsa (karar §6): Avast'ta yalnız `~/karadul_olcum/runs/hiz-taban-<commit>/` için dışlama ekli iken K ve O'yu 3'er tekrar daha koş → erişimde taramanın payı. Onay yoksa adım atlanır ve kayda geçer.
8. `HZ0.md`: hedef × aşama × adım tablosu (ortanca, en küçük, en büyük), tepe RSS, JVM GC duraklama toplamı, açma gecikmesi, iş parçacığı işlemcisi, JFR sıcak çerçeveleri; ön kayıtla kıyas.

**Kabul ölçütü.** 9 koşunun 9'unun künyesi eksiksiz; her hedefte üç tekrarın (en büyük − en küçük) / ortanca ≤ 0,10 (aşarsa en çok 2 tekrar daha). JFR kaydı açılabiliyor.
**Ön kayıt (`on_kayit_hz0.md`).**
- H0-a: B'de BSim Ghidra köprüsünün ≥ %40'ı (yük altında %51,2).
- H0-b: K'de toplam duvarın en büyük kalemi `feedback_loop`.
- H0-c: B'de CFG ms / fonksiyon, O'nunkinin ≥ 3 katı (yük altında 44,3 ↔ 2,2). Tutmazsa doğrusal üstü büyüme yük kaynaklıydı → HZ-4b'nin önceliği düşer.
- H0-d: JFR'de CFG ve xref aralıklarındaki örneklerin ≥ %50'si Ghidra program veritabanı / blok modeli çerçevelerinde (`ghidra.program.database.*`, `ghidra.program.model.block.*`), < %20'si JPype çerçevelerinde. Tutarsa darboğaz Java tarafının işidir (HZ-4a / HZ-4b sayıyı azaltarak kazandırır); tutmazsa geçiş maliyetidir.
- H0-e: boş makinede var olan `.c` açma ortancası ≥ 0,3 ms (Avast etkin). Tutarsa HZ-6'nın önceliği yükselir.
**Sınama beklentisi.** Kod değişmez.
**Bayrak.** Yok.

### HZ-1 — Ölçüm kancaları (çıktıyı değiştirmez; yalnız durum dosyalarına alan)

**Amaç.** Bugün dosya zamanlarından çıkarılan süreler ürünün kendi kaydına girsin; Ghidra'nın çözümleyici başına süreleri kaybolmasın (`headless.py:713` hesaplıyor, `macho.py:1124-1146` yazmıyor). Her makinede yinelenebilir ölçüm için.

**Dokunacağı dosyalar.** `karadul/ghidra/headless.py` (`_analyze_pyghidra`, 267–630: her adımın `time.monotonic()` süresi `adim_sureleri` sözlüğüne; `_parallel_decompile_java_threads`, 1185–1307: parça / iş başına süre özeti), `karadul/analyzers/macho.py` (`_record_ghidra_outcome`, 1103–1155: `analysis` ve `adim_sureleri` alanları `ghidra_status.json`'a), `tests/test_hz1_olcum_kancasi.py` (yeni), `scripts/measurement/mutation_specs_hz1.json` (yeni).
**Dokunmayacağı.** Adımların gövdeleri; `ghidra_output/*.json` içerikleri; `pipeline_result.json` şeması.

**Adımlar.**
1. ÖLÇEK ÖL-1 (ilerleme olayları) önce girdiyse onun adım başlangıç / bitiş noktalarını kullan; ikinci bir zamanlayıcı ekleme.
2. `_analyze_pyghidra` her adım için süre: `functions`, `strings`, `call_graph`, `decompile`, `types`, `xrefs`, `pcode`, `cfg`, `function_id`, `bsim_ingest`, `bsim_query`, `combined`. Sonuç sözlüğüne `adim_sureleri`.
3. `_record_ghidra_outcome`: `status["analysis"] = ghidra_result.get("analysis")` (durum, süre, `analyzer_times`, `disabled_analyzers`), `status["adim_sureleri"]`.
4. Decompile özeti: parça sayısı, parça başına süre (en küçük / ortanca / en büyük).
5. Testler: sahte program / sahte JVM (`tests/test_p16c_analiz_suresi.py`'deki kalıp) ile alanların varlığı ve türü; alanlar dışında `ghidra_status.json` aynı.
6. Mutasyon (3–4 mutant).

**Kabul ölçütü.** S8'de `ghidra_output/*.json`, `.c`, `naming_map.json` eşit; `ghidra_status.json`'da yalnız yeni alanlar fark; süre oranı ≤ 1,01 (ek iş yok sayılır).
**Ön kayıt.** "S8 8 / 8 çıktı eşit; `analyzer_times` 8 / 8 dolu."
**Sınama beklentisi.** `tests/test_p16a_ghidra_sonuc.py`, `tests/test_p16c_analiz_suresi.py`, yeni testler geçer; tam takım 0 hata.
**Bayrak.** Yok.

### HZ-5 — Donanım künyesi; işçi, iş parçacığı ve JVM yığını formülleri (genel)

**Amaç.** Bütün işçi / iş parçacığı / yığın değerleri çalışma anında algılanan donanımdan, `config.py`'deki tek bir formülden türetilsin. Bugünkü kusurlar (BULGULAR §4.1): yığın tavanı 32 768 MB sıkıştırılmış göstericileri kapatıyor; Windows'ta bellek algılanmıyor (yığın hep 4 096 MB); 8 GB'ta yığın belleğin %50'si; verim çekirdeksiz / perflevel'siz makinede `0.7 × cpu_count` sezgisi; cgroup CPU kotası okunmuyor; 8 yerde düz sabit.

**Dokunacağı dosyalar.** `karadul/config.py` (127–222: `_detect_cpu_cores`, `_detect_available_memory_mb`, `CPU_PERF_CORES`, `TOTAL_MEMORY_MB`, `GHIDRA_HEAP_MB`; yeni `DonanimKunyesi` + formül işlevleri), `karadul/ghidra/headless.py` (45–100 JVM argümanları; 2478 ve 2513–2515 CLI yedeği), `karadul/analyzers/binary_intelligence.py` (2181), `karadul/computation/struct_recovery/solver.py` (41, 674–681), `karadul/reconstruction/c_type_recoverer.py` (1330, 1455), `karadul/batch.py` (33, 389), `karadul/cli.py` (1653), `karadul/pipeline/runner.py` (25: değer korunur, yalnız `config.py`'ye taşınır), `tests/test_hz5_donanim.py` (yeni), `scripts/measurement/mutation_specs_hz5.json` (yeni).
**Dokunmayacağı.** `karadul/pipeline/steps/parallel_algo_eng.py:63` (`max_workers=2`: iki adımı paralel koşturur; donanım değil iş sayısı), işçi kullanan algoritmaların gövdeleri.

**Formüller (sabitler yalnız `config.py`'de; adlar öneri):**
- Çekirdek algılama: macOS `hw.nperflevels`; `basarim = hw.perflevel0.physicalcpu`, `verim = Σ hw.perflevel{1..n-1}.physicalcpu` (düzey sayısı değişebilir); perflevel yoksa `basarim = os.cpu_count()`, `verim = 0`. Linux: `/sys/devices/cpu_core/cpus` ve `/sys/devices/cpu_atom/cpus` (Intel melez) ya da `/sys/devices/system/cpu/cpu*/cpu_capacity` en büyük değerli küme (ARM big.LITTLE); yoksa hepsi başarım. Kullanılabilir mantıksal: `len(os.sched_getaffinity(0))` (Linux) / `os.cpu_count()`; cgroup v2 `cpu.max` kotası varsa `ceil(kota / dönem)` ile kırp. Windows: `GetLogicalProcessorInformationEx` `EfficiencyClass` (ctypes); başarısızsa hepsi başarım.
- Bellek: macOS `hw.memsize`; Linux `sysconf` ∧ cgroup (bugünkü gibi); Windows `GlobalMemoryStatusEx` (ctypes). Algılanamazsa uyarı + ayar zorunlu (sessiz 8 192 yedeği kaldırılır).
- `ISCI_YOGUN = max(1, basarim)` (Python süreç havuzları; işlemci yoğun).
- `ISCI_GECIKME = min(4 × mantiksal, 64)` (dosya okuma gibi beklemeli işler; G/Ç örtüşmesi).
- `DECOMPILE_IS_PARCACIGI = max(1, basarim + verim × V)`; `V` HZ-3 adım 5'te ölçülür (0 ya da 1), ölçülene dek 0 (bugünkü davranış).
- `JVM_AKTIF_ISLEMCI`: bugünkü `max(2, basarim)`; HZ-3'te "yok (JVM hepsini görür)" ile karşılaştırılır.
- `YIGIN_MB = min(YIGIN_OOPS_TAVAN_MB, max(YIGIN_TABAN_MB, int(YIGIN_ORAN × kullanilabilir_mb)), kullanilabilir_mb − REZERV_MB(kullanilabilir_mb))`, `kullanilabilir_mb = bellek_mb − ayrilmis_mb` (KaradulLM modeli gibi aynı birleşik belleği paylaşan başka süreç için ayardan), `YIGIN_OOPS_TAVAN_MB = 31744` (ölçüldü: `donanim_turetme.py --java …` → 31 744 MB'de `UseCompressedOops=true`, 32 767 ve 32 768 MB'de `false`), `YIGIN_ORAN = 0.4` (bugünkü), `REZERV_MB(m) = max(3072, int(0.3 × m))`, `YIGIN_TABAN_MB = 2048`. Örnek çıktılar (§4.1 tablosunun yeni sütunu testte sabitlenir): 8 GB → 3 276; 16 GB → 6 553; 36 GB → 14 745 (bugünle aynı); 128 GB → 31 744; Windows 32 GB → 13 107.
- Paralel Ghidra koşusu sayısı (`batch.py:389`, `cli.py:1653` bugün `min(…, 3)`): `max(1, min(ISCI_YOGUN, kullanilabilir_mb // (YIGIN_MB + REZERV_MB)))`.

**Adımlar.**
1. `DonanimKunyesi` (dataclass, `frozen`) + `donanim_kunyesi()` (modül düzeyinde bir kez; ortam değişkeniyle ezilebilir: `KARADUL_BASARIM_CEKIRDEK`, `KARADUL_BELLEK_MB` — testler ve benzetim için).
2. Formül işlevleri; `CPU_PERF_CORES`, `TOTAL_MEMORY_MB`, `GHIDRA_HEAP_MB` adları geriye uyum için kalır ama yeni işlevlerden gelir.
3. Sabit yerlerini formüle bağla (dosyalar yukarıda; `sabit_tarama.py` çıktısı denetim listesi).
4. Testler: `donanim_turetme.py`'deki on profil (yamalı `os.cpu_count`, `sysctl`, `sysconf`, cgroup, Windows) için beklenen değerler; `YIGIN_MB < 32768` her profilde; Windows'ta bellek algılanıyor (ctypes yamalı).
5. Künye: `pipeline_result.json` → `stages.static.stats.donanim` (çip, düzeyler, bellek, türetilen değerler).
6. Ölçüm: S8 ve O'da çıktı eşitliği; O'da süre oranı.
7. Mutasyon (formül sınırları, oops tavanı, Windows yolu, cgroup kırpması).
8. AppCDS (koşullu): HZ-0 adım 5b'de ilk adımın oranı ≤ 0,85 çıktıysa `_ensure_pyghidra_started`'a (`headless.py:70-83`) `-XX:+AutoCreateSharedArchive -XX:SharedArchiveFile=<KARADUL_CACHE_DIR>/jvm/karadul-<ghidra sürümü>-<jdk sürümü>.jsa` eklenir (bayrak `perf.jvm_cds`, öntanım açık); arşiv yolu sürüme bağlı olduğu için Ghidra / JDK değişince kendiliğinden yenilenir.

**Kabul ölçütü.** S8 8 / 8 ve O çıktı eşit (işçi sayısı çıktıyı değiştirmez: `c_namer.py:2276-2281` gönderim sırasıyla birleştiriyor; değişirse paket durur ve nedeni yazılır); O'da uçtan uca oran ≤ 1,03 (bu makinede değerler değişmediği için kazanç beklenmez); testler on profilde formülü sabitler.
**Ön kayıt (`on_kayit_hz5.md`).** "S8 + O 9 / 9 eşit; O oranı ∈ [0,95; 1,03]; 128 GB profilinde YIGIN_MB = 31 744 ve JVM `UseCompressedOops=true`."
**Sınama beklentisi.** `tests/test_p15a_etkisiz.py`, `tests/test_ghidra_jvm_headless.py`, `tests/test_p16c_analiz_suresi.py` (yığın testleri yeni formülle güncellenir), yeni testler; tam takım 0 hata.
**Bayrak.** `perf.ayrilmis_bellek_mb` (öntanım 0), `perf.decompile_verim_cekirdegi` (öntanım false), `perf.jvm_cds` (yalnız adım 8 açıldıysa).

### HZ-2 — BSim hızlı yol (çıktıyı değiştirmez)

**Amaç.** BSim koştuğunda (depo doluyken) iki ek decompile'ı bire ve tek iş parçacığından Ghidra'nın paralel taramasına indirmek. ÖLÇEK ÖL-2 boş depoda sorguyu atlıyor ve ingest'e bütçe koyuyor; bu paket bütçenin içinde kalan işi hızlandırır.

**Önkoşul.** ÖLÇEK ÖL-2 main'de (aynı dosya ve aynı blok: `headless.py:517-574`, `bsim.py`).
**Dokunacağı dosyalar.** `karadul/ghidra/bsim.py` (`_BSimNativeWrapper.ingest_program` 1234–1315, `query_functions` 1417–1491, `BSimDatabase.ingest_program` 1759–1819, `_query_functions` 1962–2077), `tests/test_hz2_bsim_hizli.py` (yeni), `scripts/measurement/mutation_specs_hz2.json` (yeni).
**Dokunmayacağı.** `karadul/pipeline/steps/bsim_match.py`, `_bsim_shadow.py`, eşleşme / dışlama mantığı (`_matches_from_notes` 1370–1415, `_Exclusion`), `headless.py` (ÖL-2 sonrası BSim bloğu değişmez).

**Adımlar.**
1. Ingest: `for func in …: gen.scanFunction(func)` (1263–1270) yerine `gen.scanFunctions(<Java Iterator>, n, monitor)` (Ghidra 12.1.2 `GenSignatures`; `javap` ile doğrulandı: `ParallelDecompileTask` → `DecompilerConcurrentQ`). Yineleyici `_iter_real_functions` (1141–1150) ile aynı küme ve sıra. `func_count` taranan fonksiyon sayısı olarak kalır (`manager.listAllFunctions()` sayısı; eski yolla aynı mı testte denetlenir).
2. Sorgu: aynı oturumda az önce ingest edildiyse ingest'in `DescriptionManager`'ı sorguya verilir (yeni `GenSignatures` kurulmaz); `_exe_already_ingested` doğruysa tek `GenSignatures` + `scanFunctions`. Eşleme (`getBase().getAddress()` → fonksiyon) aynı kalır.
3. Yedek: paralel tarama istisna atarsa bugünkü tekli yola düş (P16c'deki toplu → tekli düşüşü gibi), `status["scan_mode"]` = `parallel` / `serial_fallback`.
4. Testler (sahte JVM / sahte GenSignatures): aynı fonksiyon kümesi taranır; sorgu ingest yöneticisini kullanır; düşüşte tekli yol; eşleşme listesi ve sayaçlar eski yolla aynı.
5. Ölçüm (boş makine): (a) S8 sırayla ortak depoyla (taban koşusu senaryosu) önce / sonra; (b) B taze depoyla.
6. Mutasyon (4–6 mutant).

**Kabul ölçütü.** (a) S8 ortak depo senaryosunda `bsim_matches.json` ve `bsim_shadow.json` zaman alanları (`query_duration`, `bsim_detail.ingest_s`, `query_s`, `lock_wait_s`) ve yeni `scan_mode` dışında bayt eşit 8 / 8; `naming_map.json` eşit. (b) BSim adımı (ingest + sorgu) süre oranı O'da ≤ 0,5, B'de ≤ 0,4.
**Ön kayıt (`on_kayit_hz2.md`).** "Eşitlik 8 / 8; O oranı ≤ 0,5; B oranı ≤ 0,4." TAHMİN gerekçesi: sorgu tarafı ikinci decompile'ı bırakır (oran ≤ ~0,6), ingest paralel taramayla `DECOMPILE_IS_PARCACIGI` çarpanına yaklaşır; B'de bugün ingest 1 152 + sorgu 789 sn.
**Sınama beklentisi.** `tests/test_p16b_bsim.py`, `tests/test_p16c_bsim_toplu.py`, `tests/test_bsim.py`, yeni testler; tam takım 0 hata.
**Bayrak.** `bsim.paralel_tarama` (öntanım açık; kapalı = bugünkü yol).

### HZ-3 — Decompile hattı (çıktıyı değiştirmez)

**Amaç.** (1) Statik ardışık parçaların yük dengesizliğini kaldırmak (ölçüldü: openssl 5,62; sqlite3 2,31; zstd 1,60; htop 1,67), (2) decompile iş parçacığında GIL altında yapılan gereksiz geçişleri kaldırmak (atılan disassembly alanları; çağrı grafında zaten hesaplanmış arayan / çağrılan listesinin yeniden hesaplanması), (3) işçi sayısını ölçerek seçmek.

**Önkoşul.** HZ-5 (işçi formülü). HZ-4a'nın tek geçiş tablosu varsa adım 3 onu kullanır; yoksa adım 3'teki küçük önhesap bu pakette yapılır ve HZ-4a onu genişletir.
**Dokunacağı dosyalar.** `karadul/ghidra/headless.py` (`_extract_disassembly` 973–1026, `_extract_func_xrefs` 1029–1086, `_decompile_functions` 1129–1182, `_parallel_decompile_java_threads` 1185–1307, `_decompile_single_function` 1390–1591; çağrı grafında arayan / çağrılan önhesabı `_extract_call_graph` 882–970 yalnız EKLEME olarak), `tests/test_hz3_decompile.py` (yeni), `scripts/measurement/mutation_specs_hz3.json` (yeni).
**Dokunmayacağı.** `.c` dosya biçimi (başlık satırları, disassembly yorumları), `decompiled.json` / `pcode.jsonl` şeması, `_serial_decompile_fallback`, `_plan_decompile_filenames`.

**Adımlar.**
1. Dinamik dağıtım: iş parçacığı başına bir `DecompInterface` (iş parçacığına bağlı, bugünkü gibi); fonksiyonlar adres sırasıyla ortak kuyruktan küçük partilerle (parti boyu ayarda, öntanım 8) çekilir; sonuç dizinine konum indeksiyle yazılır → birleşik liste bugünkü adres sırasıyla aynı. Toplam süre sınırı (`deadline`) ve "parça düştü" kaydı korunur (parti düzeyinde).
2. Disassembly: `instr_entry`'den yalnız kullanılan alanlar (`address`, `text`); `getMnemonicString()` çağrısı istisna yolunu (`:989-993` `continue`) korumak için kalır; `getNumOperands` / `getDefaultOperandRepresentation` / `getDefaultValueRepresentation` kaldırılır.
3. Fonksiyon xref'i: `_extract_call_graph` aynı gezinmede fonksiyon başına `callers` (çağrı yeri dahil) ve `callees` (çağrı yeri dahil) listesini `{giriş adresi → kayıt}` sözlüğüne de yazar (ilk görülen tekilleştirme, `_extract_func_xrefs`'in kuralıyla aynı); decompile bu sözlükten okur. Sözlük yoksa (çağrı grafı adımı düştüyse) bugünkü `_extract_func_xrefs` çağrılır.
4. Testler (sahte program): yeni ve eski yolun `.c` metni ve sonuç kaydı eşit; parti sırası ters bitse de birleşik liste adres sırasında; çağrı grafı düşünce yedek yol.
5. İşçi sayısı ölçümü (boş makine, O ve B, 3 tekrar): `DECOMPILE_IS_PARCACIGI` formülünde `V = 0` ↔ `V = 1`; `JVM_AKTIF_ISLEMCI` bugünkü ↔ yok. Sonuç HZ-5 formülüne geri yazılır (ayrı küçük değişiklik, ana oturum onayıyla).
6. Ölçüm: S8 + B çıktı eşitliği ve decompile adımı süre oranı.
7. Mutasyon.

**Kabul ölçütü.** S8 + B `.c` bayt eşit, `decompiled.json` / `pcode.jsonl` JSON-eşit (alan dışı: `duration_seconds`, `decompiled_dir`, `jsonl_path`, `batch_size`, `total_batches`); decompile adımı süre oranı: dengesizlik ≥ 1,5 olan S8 ikililerinde (sqlite3, htop, zstd, tmux benzeri) ortanca ≤ 0,75; B'de ≤ 0,9.
**Ön kayıt (`on_kayit_hz3.md`).** "Eşitlik 9 / 9; dengesiz ikililerde ortanca oran ≤ 0,75 (TAHMİN 0,35–0,75); B ≤ 0,9 (TAHMİN 0,6–0,9: B'de parçalar dengeli, kazanç yalnız kaldırılan geçişlerden)."
**Sınama beklentisi.** `tests/test_p16a_decompile_sirasi.py`, `tests/test_headless_dosya_adi_yarisi.py`, `tests/test_ghidra_uyarilari_korunur.py`, `tests/test_decompile_all_parity.py`, yeni testler; tam takım 0 hata.
**Bayrak.** `analysis.decompile_parti_boyu` (öntanım 8; 0 = bugünkü statik parçalama).

### HZ-4a — Döküm adımları: tek başvuru geçişi ve yineleyiciler (çıktıyı değiştirmez)

**Amaç.** Çağrı grafı, xref ve CFG dökümlerinde Python ↔ Java geçiş sayısını azaltmak: gövdedeki her adres yerine yalnız başvurusu olan adresler; aynı başvuru verisini üç kez gezmek yerine bir kez; simge döngüsünde yineleyici yerine tek çağrı. ÖLÇEK ÖL-3'ün adım 2–3'ü bu pakete devredildi (ÖLÇEK PLAN §1 "HIZ'a bırakılır"); ÖL-3'ün akış biçimli yazım ve bellek kısmı ÖLÇEK'te kalır.

**Önkoşul.** KİMLİK PK-8 (`_extract_xrefs`'e `address_taken_by` alanı) ya önce girer ve bu paket alanı korur, ya da bu paketten sonra girer ve tek geçişin "giriş adresine başvuru" listesini kullanır. İkisi aynı anda yazılmaz. HZ-3 adım 3'ün sözlüğü varsa genişletilir.
**Dokunacağı dosyalar.** `karadul/ghidra/headless.py` (`_extract_call_graph` 882–970, `_extract_xrefs` 1717–1813, `_extract_cfg` 2025–2164), `tests/test_hz4_dokum.py` (yeni), `scripts/measurement/mutation_specs_hz4.json` (yeni).
**Dokunmayacağı.** JSON şemaları ve alan sıraları; `_save_output` ve akış biçimli yazım (ÖLÇEK ÖL-3); `karadul/ghidra/scripts/*` (CLI yolu).

**Adımlar.**
1. Başvuru tablosu (fonksiyon başına bir kez): `ref_mgr.getReferenceSourceIterator(body, True)` ile yalnız başvurusu olan adresler (adres sırası bugünküyle aynı: artan); her adreste `getReferencesFrom` bir kez; çağrı başvuruları (callee, çağrı yeri) ve veri başvuruları (dizgi adayı) ayrı listelere. `getReferencesTo(giriş)` bir kez: çağrı olanlar arayan listesine, olmayanlar PK-8 alanına.
2. Çağrı grafı ve xref dökümü bu tablodan kurulur; tekilleştirme kuralları ve sıraları değişmez (`:932-962`, `:1745-1776`).
3. Simge döngüsü (`:1792-1803`): `ref_mgr.hasReferencesTo(sym.getAddress())`.
4. CFG: fonksiyon başına `listing.getInstructions(body, True)` tek yineleyici; komutlar blok sınırlarına adres aralığıyla dağıtılır (bloklar `getCodeBlocksContaining` sırasıyla, bugünkü gibi); `mnemonics` ve `instruction_count` aynı.
5. Testler (sahte program, başvurusuz adresler dahil): eski ve yeni dökümler JSON-eşit; boş gövde; dış fonksiyon; aynı callee'ye birden çok çağrı.
6. Ölçüm: S8 + B JSON eşitliği; üç adımın süre oranı.
7. Mutasyon.

**Kabul ölçütü.** S8 + B `call_graph.json`, `xrefs.json`, `cfg.json` JSON-eşit 9 / 9; B'de üç adımın toplam süre oranı ≤ 0,5; S8'de ≤ 0,8.
**Ön kayıt (`on_kayit_hz4a.md`).** "Eşitlik 9 / 9; B oranı ≤ 0,5 (TAHMİN 0,2–0,6; adres başına çağrı sayısı 5,4 M adresten başvurulu adres sayısına iner — o sayı HZ-0'da `getReferenceSourceIterator` ile sayılır); S8 ≤ 0,8." H0-d tutmadıysa (darboğaz geçiş değil Java işi) beklenti "B ≤ 0,8"e çekilmez; tutmayan beklenti kayda geçer.
**Sınama beklentisi.** `tests/test_step_ghidra_metadata.py`, `tests/test_p16a_ghidra_sonuc.py`, yeni testler; tam takım 0 hata.
**Bayrak.** `analysis.dokum_tek_gecis` (öntanım açık; kapalı = bugünkü döngüler).

### HZ-4b — Java yardımcı sınıfı (KOŞULLU)

**Koşul.** HZ-4a'dan sonra B'de çağrı grafı + xref + CFG + decompile içi metadata hâlâ Ghidra köprüsünün ≥ %20'si ve HZ-0 H0-d "geçiş baskın" çıktıysa. Değilse paket açılmaz (kayda "gerekmedi" yazılır).
**Amaç.** Fonksiyon başına dökümü (başvuru tablosu, CFG blokları ve komut adları, disassembly metni, seçici pcode) tek Java çağrısında üretmek; Python yalnız sonucu (sıkı dizi / metin) sözlüğe çevirir.
**Dokunacağı dosyalar.** `karadul/ghidra/java/KaradulDokum.java` (yeni), `scripts/build_karadul_dokum_jar.sh` (yeni; `javac --release 21`, Ghidra jar'ları sınıf yolunda), `karadul/resources/ghidra/karadul-dokum.jar` (üretilen), `karadul/ghidra/headless.py` (`_ensure_pyghidra_started` 45–100: `launcher.add_classpaths(<jar>)`; döküm işlevleri jar varsa yardımcıyı, yoksa Python yolunu çağırır), uygulama paketleme betiği (jar'ın `.app`'e girmesi; dosya adı paketleme sahibinden alınır), `tests/test_hz4b_java.py`.
**Adımlar.** (1) Java tarafı yalnız ilkel dizi / metin döndürür; JSON'u Python kurar (biçim eşitliği Python'da kalır). (2) Jar yoksa ya da sürüm uyuşmazsa Python yolu (sessiz değil: `ghidra_status.json` `dokum_kipi`). (3) Ghidra 12.1.2 API'sine bağlı; sabitlenmiş Ghidra sürümü değişince jar yeniden derlenir (`GHIDRA_PINNED_VERSION`, `config.py:233`). (4) Testler gerçek Ghidra ister: `@pytest.mark.ghidra` ile; CI'da atlanır, ölçümde koşulur. (5) Ölçüm S8 + B.
**Kabul ölçütü.** S8 + B JSON / `.c` eşit; B'de hedeflenen adımlar HZ-4a sonrasına göre oran ≤ 0,5.
**Ön kayıt.** Paket açılırsa yazılır (HZ-4a sonrası sayılarla).
**Risk.** Derleme zinciri, `.app` paketleme, Ghidra sürüm bağı; bakım yükü.
**Bayrak.** `analysis.dokum_java_yardimci` (öntanım kapalı; ölçümden sonra karar).

### HZ-6 — Ghidra sonrası dosya işleri: deobfuscate ve istihbarat okuması (çıktıyı değiştirmez)

**Amaç.** Küçük dosya açma maliyetini (bu makinede ortanca 0,6–2,8 ms) örtmek ve açma sayısını azaltmak: deobfuscate'te `copytree` + yeniden yazım yerine tek yazım; okumaları beklemeli iş parçacıklarıyla örtüştürmek. Gösteride bu iki iş 880 + ≥ 664 sn.

**Önkoşul.** ÖLÇEK ÖL-3b (istihbarat bütçesi) ve yayın D2 (`binary_intelligence.py`) ile sıralı: bu paket yalnız `analyze_decompiled`'ın okuma kısmına dokunur; önce hangisi girdiyse öbürü üstüne kurar.
**Dokunacağı dosyalar.** `karadul/deobfuscators/binary_deobfuscator.py` (`deobfuscate` 102–286), `karadul/analyzers/binary_intelligence.py` (`analyze_decompiled` 2142–2205: yalnız okuma döngüsü 2168–2178; işçi sayısı 2181 HZ-5'in), `tests/test_hz6_dosya_isleri.py` (yeni), `scripts/measurement/mutation_specs_hz6.json` (yeni).
**Dokunmayacağı.** Dosya başına dönüşümlerin kendisi (`_clean_ghidra_artifacts`, `_mark_*`, string decryptor, opaque, CFF), `_analyze_single_file`, rapor şeması.

**Adımlar.**
1. Deobfuscate: `copytree` (149) kaldırılır; her `.c` kaynaktan okunur, dönüştürülür, hedefe bir kez yazılır (içerik bugünküyle aynı). Dosya izinleri ve dizin yapısı aynı (`.c` dışındaki dosyalar için `copy2` korunur).
2. Dosya başına işin okuma + yazma kısmı `ISCI_GECIKME` iş parçacığıyla (sonuçlar dosya adı sırasıyla toplanır; sayaçlar aynı); dönüşüm işlemcisi bugün dosya başına ~1,8 ms (profil) — süreç havuzu GEREKMEZ.
3. İstihbarat okuma döngüsü (2168–2178): aynı iş parçacığı havuzuyla paralel okuma; `work_items` sırası aynı.
4. Testler: eski ve yeni deobfuscate çıktısı bayt eşit (sahte dizin, 200 dosya; uyarı ve sayaçlar aynı); okuma hatası olan dosya yine hata listesinde.
5. Ölçüm: S8 + B `deobfuscated/decompiled` bayt eşit, `intelligence_report.json` JSON-eşit; deobfuscate aşaması ve istihbarat süre oranı.
6. Mutasyon.

**Kabul ölçütü.** Eşitlik 9 / 9; deobfuscate aşaması oranı B'de ≤ 0,5, O'da ≤ 0,7; istihbarat oranı B'de ≤ 0,8 (istihbaratın `analyze` kısmı ÖL-3b'nin).
**Ön kayıt (`on_kayit_hz6.md`).** "Eşitlik 9 / 9; deobfuscate B ≤ 0,5 (TAHMİN 0,2–0,5), O ≤ 0,7; istihbarat B ≤ 0,8." H0-e (boş makinede açma ≥ 0,3 ms) tutmadıysa beklentiler aynen kalır, tutmazlarsa kayda geçer.
**Sınama beklentisi.** `tests/test_deobfuscator.py`, `tests/test_deobf_honest_success.py`, `tests/test_binary_intelligence*.py`, yeni testler; tam takım 0 hata.
**Bayrak.** Yok (davranış aynı).

### HZ-7 — Yeniden kurma (dört alt paket; sırayla)

Dayanak: BULGULAR §3 (seri profil: yeniden kurmanın 953 sn'sinin 481 sn'si düzenli ifade derlemesi, 135 sn'si dosya okuması) ve §4.5 (havuz sayacı). `karadul/reconstruction/c_namer.py` ortak ve tehlikeli dosyadır (ÖZ KOD ÖK-2 / ÖK-3, ÜST VERİ, P12d): HZ-7a o paketlerle **sıralı** koşar ve yalnız aşağıda adı geçen işlevlere dokunur.

#### HZ-7a — Düzenli ifade deseni önbelleği ve satır ön süzgeci (çıktıyı değiştirmez) — İLK YAPILACAK KOD PAKETİ

**Amaç.** Aynı desenin milyonlarca kez derlenmesini ve her (ad, desen) için bütün satırların taranmasını kaldırmak.
**Dokunacağı dosyalar.** `karadul/reconstruction/c_namer.py` (yalnız `_strategy_dataflow` 3856–4008'deki `:3902-3907` döngüsü ve `_line_search` `:3873-3878`; `_strategy_local_var_naming` 4335–…'teki `:4409-4413` döngüsü, `:4443-4445` `_ret_capture_re` ve `_line_search` `:4356-4360`; modül düzeyinde yeni yardımcı `_ozel_desen(sira, kalip, ad)`), `karadul/reconstruction/api_param_db.py` (`propagate_params` 388–417: `call_re` örnek başına bir kez, tembel; `reverse_propagate_function_names` 481–…: `call_start_re` ve `fun_re` örnek başına bir kez), `tests/test_hz7a_desen_onbellegi.py` (yeni), `scripts/measurement/mutation_specs_hz7a.json` (yeni).
**Dokunmayacağı.** Desen listeleri (`_PARAM_USAGE_PATTERNS` `c_namer.py:1117`, `_LOCAL_VAR_USAGE_PATTERNS` `:1242`) ve içerikleri; aday güvenleri; karar kuralları; `_add_candidate`.

**Adımlar.**
1. `_ozel_desen`: anahtar (desen listesindeki sıra, `id` değil, `ad`) → `re.compile(kalip.pattern.replace("PARAM", re.escape(ad)))`; sözlük modül düzeyinde, süreç başına (işçi süreçleri kendi sözlüğünü kurar). Boyut sınırı: girdi sayısı ayarda (`perf.desen_onbellegi_ust_sinir`, öntanım 200 000; dolunca sözlük temizlenir — sonuç değişmez, yalnız yeniden derlenir). `re.error` yolu bugünkü gibi (`:4414-4419`: atla, günlüğe yaz) — hata da önbelleğe "derlenemedi" olarak girer.
2. Satır ön süzgeci: her ad için bir kez `satirlar = [ln for ln in body_lines if ad in ln]`; `_line_search` yalnız bu satırlarda arar. Koşul (testte denetlenir): listedeki her desende `PARAM` tam bir kez ve zorunlu konumda (bugün `_LOCAL_VAR_USAGE_PATTERNS` 125 / 125 doğrulandı; `_PARAM_USAGE_PATTERNS` için aynı denetim testte). Koşulu sağlamayan desen ön süzgeçsiz aranır.
3. `api_param_db`: `self._db` ve `self._callback_db` yalnız `__init__`'te kuruluyor (`:360-378`); desenler ilk kullanımda kurulup örnekte saklanır. Bir yöntem ileride `_db`'yi değiştirirse önbellek boşaltılır (yardımcı `_desenleri_sifirla()`; bugün çağıran yok).
4. Test: test içinde sabit dizgi olarak tutulan küçük C gövdeleri (elle yazılmış parçalar + geliştirme setinden, kilitli setlerden DEĞİL, 20 gövde) için eski ve yeni stratejinin aday listesi (ad, güven, sıra) eşit — eski davranış testte önbelleksiz yardımcıyla yeniden üretilir; `PARAM` koşulu iki listede; `re.error` veren ad; önbellek sınırı dolunca sonuç aynı.
5. Ölçüm (boş makine; Ghidra'sız yeniden oynatma yeterli): `profil_yeniden.py --havuz-say --isci <ISCI_YOGUN> --asamalar C` ile O ve B'nin çalışma alanları (B: gösteri `ws`'si kopyalanarak), önce / sonra 3'er tekrar; ayrıca `--seri` profille `re._compile` kümülatif payı.
6. Ürün koşusu: S8 çıktı eşitliği (`naming_map.json`, `naming_provenance.json`, `reconstructed/src/` bayt).
7. Mutasyon (desen anahtarına adı katmamak, ön süzgeci ters çevirmek, `re.error` yolunu düşürmek, api desenini her çağrıda yeniden kurmak → süre testi değil eşitlik testi öldürmeli).

**Kabul ölçütü.** S8 8 / 8 ve B çıktı bayt eşit; `c_naming` (iki turun toplamı) süre oranı O'da ≤ 0,5, B'de ≤ 0,6; seri profilde `re._compile` kümülatif payı ≤ %5 (bugün %50,5).
**Ön kayıt (`on_kayit_hz7a.md`).** "Eşitlik 9 / 9; `c_naming` oranı O ≤ 0,5, B ≤ 0,6 (TAHMİN 0,2–0,5); `re._compile` payı ≤ %5; uçtan uca oran K ≤ 0,95, O ≤ 0,92, B ≤ 0,93."
**Sınama beklentisi.** `tests/test_c_namer_determinism.py`, `tests/test_p12a_*.py`, `tests/test_c_namer*.py`, `tests/test_ad_gecerliligi.py`, yeni testler; tam takım 0 hata.
**Bayrak.** Yok (davranış aynı).

#### HZ-7b — `stat` doğrulamalı `.c` metni önbelleği (çıktıyı değiştirmez)

**Amaç.** Yeniden kurmanın 96 338 okumasını (seri profilde 135 sn; bu makinede açma başına 0,6–2,8 ms) azaltmak. Bayat içerik tehlikesi bilinir (`inline_detection.py:9-41`, P14 / BORU-11: eski `file_cache` bu yüzden bırakıldı) → önbellek içeriği her okumada `os.stat` (yol, `st_mtime_ns`, `st_size`, `st_ino`) ile doğrulanır; `stat` dosya açmaz.
**Dokunacağı dosyalar.** `karadul/core/metin_onbellegi.py` (yeni: `oku(yol) -> str`, süreç içi, bayt sınırlı LRU, anahtar = mutlak yol, değer = (stat dörtlüsü, metin)), okuyucular — yalnız `Path.read_text(...)` çağrısı `metin_onbellegi.oku(...)` ile değişir, başka satır değişmez: `karadul/reconstruction/c_algorithm_id.py` (`_analyze_file` 1096), `karadul/reconstruction/tarif/kesin.py` (`load_static` 233), `karadul/analyzers/signature_db.py` (`match_all` 3119), `karadul/reconstruction/c_namer.py` (`_read_and_extract` 2226 — HZ-7a ile aynı dosya: HZ-7a'dan SONRA), `karadul/reconstruction/binary_name_extractor.py` (`_collect_swift_mangled_symbols` 2293), `karadul/reconstruction/engineering/block_annotator.py` (`annotate` 643), `karadul/pipeline/steps/_feedback_typing_extras.py` (`run_ngram_naming` 213); `tests/test_hz7b_metin_onbellegi.py` (yeni), `scripts/measurement/mutation_specs_hz7b.json` (yeni).
**Dokunmayacağı.** `karadul/stages.py` `_recover_main_from_entry` (1816; ÜST VERİ P-ÜV5'in alanı — o paket girdikten sonra ayrı küçük değişiklikle eklenir), süreç havuzu işçilerindeki okumalar (`c_type_recoverer.py:146`, `engineering/analyzer.py:557`; işçi başına önbellek kazandırmaz), `feedback_loop.py` `file_cache` (ÖLÇEK ÖL-7).

**Adımlar.**
1. `metin_onbellegi.oku`: `st = os.stat(yol)`; anahtar eşleşirse metni döndür; yoksa `read_text(encoding, errors)` (çağıranın parametreleriyle; farklı kodlama parametresi farklı anahtar) ve sakla. Bayt sınırı `perf.metin_onbellegi_mb` (öntanım `min(1024, bellek_mb // 16)`; formül HZ-5'teki `config.py` yardımcısıyla).
2. Okuyucuları değiştir (liste yukarıda); her biri tek satır.
3. Test: yaz → oku → yeniden yaz (aynı boy, farklı içerik) → oku: yeni içerik (mtime_ns değişir); aynı saniyede iki yazım; silinen dosya `FileNotFoundError` aynen; kodlama hataları (`errors="replace"`) aynı metin.
4. Ölçüm: O ve B yeniden oynatma (3 tekrar); `_io.open` çağrı sayısı ve süresi (seri profil) önce / sonra.
5. S8 çıktı eşitliği.
6. Mutasyon (stat anahtarından `mtime_ns`'yi çıkarmak → bayatlık testi öldürmeli).

**Kabul ölçütü.** S8 + B bayt eşit; yeniden kurmada `open` çağrısı ≤ 0,5 × önce (seri profil); yeniden kurma süre oranı O ≤ 0,93, B ≤ 0,95.
**Ön kayıt.** "Eşitlik 9 / 9; `open` ≤ 0,5×; O ≤ 0,93; B ≤ 0,95 (TAHMİN 0,85–0,97)."
**Sınama beklentisi.** Okuyucuların mevcut testleri + yeni testler; tam takım 0 hata.
**Bayrak.** `perf.metin_onbellegi_mb` (0 = kapalı, bugünkü davranış).

#### HZ-7c — İkinci `feedback_loop` turunun ön sınaması (ÇIKTIYI DEĞİŞTİREBİLİR — ölçümle karar)

**Amaç.** 118 / 119 ikilide 0 yeni ad üreten ikinci turun (taban duvarının %11,2'si) çıktıya etkisini ölçmek; etkisizse atlamak için ölçülmüş bir koşul koymak.
**Dokunacağı dosyalar.** Önce yalnız ölçüm: `scripts/arge/hiz/hz7c_tur.py` (yeni; `feedback_loop` iki koşulla yeniden oynatılır: `pipeline_iterations = 1` ↔ `2`, ayar yamasıyla — `Config` örneğinde alan değiştirilir, ürün kodu değişmez). Ürün değişikliği yalnız ölçüm tuttuysa: `karadul/pipeline/steps/feedback_loop.py` (96–212), `karadul/pipeline/steps/_feedback_helpers.py` (`check_convergence` 87–…), `karadul/config.py` (bayrak).
**Adımlar.** (1) 119 ikiliyi Ghidra'sız yeniden oynat (`profil_yeniden.py --asamalar C` kalıbı; 2 kol); (2) `urun_olc.py karsilastir` ile ad ölçümü (tam eşitlik, tam + biçim; KARARLAR A-3) ve `reconstructed/src/` bayt farkı sayısı; (3) fark çıkan ikililerde hangi dosya / alan; (4) ön kayıttaki eşik tuttuysa koşul: "ilk turda yeni ad sayısı ≤ k ∧ … ise ikinci tur atlanır" (koşul ölçümden önce yazılmaz; ölçüm keşif ↔ sınama bölmesiyle: coreutils tek birim, ORTAK_BRIF §2.4).
**Kabul ölçütü.** Sınama birimlerinde tam eşitlik ve tam + biçim sayıları birebir aynı; yanlış ad sayısı aynı. Değilse paket "tutmadı" diye kapanır, ürün değişmez.
**Ön kayıt (`on_kayit_hz7c.md`).** "1 tur ↔ 2 tur: ad ölçümü 119 / 119 aynı; `reconstructed/src/` bayt farkı olan ikili ≤ 5; fark yalnız yorum / tip satırlarında." Tutmazsa kayda geçer.
**Bayrak.** `pipeline_tek_tur_kosulu` (öntanım kapalı).

#### HZ-7d — Süreç havuzlarının yeniden kullanımı (çıktıyı değiştirmez)

**Amaç.** Bir yeniden kurmada kurulan 10 süreç havuzunun (her biri spawn + içe aktarma + `initargs` pickle) maliyetini azaltmak.
**Dokunacağı dosyalar.** `karadul/core/havuz.py` (yeni: koşu boyunca yaşayan, `ISCI_YOGUN` işçili tek `ProcessPoolExecutor`; `forkserver` denemesi bayrakla), havuz kuran yerler: `karadul/reconstruction/engineering/analyzer.py` (465), `karadul/reconstruction/c_type_recoverer.py` (1342, 1471), `karadul/reconstruction/engineering/semantic_namer.py` (2793); `c_namer.py` (2285) EN SON ve HZ-7a / HZ-7b'den sonra; `tests/test_hz7d_havuz.py`, `scripts/measurement/mutation_specs_hz7d.json`.
**Dokunmayacağı.** İşçi işlevlerinin gövdeleri; birleştirme sırası (`c_namer.py:2276-2281` gönderim sırası).
**Adımlar.** (1) `initargs` ile gönderilen salt okur veriyi işçide ilk kullanımda yükleyen biçime çevir (veri bir kez pickle'lanıp her işe değil, havuz başına bir kez); (2) havuzu koşu boyunca paylaş (aynı işçi işlevleri için); (3) `forkserver` + `set_forkserver_preload` denemesi bayrakla, macOS'ta Objective-C çalışma zamanı uyarısı / çökmesi izlenir; (4) küçük işte (iş sayısı < `2 × işçi`) havuz yerine aynı süreçte koş; (5) S8 eşitlik; (6) havuz sayacı koşusuyla önce / sonra (havuz sayısı, ilk sonuç gecikmesi).
**Kabul ölçütü.** S8 bayt eşit; havuz kurulumu sayısı ≤ 3; yeniden kurma oranı K ≤ 0,95.
**Ön kayıt.** "Eşitlik 8 / 8; havuz ≤ 3; K ≤ 0,95 (TAHMİN 0,90–0,98)."
**Bayrak.** `perf.ortak_havuz` (öntanım kapalı → ölçümden sonra açılır), `perf.forkserver` (öntanım kapalı).

**Not (adım koşucusu).** `runner.py:332` iş parçacığı düzeyleri işlemci yoğun Python adımlarında GIL yüzünden hız kazandırmıyor ve adım sürelerini birbirine karıştırıyor (`project_build` seride 3,0, paralelde 36,2 sn; BULGULAR §4.5). Bu turda paket önerilmiyor (süreç tabanlı adım koşturma büyük değişiklik); HZ-1 / HZ-0 raporları paralel düzeydeki `*_duration_s`'leri toplamamalı.

### HZ-8 — JSON hızlı yazım (KOŞULLU: bağımlılık kararı)

**Koşul.** Berke / ana oturum `orjson`'u isteğe bağlı bağımlılık (`pyproject.toml` `perf` grubu) olarak kabul ederse.
**Amaç.** `indent=2` yazımında saf Python kodlayıcı yerine `orjson.dumps(…, option=OPT_INDENT_2)`; ölçüldü: 128 MB'de 3,42 → 0,12 sn, 5 / 5 dosyada bayt eşit (`json_olcum.py`). Kazanç küçük (B'de toplam ~5–10 sn TAHMİN); ÖL-3'ün çift yazımı kaldırması bunun yarısını zaten götürür.
**Dokunacağı dosyalar.** `karadul/ghidra/headless.py` (`_save_output` 2451–2457), `karadul/core/workspace.py` (`save_json` 234–249), `pyproject.toml`, `tests/test_hz8_json.py` (yeni).
**Adımlar.** orjson yoksa bugünkü yol; varsa orjson; `default=str` davranışı ve `ensure_ascii=True` (workspace) için eşdeğer seçenek yoksa o çağrıda bugünkü yol; büyük tamsayı (> 64 bit) istisnasında bugünkü yola düş. Test: iki yolun baytı eşit (S8 çıktılarının hepsi).
**Kabul ölçütü.** S8 bütün JSON'lar bayt eşit; `_save_output` toplam süre oranı ≤ 0,2.
**Bayrak.** Yok (bağımlılık varsa kullanılır).

### HZ-9 — Sonra ölçümü

**Amaç.** HZ-0'ın aynı hedefleri, aynı koşucu, aynı tekrar sayısı; girmiş paketlerle. Ayrıca 119'luk birleşik ölçüm (`urun_kos.py` + `urun_olc.py karsilastir`): HZ paketlerinin hiçbiri ad haritasını değiştirmemeli (HZ-7'nin çıktıyı değiştirebilen kalemi hariç; o kalem kendi ölçümüyle).
**Dokunacağı dosyalar.** `docs/arge/2026-11-19_mythos/hiz/HZ9.md`, `on_kayit_hz9.md`.
**Ön kayıt (taslak).** (a) 119'da `naming_map.json` bayt eşit 119 / 119 (HZ-7 ikinci tur kalemi açıksa: ad ölçümü değişmedi); (b) uçtan uca oran K ≤ 0,8, O ≤ 0,7, B ≤ 0,5 (TAHMİN; B'nin çoğu HZ-2 + HZ-4a'dan); (c) ölçüm makinesi dışında en az bir makinede (farklı çekirdek düzeni) K ve O'nun künyeli koşusu — oran aynı yönde mi.
**Kabul.** Her ön kayıt satırı için tuttu / tutmadı.

## 3. Gerekli veri ve araç

- Veri: hepsi makinede (S8, gösteri girdisi, taban koşusu). İndirme yok.
- Araç: JDK 21 `jfr` (Homebrew OpenJDK ile geliyor), `javap`, `ps`, `sysctl`, `systemextensionsctl`. Profil için ek araç kurulmaz; py-spy (Python iş parçacıklarının örneklenmesi) yararlı olurdu ama kurulumu indirme ister → Berke'ye sorulur, yoksa cProfile + `profil_yeniden.py`.
- HZ-4b için `javac` (Homebrew OpenJDK 21'de var).

## 4. Riskler ve bilinmeyenler

- **Yük altında ölçüldü.** Bu turun bütün mutlak süreleri yük ortalaması 23–43 altında; doğrusal üstü büyümenin (H0-c) ve açma maliyetinin (H0-e) ne kadarı yükten, HZ-0'a kadar bilinmiyor. Paket öncelikleri HZ-0'dan sonra yeniden sıralanabilir.
- **Erişimde tarama (Avast) nedensellik değil korelasyon.** Dışlama denemesi Berke'nin onayına bağlı; güvenlik ödünleşimi var (çalışma alanında hedef ikilinin `raw/` kopyası duruyor: dışlama yalnız `.c` dizinlerine verilmeli).
- **Çıktı eşitliği "aynı girdi" varsayımına dayanıyor.** `pcode_high_vars` sırası P16d'de sabitlendi; başka bir sıra kaynağı çıkarsa eşitlik testleri onu yakalar (paket durur, kaynak yazılır).
- **Paralel BSim taramasının fonksiyon kümesi** tekli yolla aynı olmalı; `scanFunctions` thunk / dış fonksiyonları kendisi eliyor olabilir (`javap` bayt kodunda `isThunk` denetimi görülüyor). HZ-2 testi kümeyi eski yolla karşılaştırır.
- **Donanım formülü yalnız benzetimle sınandı.** 8 GB / 4+4 makinede gerçek koşu yapılmadı; `YIGIN_TABAN_MB = 2048`'in büyük ikilide yetip yetmediği bilinmiyor (HZ-0'ın GC günlüğünden tepe yığın doluluğu okunur).

## 5. Çakışma (kalem 8): HIZ paketleri ↔ ÖLÇEK, yayın kapısı, ÜST VERİ, KİMLİK, ÖZ KOD

Kaynak: `olcek/PLAN.md` §1 tablosu, `ustveri/PLAN.md`, `kimlik/PLAN.md`, `ozkod/PLAN.md`, `2026-11-19_yayin/YAYIN_KAPISI.md` (dosya adları `grep -o "karadul/…\.py"` ile çıkarıldı). Kural: aynı dosyaya dokunan paketler aynı anda koşmaz (proje kuralı, 2026-05-14).

| Dosya | HIZ paketleri (bölge) | Öbür hatlar (bölge) | Önerilen sıra |
|---|---|---|---|
| `karadul/ghidra/headless.py` | HZ-1 (`_analyze_pyghidra` 267–630), HZ-5 (JVM argümanları 45–100, CLI yedeği 2478 / 2513–2515), HZ-3 (973–1086, 1129–1591; `_extract_call_graph`'a ekleme), HZ-4a (882–970, 1717–1813, 2025–2164), HZ-4b | ÖLÇEK ÖL-1 = yayın G1 / G2 (`_run_auto_analysis`, ilerleme olayları), ÖL-2 (bütün `_extract_*`'e `son_an` parametresi; BSim bloğu 517–574), ÖL-3 (akış biçimli yazım, `_save_output`), ÖL-6 (küçük); KİMLİK PK-8 (`_extract_xrefs`'e `address_taken_by`) | ÖL-1 → HZ-1 → ÖL-2 → HZ-5 → HZ-3 → HZ-4a (PK-8'i içerir ya da PK-8'den sonra) → ÖL-3 → HZ-4b. ÖL-2'nin `son_an` denetimi HZ-3 / HZ-4a'nın yeni döngülerine de konur (ÖL-2 önce girdiyse HZ paketi korur). |
| `karadul/ghidra/bsim.py` | HZ-2 (1234–1315, 1417–1491, 1759–1819, 1962–2077) | ÖLÇEK ÖL-2 (provenance sorgusu, ingest bütçesi); KİMLİK (yalnız okur) | ÖL-2 → HZ-2. Bütçe denetimi paralel taramada `TaskMonitor` iptaliyle korunur. |
| `karadul/analyzers/macho.py` | HZ-1 (`_record_ghidra_outcome` 1103–1155) | ÖLÇEK ÖL-3 (425–470), ÖL-9 (1247–1300), ÖL-10 | HZ-1 → ÖL-3 (farklı işlevler; aynı dosya kuralı yüzünden sıralı). |
| `karadul/config.py` | HZ-5 (127–222 + yeni alanlar), HZ-2 / HZ-3 / HZ-7a / HZ-7b / HZ-7c / HZ-7d (birer bayrak) | ÖLÇEK ÖL-1, ÖL-2, ÖL-5a, ÖL-6; ÖZ KOD ÖK-1, ÖK-2, ÖK-3, ÖK-4b, ÖK-6; ÜST VERİ P-ÜV6; KİMLİK (bayraklar) | En çekişmeli dosya. HZ paketleri `config.py` değişikliğini **yama dosyası** olarak teslim eder (`docs/arge/2026-11-19_mythos/hiz/yamalar/HZ-<n>__config.py.patch`; P16c'deki gibi), ana oturum sırayla uygular. Kod alanları `getattr` ile okur; yama uygulanmadan öntanım davranış aynı. |
| `karadul/reconstruction/c_namer.py` | HZ-7a (3856–4008, 4335–…), HZ-7b (2226), HZ-7d (2285) | ÖZ KOD ÖK-2 / ÖK-3 (`_strategy_string_context` klasik aşama ≈ 3523–3570), P12d (agresif aşama, erken dönüş), ÜST VERİ (1 yer) | ÖZ KOD / P12d ile aynı anda değil; HZ-7a farklı işlevlere dokunduğu için sıra serbest ama tek seferde biri. HZ-7a → HZ-7b → HZ-7d. |
| `karadul/reconstruction/api_param_db.py` | HZ-7a | — | serbest |
| `karadul/analyzers/binary_intelligence.py` | HZ-5 (2181), HZ-6 (2168–2178) | ÖLÇEK ÖL-3b (`analyze`, `_cluster_strings`, bütçe), yayın D2 (IMZA-01) | HZ-5 → HZ-6; ÖL-3b ve D2 ile sıralı. |
| `karadul/deobfuscators/binary_deobfuscator.py` | HZ-6 | — | serbest |
| `karadul/stages.py` | (HIZ dokunmaz; HZ-7b `_recover_main_from_entry`'yi bilerek dışarıda bırakır) | ÜST VERİ P-ÜV5 (`_recover_main_from_entry` ≈ 1816), P-ÜV6; ÖZ KOD ÖK-4b; ÖLÇEK ÖL-5a | P-ÜV5 girdikten sonra HZ-7b'ye tek satırlık ek (ayrı küçük değişiklik). |
| `karadul/pipeline/steps/feedback_loop.py`, `_feedback_helpers.py` | HZ-7c (yalnız ölçüm tuttuysa) | ÖLÇEK ÖL-7 (`_refresh_file_cache`; yayından sonra) | HZ-7c ölçümü önce; ürün değişikliği ÖL-7 ile sıralı. |
| `karadul/reconstruction/c_type_recoverer.py` | HZ-5 (1330, 1455), HZ-7d (1342, 1471) | — | HZ-5 → HZ-7d |
| `karadul/reconstruction/tarif/kesin.py` | HZ-7b (`load_static` 233; tek satır) | ÖZ KOD (`tarif/kesin.py` 1 yer) | sıralı |
| `karadul/cli.py`, `karadul/batch.py` | HZ-5 (1653; 33, 389) | ÖLÇEK ÖL-4, ÖL-5b; KİMLİK (cli 1 yer) | sıralı |
| `karadul/core/workspace.py` | HZ-8 (koşullu) | ÖLÇEK ÖL-6, ÖL-5b | sıralı |

**Yayın kapısı (G1–G4) ile ilişki:** G1 / G2 (ilerleme, takılan çözümleyici) = ÖLÇEK ÖL-1; HIZ'ın HZ-1'i onun adım zamanlarını kalıcı dosyaya yazar. G3 (ObjC çözümleyicisini öntanımda kapatmak) hız kararıdır ama çıktıyı değiştirir: HZ-0'ın `p16c_sure.py` çözümleyici süreleri G3'ün ölçümüne girdi olur; HIZ ayrıca paket açmaz. G4 (Go) ÜST VERİ'nin. D2 (`binary_intelligence.py`) HZ-6 ile sıralı.

**ÖLÇEK ile iş bölümü (ÖLÇEK PLAN §1 önerisiyle uyumlu):** ÖLÇEK'te kalan — bütçe ve bekçiler (ÖL-1, ÖL-2, ÖL-6), BSim'in boş depoda koşmaması (ÖL-2 adım 3), paket yöneticisi, akış biçimli yazım ve tek serileştirme (ÖL-3'ün bellek kısmı), önbellek / tembel derinlik (ÖL-9, ÖL-10), reconstruct kopyaları ve `file_cache` belleği (ÖL-7). HIZ'a geçen — döküm döngüleri ve JPype geçişi (ÖL-3 adım 1–3 → HZ-4a / HZ-4b; ÖL-3 adım 1'in profil işi HZ-0'ın JFR'ı), decompile işçisi ve dinamik parça (HZ-3), istihbaratın okuma hızı (ÖL-3b'nin hız kısmı → HZ-6; bütçe ÖL-3b'de), BSim'in kendi hızı (HZ-2), JVM yığını ve GC (HZ-5). ÖLÇEK'in ÖL-3 kabul ölçütündeki "xref ≤ 100 sn, CFG ≤ 150 sn" hedefi HZ-4a'nın kabulüyle aynı yöne bakar; iki paket aynı hedefi iki kez saymaz (HZ-4a ölçer, ÖL-3 bellek kısmını ölçer).

## 6. Karar gerektirenler (ana oturum / Berke)

| No | Karar | Neden | Öneri |
|---|---|---|---|
| K-HZ-1 | Avast'ta yalnız ölçüm kökünün `.c` dizinleri için dışlama denemesi (HZ-0 adım 7) | Açma maliyetinin ne kadarının erişimde taramadan geldiği ancak böyle ayrılır; çalışma alanında hedef ikilinin kopyası da durduğu için dışlama dar tutulmalı | Yalnız ölçüm kökü, yalnız deneme süresince |
| K-HZ-2 | `orjson`'u isteğe bağlı bağımlılık yapmak (HZ-8) | Bayt eşit, 28× hızlı; kazanç küçük | Düşük öncelik; ÖL-3'ten sonra yeniden bak |
| K-HZ-3 | BSim gölge kipteyken büyük ikilide koşsun mu | Gösteride uçtan ucun %25,3'ü, adlara girmiyor; "kapsam küçültülmez" kararıyla gerilim (ÖLÇEK ÖL-2 ile ortak) | HZ-2 + ÖL-2 bütçesi; kapatma yok |
| K-HZ-4 | py-spy kurulumu (Python iş parçacıklarını örnekleyen profil aracı; indirme ister) | cProfile çok iş parçacıklı decompile'ı göremiyor | İsteğe bağlı; yoksa JFR + seri profil |
| K-HZ-5 | HZ-7c sonucu: ikinci turu ölçülmüş koşulda atlamak | Çıktıyı değiştirebilir; yalnız ad ölçümü aynı kalırsa | Ölçümden sonra |
| K-HZ-6 | HZ-4b Java yardımcı sınıfı | Paketleme ve Ghidra sürüm bağı | Yalnız HZ-0 H0-d ve HZ-4a ölçümü gösterirse |
