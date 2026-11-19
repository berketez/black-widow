# ÖLÇEK — plan (tur 1 sonrası, 2026-11-19)

Bu belge kendi başına uygulanabilir olacak biçimde yazıldı: uygulayan Opus ajanları bu turun oturumunu görmeyecek. Kanıt ve sayılar `BULGULAR.md`'de, çalışma günlüğü `DEFTER.md`'de. Araştırma betikleri `scripts/arge/olcek/`, çıktıları `~/karadul_olcum/runs/arge-2026-11-19/olcek/`.

## 0. Bir bakışta

**Hat:** ÖLÇEK (soru kimlikleri E1, E3, E4, D1; BICIM-09; yayın kapısı G1, G2, G3, D3). Gereksinim (Berke, 2026-11-19): "Sadece 50 MB'de de olmayacak; birkaç GB'lık yazılımlarda da çalışabilmesi lazım."

**Hipotez.** "Birkaç GB'lık yazılım" iki ayrı sorundur:
1. **Paket sorunu.** Birkaç GB'lık kurulumun çoğu, sayıca küçük çok sayıda bileşen ile birkaç büyük üçüncü taraf çalışma zamanından (Chromium / Electron çerçevesi, Qt, LLVM, Python, Office paylaşılan çerçeveleri) oluşur. Yineleme, bağlı dosya ve üçüncü taraf payı ayıklanıp bütçe ve öncelikle sıralanınca paket, ana bileşenin süresine yakın sürede kullanılabilir rapor verir.
2. **Tek büyük ikili sorunu.** ~100 MB'lık tek C++ ikilisi (ör. `mlir-transform-opt`: 54 MiB kod, 163 141 fonksiyon) bugünkü "her şeyi baştan sona yap" akışıyla bu makinede yalnız Ghidra aşamasında 14,5–39,4 saat sürer (TAHMİN A; kötümser B 136,5 sa; BULGULAR §3.5). Bunun çaresi bütçe, bekçi ve **tembel derinliktir** (her fonksiyonu decompile etmeden önce ucuz katmanla ilk raporu vermek).

**Literatürün beklediği cevap / aykırı öncül:** bu pakete uygulanmaz (`ORTAK_BRIF.md`, `OLCEK.md`). Yerine sınanacak tasarım varsayımları her paketin ön kaydında yazılıdır.

**Ölçülen (BULGULAR):** uçtan uca ölçülmüş en büyük tek ikili 3,2 MB (5 697 fonksiyon; 708 sn). Gösteri dilimi (26,6 MB, 5,5 MB kod, 13 559 fonksiyon): Ghidra köprüsü 3 815,4 sn (63,6 dk); bunun 1 951,9 sn'si BSim ve **0 eşleşme**; xref ve CFG adımları örneklem modelinin 8,6 / 9,7 katı sürdü; decompile modelle tuttu (1,00×). Paket kuralı Ollama.app'te 26 bileşen veriyor, 16'sı tekil; asıl sunucu ikilisi (`Contents/Resources/ollama`, 52 MB) listede yok. FreeCAD.app'te 1 903 bileşen (867 tekil); KiCad.app'te 304 Mach-O'nun 298'i kapsam dışı. Bugünkü kuralla FreeCAD.app'in statik aşaması TAHMİN 177–345 saat (doğrusal), yineleme ayıklanınca 77–147 saat (BULGULAR §3.6).

**Paket sırası (önkoşul ve dosya sahipliği §1'de):**

```
Dalga 0  ÖLÇ-0 gösteri ölçümünü oku (salt okur)       ÖLÇ-A ölçüm koşucusu (yeni betik)
         ÖLÇ-1 taban ölçümü: bugünkü ürünle T25, T100, T300, PAKET (makine boşken, tek Ghidra)
Dalga 1  ÖL-1 köprü bekçisi + ilerleme olayları        ║ ÖL-4 ilerlemenin CLI / arayüzde görünmesi
Dalga 2  ÖL-2 adım bütçeleri + BSim koşulları
Dalga 3  ÖL-5a paket yöneticisi                         ║ ÖL-3 çıkarım hızı + akış biçimli yazım
Dalga 4  ÖL-6 bellek ve disk bekçisi                    ║ ÖL-3b ikili istihbarat süresi
Dalga 5  ÖL-5b yarıda kalan koşuyu sürdürme
Dalga 6  ÖLÇ-2 sonra ölçümü (ÖLÇ-1 ile aynı hedef, aynı koşucu) → "şu boyuta kadar denendi" cümlesi
— yayından sonra —
ÖL-7 reconstruct belleği ve kopyaları   ÖL-8 arayüz ölçeği   ÖL-9 sha256 önbelleği
ÖL-10 tembel derinlik (büyük ikili kipi)   ÖL-11 bilinen bileşen (KİMLİK / C5 ile)
```
`║` = paralel koşabilir (dosya kümeleri ayrık). Aynı anda en çok 2 kod paketi + 1 ölçüm; **aynı anda en çok 1 Ghidra koşusu**.

**Durma ölçütü (hat için).** ÖL-1 + ÖL-2 + ÖL-3 + ÖL-5a'dan sonra ÖLÇ-2'de T25 (gösteri dilimi) uçtan uca 60 dk'yı geçerse ya da T100 12 saat içinde ilk raporu veremezse "tek büyük ikili" için tam derinlik bırakılır; büyük ikili yalnız ÖL-10 (tembel derinlik) yoluyla desteklenir ve yayın notuna "N MB üstünde yalnız ucuz katman + seçili fonksiyonlar" yazılır.

## 1. Ortak kurallar ve dosya sahipliği

**Ortak kurallar (her paket):**
- Depo kökünden `PYTHONDONTWRITEBYTECODE=1 python -m …` / `python scripts/…`. Kabuk zsh: komutu ya da listeyi değişkende tutma.
- Kilitli setler (`targets/test_seti/`, `targets/dogrulama_seti/` ve koşu çıktıları) açılmaz, listelenmez.
- Ön kayıt metni ölçümden ÖNCE commit'lenir: `docs/arge/2026-11-19_mythos/olcek/on_kayit_<paket>.md` (her pakette hazır metin var). Tutmayan beklenti silinmez.
- Sayılar betikten. Ghidra koşusu: aynı anda en çok 1; `PYTHONHASHSEED=0`; koşuya özel `KARADUL_CACHE_DIR`. Süre ölçümü makine boşken (başka ajan yokken) yapılır; yük ortalaması künyeye yazılır (`uptime`).
- Mutasyon: `PYTHONDONTWRITEBYTECODE=1 python scripts/mutation_probe.py --spec scripts/measurement/mutation_specs_<paket>.json`. Mutantın `find` metni dosyada tekil, `replace` metni farklı uzunlukta; aynı worktree'de eşzamanlı mutasyon yok.
- Tam takım: `python -m pytest -q` (Y1 kapısı; 0 hata).
- Bayraklar `karadul/config.py`'de; okunmayan alan `INERT_SETTINGS`'e yazılır (`tests/test_p15a_etkisiz.py::test_every_unread_field_is_registered` denetler), bağlanınca oradan silinir.
- Git: commit'i ana oturum atar; `Co-Authored-By` satırı yok. Sürüm numarasını ana oturum belirler.
- **S8 alt kümesi** (çıktı eşitliği denetimi; 119'un boyut aralığını kapsar): girdiler `~/karadul_olcum/runs/urun-onarim-a62f15e/{debian/coreutils/cat, debian/coreutils/sort, debian/tree/tree, debian/sqlite3/sqlite3, debian/htop/htop, debian/tmux/tmux, debian/zstd/zstd, mac/tmux}` çalışma alanlarının `raw/` kopyaları (`urun_kos.py` `_ham_girdi` ile aynı yol). Önce / sonra aynı makinede, aynı `KARADUL_CACHE_DIR` düzeniyle (koşu başına boş) koşulur; karşılaştırma `ghidra_output/*.json` JSON eşitliği, `decompiled/*.c` bayt eşitliği, `naming_map.json` bayt eşitliği.
- İlerleme olayı sözleşmesi (ÖL-1 üretir, ÖL-4 gösterir; ikisi paralel yazılacağı için burada sabit): günlükçü adı `karadul.ilerleme`, düzey INFO, ileti biçimi tek satır `ILERLEME alan=değer …`; alanlar: `asama` (identify / static / deobfuscate / reconstruct / report / paket), `adim` (ör. `ghidra.otomatik_analiz`, `ghidra.decompile`, `ghidra.xref`, `ghidra.cfg`, `ghidra.bsim`, `paket.bilesen`), `durum` (`basladi` / `suruyor` / `bitti` / `kismi` / `atlandi`), isteğe bağlı `islenen`, `toplam`, `gecen_sn`, `cozumleyici`, `bilesen`, `neden` (boşluk içeren değer çift tırnakta).

**HIZ hattıyla ayrım** (`docs/arge/2026-11-19_mythos/HIZ.md`: "ÖLÇEK neyi hiç koşmamalı / neyi önbelleğe almalı; HIZ koşan her adımı hızlandırır"). Bu plan yazılırken HIZ'ın `PLAN.md`'si yoktu; ana oturum iki planı birleştirirken şu ayrım önerilir:
- **ÖLÇEK'te kalır:** bütçe ve bekçiler (ÖL-1, ÖL-2, ÖL-6), BSim'in sonuç üretemeyeceği durumda koşmaması (ÖL-2 adım 3), paket yöneticisi (ÖL-5a/b), akış biçimli yazım ve tek serileştirme (ÖL-3'ün bellek kısmı), önbellek ve tembel derinlik (ÖL-9, ÖL-10).
- **HIZ'a bırakılır:** xref / CFG / çağrı grafiği döngülerini Java tarafına taşıma ve JPype geçişini azaltma (ÖL-3 adım 1–3 HIZ'ın paketiyle birleşir), decompile işçi sayısı ve dinamik parça, ikili istihbarat taramasının hızı (ÖL-3b'nin hız kısmı), BSim'in kendi hızı (ingest + sorgu), JVM yığını ve çöp toplayıcı ayarı.
- Aynı dosyaya (`karadul/ghidra/headless.py`, `karadul/ghidra/bsim.py`, `karadul/analyzers/binary_intelligence.py`) dokunan ÖLÇEK ve HIZ paketleri sıralı koşar.

**Tehlikeli (ortak) dosyalar ve sahiplik:**

| Dosya | Bu plandaki paketler (sıra) | Başka hatlar / işler |
|---|---|---|
| `karadul/ghidra/headless.py` | ÖL-1 → ÖL-2 → ÖL-3 → (ÖL-6 küçük) | yayın G2 (= ÖL-1); **KİMLİK PK-8** (`_extract_xrefs`'e alan) — ÖL-3 ile aynı işlev, sıralı; **HIZ** (JPype / Java tarafı) |
| `karadul/config.py` | ÖL-1 → ÖL-2 → ÖL-5a → ÖL-6 | ÖZ KOD ÖK-1, ÖK-2, ÖK-3, ÖK-4b, ÖK-6; ÜST VERİ P-ÜV6; KİMLİK (bayraklar) |
| `karadul/stages.py` | ÖL-5a (yalnız `StaticAnalysisStage._execute_app_bundle`, ≈ 595–683) | ÖZ KOD ÖK-4b (`_seed_recovery_pre_names`, ≈ 1751–1812); ÜST VERİ P-ÜV5 (`_recover_main_from_entry`, ≈ 1816) ve P-ÜV6 (≈ 2505–2530) |
| `karadul/analyzers/macho.py` | ÖL-3 (≈ 425–470) → ÖL-9 (≈ 1247–1300) → ÖL-10 | — (ÜST VERİ planı `macho.py`'ye dokunmuyor: `ustveri/PLAN.md` ≈ satır 172) |
| `karadul/core/target.py`, `karadul/analyzers/app_bundle.py` | ÖL-5a → ÖL-5b → ÖL-11 | yayın D3 (= ÖL-5a) |
| `karadul/cli.py`, `karadul/cli_common.py` | ÖL-4 → ÖL-5b | — |
| `ui/server.py`, `ui/index.html` | ÖL-4 (yalnız `_job_progress`) → ÖL-8 | — |
| `karadul/core/pipeline.py`, `karadul/core/workspace.py` | ÖL-6 → ÖL-5b | — |
| `karadul/ghidra/bsim.py` | ÖL-2 | KİMLİK (BSim ölçümü yalnız okur); **HIZ** (BSim hızı) — sıralı |
| `karadul/analyzers/binary_intelligence.py` | ÖL-3b | yayın D2 (IMZA-01 kalanı); **HIZ** (tarama hızı) — sıralı |

---

## 2. Ölçüm paketleri

### ÖLÇ-0 — Gösteri koşusunun bitmiş ölçümü (salt okur, Ghidra yok)

**Amaç.** Bu tur yazılırken süren gösteri koşusunun (Ollama 0.40.3 arm64 dilimi, b4be6f3) uçtan uca sayılarını okumak ve BULGULAR §3.5'teki 25 MB tahminini sınamak.

**Dokunacağı dosyalar.** `docs/arge/2026-11-19_mythos/olcek/OLC0.md` (yeni). Veri: `~/karadul_olcum/runs/arge-2026-11-19/olcek/gosteri_son.json` (yeni).
**Dokunmayacağı.** `~/karadul_olcum/runs/gosteri-2026-11-19/` (salt okur), ürün kodu, testler.

**Adımlar.**
1. `~/karadul_olcum/runs/gosteri-2026-11-19/ollama/CIKIS` var mı bak. Yoksa koşu sürüyordur: bekleme, `gosteri_oku.py` ile o anki durumu yaz ve paketi "koşu sürüyor" diye kapat.
2. `PYTHONDONTWRITEBYTECODE=1 python scripts/arge/olcek/gosteri_oku.py --gosteri ~/karadul_olcum/runs/gosteri-2026-11-19/ollama --cikti ~/karadul_olcum/runs/arge-2026-11-19/olcek/gosteri_son.json`.
3. `kosu.log` sonundaki `/usr/bin/time -l` satırlarından gerçek süre, azami RSS ve tepe ayak izi (betik `deneme2_time` alanına yazar).
4. Aşama süreleri `pipeline_result` alanından (`identify`, `static`, `deobfuscate`, `reconstruct`, `report`) ve reconstruct'ın `timing_*` adımları; çalışma alanı ve `out/` diski (`disk_calisma_alani`), dosya sayısı.
5. Tahminle kıyas (ön kayıt aşağıda): reconstruct süresi, çalışma alanı diski, dosya sayısı.
6. `OLC0.md`'ye tablo + "tuttu / tutmadı".

**Ön kayıt (bu turda, 2026-11-19 12:38'de, gösteri `reconstructed/` dizini boşken yazıldı; DEFTER).** Örneklem modelinin (119 ikili; `olcek_egri.py`, `egri_ozet.txt` "Gösteri için örneklem öngörüsü"; p5–p95) gösterinin kendi fonksiyon sayısı (13 559) ve kod baytı (5 509 156) için öngörüsü:
- reconstruct süresi: 466 [315; 732] sn (fonksiyon ekseni), 464 [326; 710] sn (kod ekseni);
- çalışma alanı diski: 1,95 [1,55; 2,66] GB / 1,61 [1,38; 2,12] GB;
- çalışma alanı dosya sayısı: 161 700 [159 700; 164 000] / 114 500 [75 450; 207 200];
- `out/` diski: 117,7 [97,4; 160,4] MB / 96,2 [77,8; 144,2] MB;
- toplam süre: 1 108 [727; 1 632] sn — **şimdiden tutmadı** (Ghidra köprüsü tek başına 3 815 sn; statik aşamanın köprü dışı kısmı 912 sn, öngörü 35 [10; 77]).
Hüküm: her satır için gözlenen değer aralığın içinde mi. Tutmayan satır kayda geçer; model değiştirilmez.

**Sınama beklentisi.** Yok (kod değişmez).

### ÖLÇ-A — Ölçek ölçüm koşucusu (yeni betik)

**Amaç.** Tek hedef için `karadul analyze` koşusunu süre, bellek, disk ve ilerleme gözlemiyle saran, duvar sınırı olan, tekrarlanabilir koşucu. Bugün yalnız `/usr/bin/time -l` var; RSS zaman serisi, disk zaman serisi, Ghidra adım süreleri ve JVM çöp toplama günlüğü yok.

**Dokunacağı dosyalar.** `scripts/measurement/olcek_kos.py` (yeni), `tests/test_olcek_kos.py` (yeni), `scripts/measurement/mutation_specs_olcek_kos.json` (yeni).
**Dokunmayacağı.** `scripts/measurement/urun_kos.py` (ÖLÇÜ hattı değiştiriyor), ürün kodu.

**Adımlar.**
1. Arayüz: `python scripts/measurement/olcek_kos.py --agac <ürün ağacı> --hedef <dosya ya da .app> --kok <koşu dizini> --duvar-sn <N> [--ayar <yaml>] [--etiket <ad>]`. Ürün `--agac`'tan yüklenir ve bu denetlenir (`urun_kos.py:88-104` `agac_kunyesi` ile aynı yöntem; kodu kopyalama, içe aktar).
2. Koşu: `/usr/bin/time -l python -m karadul analyze <hedef> --skip-dynamic --output-dir <kök>/ws --output <kök>/out [--config <yaml>]`, ortam `PYTHONHASHSEED=0`, `KARADUL_CACHE_DIR=<kök>/cache`, `JAVA_TOOL_OPTIONS=-Xlog:gc*:file=<kök>/gc.log:time,uptime` (JVM çöp toplama günlüğü; kod değişikliği gerektirmez).
3. Örnekleyici (ayrı iş parçacığı, 10 sn'de bir): süreç ağacının RSS'i (`ps -o rss= -p <pid>` + çocuklar), `<kök>` disk kullanımı (60 sn'de bir, `os.scandir` ile ayrılan bayt), `uptime` yük ortalaması → `<kök>/ornekler.csv`.
4. Duvar sınırı: `--duvar-sn` dolunca SIGTERM, 60 sn sonra SIGKILL; `BITTI` dosyasına `zaman_asimi`.
5. Bitişte künye `<kök>/kunye.json`: başlangıç / bitiş, çıkış kodu, `time -l` alanları, tepe RSS (örneklerden), tepe disk, son yük, Ghidra adım süreleri (`scripts/arge/olcek/olcek_topla.py`'deki `ghidra_adim_sureleri` mantığı; işlev `scripts/measurement/olcek_kos.py`'ye taşınır, araştırma betiği değişmez), aşama süreleri (`pipeline_result.json`), ilk rapor zamanı (`reports/report.json` ilk oluşma zamanı), dosya sayısı.
6. Testler (Ghidra yok): sahte hedef komutuyla (`--komut` test kancası: `python -c "…uyku + dosya yaz…"`) duvar sınırı, örnekleyici, künye alanları.
7. Mutasyon tanımı (4–6 mutant: duvar sınırı, SIGKILL, tepe RSS seçimi, künye alanı).

**Kabul ölçütü.** Testler geçer; mutantların hepsi ölür; sahte 30 sn'lik koşuda `ornekler.csv` ≥ 3 satır; duvar 5 sn verildiğinde çıkış `zaman_asimi` ve süre ≤ 5 + 60 + 2 sn.
**Ön kayıt.** Gerekmez (araç).
**Bayrak.** Yok.

### ÖLÇ-1 — Taban ölçümü: bugünkü ürünle üç boyut + bir paket

**Amaç.** Kod değişikliklerinden önce, sabit bir ürün ağacıyla (`git archive` ile `~/karadul_olcum/urun-<commit>`; bkz. `urun_kos.py` künyesi) "bugün" sayılarını ölçmek. Hedefler yalnız açık kaynak ve makinede hazır (indirme yok):

| Kod | Hedef | Lisans | Boyut | Kod (`__text`) | Fonksiyon başlangıcı | Not |
|---|---|---|---|---|---|---|
| T25 | `~/karadul_olcum/runs/gosteri-2026-11-19/ollama/girdi/Ollama` (arm64 dilimi otomatik seçilir) | MIT | 54 300 560 B dosya; dilim 26 627 984 B | 5 509 156 B | 12 952 | Go + Swift + C++; gösteri hedefi |
| T100 | `/opt/homebrew/Cellar/llvm/23.1.6/bin/mlir-transform-opt` | Apache-2.0 WITH LLVM-exception | 94 869 440 B | 56 755 068 B | 163 141 | C++; ince arm64 |
| T300 | `/opt/anaconda3/envs/project_env/lib/python3.12/site-packages/tensorflow/libtensorflow_cc.2.dylib` (TensorFlow 2.19.0) | Apache-2.0 (`tensorflow-2.19.0.dist-info/METADATA`) | 646 577 920 B | 220 438 340 B (210,2 MiB) | 746 814 | C++; ince arm64; çalıştırma biti yok (dylib) |
| PAKET | `/Applications/FreeCAD.app` (FreeCAD 1.1.4; `Info.plist` `CFBundleVersion`) | LGPL-2.1-or-later (FreeCAD); paket içi conda kitaplıkları çeşitli açık kaynak lisanslar (`Contents/packages.txt`) | 2,48 GiB (31 577 dosya) | — | — | Bugünkü kuralla 1 903 bileşen, 867 tekil sha256; 964 Mach-O kapsam dışı (§1, `envanter.py`) |
| PAKET-E (isteğe bağlı) | `/Applications/Element.app` (1.11.91; Electron) | açık kaynak (sürümün lisansı paket içindeki lisans dosyasından doğrulanmalı) | 556 MB (`du -sh`); `app.asar` 33 848 946 B + `webapp.asar` 97 917 378 B | — | — | Electron JS hattı büyük `asar`'la hiç koşulmadı (BICIM-09). Kapalı kaynak ChatGPT.app'te `app.asar` 747 MiB: büyük Electron uygulamasının ölçeği |

**Dokunacağı dosyalar.** `docs/arge/2026-11-19_mythos/olcek/OLC1.md` (yeni), `docs/arge/2026-11-19_mythos/olcek/on_kayit_olc1.md` (yeni); veri `~/karadul_olcum/runs/olcek-taban-<commit>/<kod>/`.
**Dokunmayacağı.** Ürün kodu; hedef dosyalar (yalnız okunur, kopyalanmaz; ürün kendi `raw/` kopyasını alır).

**Adımlar.**
1. Ürün ağacını sabitle (`git archive <commit> | tar -x -C ~/karadul_olcum/urun-<commit>`; `signatures.lmdb` bağı `urun_kos.py:39-43`'teki çalışma verisi listesiyle).
2. Ön kaydı (aşağıda) commit'let.
3. Makine boşken sırayla: T25 (duvar 3 sa), T100 (duvar 8 sa), T300 (duvar 8 sa), PAKET (duvar 8 sa). Her biri `olcek_kos.py` ile; aynı anda tek koşu.
4. Her koşudan: bitti mi, nerede kaldı (son yazılan Ghidra çıktısı), aşama / adım süreleri, tepe RSS, tepe disk, dosya sayısı, ilk rapor zamanı, JVM GC toplam duraklama süresi (`gc.log`).
5. PAKET için ayrıca: kaç bileşen bitti, hangileri, bileşen başına süre (`static/bundle_analysis.json` yalnız sonda yazılıyor → yarıda kalırsa `components/*/static/ghidra_status.json`'lardan sayılır).
6. `OLC1.md`: tablo + ön kayıtla kıyas.

**Ön kayıt (`on_kayit_olc1.md` taslağı; tahmin aralıkları BULGULAR §3.5 / §3.6'dan, koşudan önce commit'lenir):**
- T25: Ghidra köprüsü gösterinin ± %20'si içinde: [3 052; 4 578] sn (gösteri 3 815,4 sn, yük altında); uçtan uca 3 saatlik duvarda biter.
- T100 (56 755 068 B kod, 163 141 fonksiyon): köprü TAHMİN A [14,5; 39,4] sa, B 136,5 sa (BULGULAR §3.5); **8 saatlik duvarda Ghidra köprüsü bitmez**; decompile 7 200 sn sınırında kısmi kalır (alt uç 16 214 sn). Biterse kayda "beklenti tutmadı (iyi yönde)" yazılır.
- T300 (220 438 340 B kod, 746 814 fonksiyon): köprü TAHMİN A [77,9; 447,5] sa; 8 saatlik duvarda köprü bitmez; ilk adımın (JVM + içe aktarma + otomatik analiz) TAHMİN A aralığı [5 041; 16 085] sn — ön kayıt: "otomatik analiz 8 saatlik duvarda biter" (aralığın tamamı 28 800 sn'nin altında; tutmazsa kayda geçer). Tepe RSS ön kaydı: ≥ 14,7 GB (JVM yığın sınırına dayanır).
- PAKET: 8 saatlik duvarda bileşenlerin hepsi bitmez (§3.6 senaryo S0 alt sınırı duvarı aşıyorsa).
- Tepe RSS: T25 ≥ 6,4 GB (1. deneme otomatik analizde 6,4 GB idi).

**Kabul ölçütü.** Dört koşunun dördünün de künyesi (`kunye.json`) eksiksiz; her biri için "bitti / şurada kaldı" hükmü.
**Bayrak.** Yok.

### ÖLÇ-2 — Sonra ölçümü

**Amaç.** ÖL-1, ÖL-2, ÖL-3, ÖL-5a, ÖL-6 (ve varsa ÖL-5b) girdikten sonra ÖLÇ-1'in aynı hedefleri, aynı koşucu, aynı duvarlar. Yayın notundaki "şu boyuta kadar denendi" cümlesi bu paketten çıkar.
**Dokunacağı dosyalar.** `docs/arge/2026-11-19_mythos/olcek/OLC2.md`, `on_kayit_olc2.md` (yeni).
**Adımlar.** ÖLÇ-1 adımları 1–6, yeni ürün ağacıyla; ayrıca yanlış ad kapısı için 119'luk birleşik ölçüm (`urun_kos.py` + `urun_olc.py karsilastir`, taban a62f15e ya da o günkü taban) — ölçek değişiklikleri ad haritasını değiştirmemeli.
**Ön kayıt (taslak).** (a) 119'da `naming_map.json` bayt eşit 119 / 119 (ad haritası tohumdan bağımsız: P12a; döküm sırası P16d'de sabitlendi); doğru / yanlış ad sayıları aynı. Eşit olmayan her ikili nedeniyle kayda geçer. (b) T25 uçtan uca ≤ 45 dk. (c) T100: ilk rapor ≤ 4 sa (bütçeli kısmi rapor sayılır). (d) PAKET: ilk rapor ≤ ana bileşen süresi + 10 dk; toplam süre ≤ paket bütçesi + 10 dk. (e) Hiçbir koşuda 60 sn'den uzun ilerleme sessizliği yok.
**Kabul.** Ön kaydın her satırı için tuttu / tutmadı; yayın notu cümlesi (şablon; ÖLÇ-2 doldurur): "Tek ikilide ⟨en büyük biten hedef⟩ uçtan uca denendi (⟨süre⟩, ⟨tepe RSS⟩); paket olarak ⟨PAKET⟩ (⟨GB⟩) bütçeyle denendi; daha büyüğü denenmedi."

---

## 3. Yayından önce ürün paketleri

### ÖL-1 — Ghidra köprüsü: takılan çözümleyici bekçisi ve ilerleme olayları (G2; G1'in köprü tarafı)

**Amaç.** Otomatik analizde tek çözümleyicinin dakikalarca dönmesini fark edip kapatarak sürdürmek; köprünün her adımında ilerleme olayı üretmek.

**Dokunacağı dosyalar.** `karadul/ghidra/headless.py` (`_run_auto_analysis` ≈ 672–716, `_analyze_pyghidra` ≈ 267–630 içinde yalnız olay satırları, yeni özel sınıf `_CozumleyiciBekcisi`), `karadul/config.py` (`AnalysisConfig`'e iki alan), `tests/test_ol1_kopru_bekci.py` (yeni), `scripts/measurement/mutation_specs_ol1.json` (yeni).
**Dokunmayacağı.** `karadul/analyzers/macho.py`, `karadul/cli.py`, `ui/`, `karadul/ghidra/bsim.py`, adımların gövdeleri (`_extract_*`; ÖL-2 / ÖL-3'ün).

**Adımlar.**
1. **Fizibilite (önce, ≤ 1 saat, küçük ikiliyle tek Ghidra koşusu):** o an çalışan çözümleyicinin adını okumanın üç yolunu dene, birini seç ve paket defterine yaz: (a) `AutoAnalysisManager` üstünden etkin görev (Ghidra 12.1.2'de var mı: `javap -cp <ghidra jar> ghidra.app.plugin.core.analysis.AutoAnalysisManager | grep -i task`); (b) analiz iş parçacığının yığın örneği (`java.lang.Thread.getAllStackTraces()`; `ghidra.app.services.Analyzer` arayüzünü uygulayan ilk çerçevenin sınıfı — gösteri 1. denemedeki `deneme1_jstack.txt` bunu gösterdi: `ObjcMessageAnalyzer`); (c) `TaskMonitor` iletisi (`setMessage`). JPype'ın `JProxy` ile iş parçacığı sorunu `headless.py:1190-1196` notunda var; (b) bu yüzden önde.
2. `_CozumleyiciBekcisi` (daemon Python iş parçacığı): `analysis.bekci_aralik_sn` (öntanım 15) aralıkla çalışan çözümleyiciyi okur; her okumada `ILERLEME asama=static adim=ghidra.otomatik_analiz durum=suruyor cozumleyici="…" gecen_sn=…` olayı (`karadul.ilerleme`, §1 sözleşmesi).
3. Aynı çözümleyici `analysis.cozumleyici_takilma_sn` (öntanım 600) boyunca tepedeyse: izleyiciyi iptal et (`TimeoutTaskMonitor.cancel()`), adı `info["takilan_cozumleyici"]`'ye yaz, `_disable_analyzers(program, [ad])` ile kapat ve `analyzeAll`'ı kalan süre bütçesiyle BİR kez daha çağır. İkinci kez takılırsa yeniden deneme yok: `status = "timeout"` (bugünkü kısmi yol).
4. `info["status"]`'a yeni değer: `ok_cozumleyici_kapatildi`; `step_errors["analysis"]`'a neden (ad + süre). `static` aşaması bunu kısmi sayar (çıkış 3; `EXIT_ANALYSIS_PARTIAL`, `karadul/core/pipeline.py`).
5. Köprünün her adımının başına / sonuna olay: `adim=ghidra.<adim> durum=basladi|bitti islenen=… toplam=… gecen_sn=…` (`headless.py:359-605` arasındaki her `try` bloğu). Decompile parçaları bittikçe (`headless.py:1266-1272`) `durum=suruyor islenen=<biten parça × parça boyu>`.
6. Testler (Ghidra yok, sahte program / sahte yöneticiyle; `tests/test_p16c_analiz_suresi.py`'deki sahte JVM kalıbı): bekçi takılmayı süre dolunca yakalar, çözümleyiciyi kapatır, ikinci tur çağrılır; ikinci takılmada yeniden deneme yok; olaylar sözleşme biçiminde; bekçi kapalıyken (`cozumleyici_takilma_sn = 0`) davranış bugünküyle aynı.
7. Mutasyon tanımı (≥ 8 mutant: eşik karşılaştırması, ikinci tur sayacı, kapatılan ad, olay alanları).

**Kabul ölçütü.** (a) Ollama dilimi (T25), "Objective-C Message Analyzer" AÇIK (gösteri 1. denemenin koşulu): bekçi ≤ 660 sn'de tetiklenir; koşu biter (çıkış 0 ya da 3); `ghidra_status.json` `analysis.takilan_cozumleyici` = bu çözümleyici. (b) S8 alt kümesinde (§1) `ghidra_output/*.json` ve `.c` dosyaları öncesiyle aynı (fark yalnız mutlak yol). (c) T25'te `ILERLEME` satırları arasındaki en uzun boşluk ≤ 60 sn (bugün: gösteri 2. denemede `kosu.log` 11:12–13:05 arası 113 dk değişmedi).
**Ön kayıt (`on_kayit_ol1.md`).** "Bekçi açıkken T25 1. deneme koşulunda tetiklenme ≤ 660 sn; 8 / 8 alt küme çıktısı aynı; ilerleme sessizliği ≤ 60 sn. Tetiklenen çözümleyici kapatılınca kalan analiz ≤ 600 sn'de biter (gösteri 2. denemede otomatik analiz 226,4 sn)."
**Sınama beklentisi.** Yeni testler geçer; mutantların hepsi ölür; tam takım 0 hata.
**Bayrak.** `analysis.cozumleyici_takilma_sn` (öntanım 600; 0 = kapalı), `analysis.bekci_aralik_sn` (öntanım 15). Öntanım açık: takılmayan koşuda davranış değişmez (yalnız olay satırı).

### ÖL-4 — İlerlemenin CLI ve arayüzde görünmesi (G1'in gösterim tarafı)

**Amaç.** `karadul.ilerleme` olaylarını `--verbose` olmadan da kullanıcıya göstermek; arayüzün iş günlüğünü her yoklamada baştan okumasını kaldırmak.

**Dokunacağı dosyalar.** `karadul/cli.py` (≈ 957–999: `analyze` içinde ilerleme işleyicisi), `karadul/cli_common.py` (`make_progress_callbacks` ≈ 215–), `ui/server.py` (`_job_progress` ≈ 2477–2530), `tests/test_ol4_ilerleme.py` (yeni), `scripts/measurement/mutation_specs_ol4.json` (yeni).
**Dokunmayacağı.** `karadul/ghidra/headless.py` (ÖL-1), `karadul/core/pipeline.py`, `ui/index.html` (yalnız sunucu tarafı; görsel değişiklik ÖL-8'de).

**Adımlar.**
1. `analyze`: `karadul.ilerleme` günlükçüsüne stderr işleyicisi (yalnız bu günlükçü, düzey INFO, `--quiet` / `--json` kipinde kapalı); TTY değilse de yazar (bugün `transient=True` çubuk TTY dışında iz bırakmıyor, `cli.py:979-986`).
2. TTY'de: çubuğun açıklama satırı son olayın `adim` + `islenen/toplam` + `gecen_sn`'si.
3. `_job_progress`: günlüğün yalnız son 64 KiB'ı okunur (dosya ofseti saklanır); `ILERLEME` satırları ayrıştırılıp son durum JSON'da (`adim`, `durum`, `islenen`, `toplam`, `cozumleyici`).
4. Sahte veri yok: olay yoksa alan `null`; animasyonlu "ilerliyor" göstergesi eklenmez (CLAUDE.md "sahte animasyon yasağı").
5. Testler: sahte günlük dosyasıyla `_job_progress` yalnız kuyruğu okur (ofset), 10 MB'lık günlükte süre < 50 ms; CLI'da `--quiet` ile olay basılmaz, normal kipte basılır.
6. Mutasyon tanımı.

**Kabul ölçütü.** 10 MB'lık sahte günlükte `_job_progress` < 50 ms (bugün tam okuma); T25 koşusunda (ÖL-1 ile birlikte) `kosu.log`'da `ILERLEME` satırları var ve en uzun boşluk ≤ 60 sn.
**Ön kayıt.** Gerekmez (gösterim; ölçüt testte).
**Bayrak.** Yok (gösterim). `--quiet` mevcut davranışı korur.

### ÖL-2 — Adım bütçeleri ve BSim koşulları

**Amaç.** Ghidra köprüsünün sınırsız adımlarına (dizgi, çağrı grafiği, tip, xref, P-code, CFG, FunctionID, BSim) süre bütçesi; BSim'in sonuç üretemeyeceği durumda (depoda başka program yok) sorguyu atlamak, büyük ikilide ingest'i bütçelemek.

**Dokunacağı dosyalar.** `karadul/ghidra/headless.py` (`_extract_strings`, `_extract_call_graph`, `_extract_types`, `_extract_xrefs`, `_extract_cfg`, `_extract_function_id_matches` imzalarına `son_an` (monotonic deadline) parametresi ve döngü içinde denetim; `:517-574` BSim çağrı bloğu), `karadul/ghidra/bsim.py` (provenance'tan "depoda kendisi dışında program var mı" sorgusu; ingest'e süre bütçesi), `karadul/config.py` (`Timeouts`'a `ghidra_adim`; `BSimConfig`'e `bos_depoda_sorgu_atla`, `ingest_butcesi_sn`), `tests/test_ol2_adim_butcesi.py`, `tests/test_ol2_bsim_kosul.py` (yeni), `scripts/measurement/mutation_specs_ol2.json` (yeni).
**Dokunmayacağı.** `_run_auto_analysis` ve bekçi (ÖL-1), `_decompile_functions` (zaten sınırlı), `karadul/analyzers/macho.py`, `karadul/pipeline/steps/bsim_match.py`.

**Adımlar.**
1. `son_an` sözleşmesi: her `_extract_*` 500 fonksiyonda (ya da 50 000 adreste) bir `time.monotonic() > son_an` denetler; aşınca döngüden çıkar, çıktıya `"kismi": true, "islenen": n, "toplam": N, "neden": "adım bütçesi (S sn) doldu"` ekler; `step_errors[<adım>]`'a aynı neden. Kısmi çıktı geçerli JSON'dur (aşağı akış okur).
2. Bütçe: `timeouts.ghidra_adim` (öntanım 3 600 sn; 119'un en uzun adımı 141,8 sn → öntanımda 119'da hiçbir adım kesilmez).
3. BSim sorgu koşulu: ingest'ten ÖNCE provenance'ta (`bsim.py` `_ProvenanceStore.load`, ≈ 585–624) bu programın md5'i dışında kayıt yoksa ve `bsim.bos_depoda_sorgu_atla` açıksa sorgu atlanır: `bsim_matches.json` aynı şemada `total_matches: 0`, `bsim_status: "atlandi"`, `bsim_detail.neden: "depoda başka program yok; sorgu kendi kendine eşleşirdi ve dışlanırdı"`. Çıktının anlamı bugünküyle aynı (gösteride 0 eşleşme).
4. BSim ingest bütçesi `bsim.ingest_butcesi_sn` (öntanım 900): aşılırsa ingest durdurulur, `bsim_status: "kismi"`, sayılar yazılır. (Ingest gelecekteki koşuların sorgusu içindir; kapatılmaz, bütçelenir — "kapsam küçültülmez" kararı.)
5. İlerleme olayları (ÖL-1 sözleşmesi) bütçe aşımında `durum=kismi neden="…"`.
6. Testler (sahte program): bütçe aşımında kısmi JSON ve adım hatası; öntanım bütçede davranış aynı; BSim boş depo → sorgu çağrılmaz, şema aynı; dolu depo → sorgu çağrılır; ingest bütçesi.
7. Mutasyon tanımı (≥ 10 mutant).

**Kabul ölçütü.** (a) T25'te BSim adımı ≤ 900 + 30 sn (bugün 1 951,9) ve `bsim_matches.json` `total_matches` = 0 (bugünle aynı). (b) Debian sqlite3'te `timeouts.ghidra_adim: 2` ile her sınırsız adım ≤ 2 + 5 sn'de kısmi biter; koşu çıkış 3. (c) S8 alt kümesinde öntanım ayarla çıktı aynı (koşuya özel boş depo → BSim sorgusu atlanır: `bsim_matches.json`'da yalnız `bsim_status` / `bsim_detail` alanları farklı; bunun dışında aynı). (d) 119 birleşik koşusunda (paylaşılan depo: ilk ikili dışındakilerde depo dolu) ad haritası aynı (BSim gölge kipte).
**Ön kayıt (`on_kayit_ol2.md`).** "T25 BSim ≤ 930 sn, eşleşme 0 → 0; sqlite3 2 sn bütçede her adım ≤ 7 sn; alt küme çıktısı (BSim durum alanları hariç) aynı; 119 ad haritası 119 / 119 aynı."
**Sınama beklentisi.** Yeni testler + `tests/test_p16b_bsim.py`, `tests/test_p16c_bsim_toplu.py` geçer; mutantlar ölür; tam takım 0 hata.
**Bayrak.** `timeouts.ghidra_adim` (öntanım 3 600), `bsim.bos_depoda_sorgu_atla` (öntanım açık), `bsim.ingest_butcesi_sn` (öntanım 900; 0 = sınırsız).

### ÖL-3 — Çıkarım hızı ve akış biçimli yazım (xref, CFG, çağrı grafiği; çift yazım)

> **HIZ ile birleşme notu:** adım 1–3 (profil, xref / CFG döngüleri) HIZ hattının JPype / Java tarafı paketiyle aynı işi yapar; ana oturum ikisinden birini seçer. ÖLÇEK için vazgeçilmez olan adım 4–5'tir (akış biçimli yazım, tek serileştirme) ve kabul ölçütü (c)'dir (tepe RSS).

**Amaç.** Gösteride xref 348,7 sn ve CFG 600,9 sn (örneklem modelinin 8,6 / 9,7 katı) ve köprünün bütün çıktıyı bellekte tutması (K6). Önce nedeni ölç, sonra adres / komut başına Python↔Java çağrılarını toplu yineleyicilerle değiştir ve çıktıyı akış biçiminde yaz.

**Dokunacağı dosyalar.** `karadul/ghidra/headless.py` (`_extract_xrefs` ≈ 1717–1813, `_extract_cfg` ≈ 2025–2164, `_extract_call_graph` ≈ 882–970, `_save_output` ≈ 2451–2457; `scripts_output`'ta büyük çıktılar yerine yol), `karadul/analyzers/macho.py` (≈ 425–470: `static/ghidra_*.json`'ı yeniden serileştirmek yerine `ghidra_output/*.json`'dan kopya / sabit bağ), `tests/test_ol3_cikarim.py` (yeni), `scripts/measurement/mutation_specs_ol3.json` (yeni). Profil betiği `scripts/arge/olcek/profil_cikarim.py` (yeni; araştırma).
**Dokunmayacağı.** Adım bütçesi ve BSim (ÖL-2), bekçi (ÖL-1), `karadul/pipeline/steps/*` (okuyucular; şema değişmez).

**Adımlar.**
1. **Profil (önce):** T25 diliminde (tek Ghidra koşusu, `olcek_kos.py` + `JAVA_TOOL_OPTIONS` GC günlüğü) xref ve CFG'yi ayrı ölç: (i) Python tarafı çağrı sayısı ve süresi (adım içinde sayaç), (ii) JVM GC duraklama toplamı o aralıkta, (iii) `_extract_xrefs`'in "bütün simgeler" döngüsü (`:1792-1803`, gösteride 173 498 simge) tek başına. Hipotezler: H-a JVM yığın baskısı / GC; H-b simge döngüsü; H-c adres başına çağrı sayısı. Sonucu paket defterine yaz; hangisi baskınsa ondan başla.
2. xref: adres başına `getReferencesFrom` yerine `ReferenceManager.getReferenceSourceIterator(body, True)` (yalnız başvurusu olan adresler; API'yi Ghidra 12.1.2'de `javap` ile doğrula). Simge döngüsü: yalnız sayı üretiyor (`total_globals_with_xrefs`); `ReferenceManager.getReferenceDestinationIterator` ile sayım ya da aynı sayıyı veren daha ucuz yol.
3. CFG: blok başına `listing.getInstructions(block, True)` yerine fonksiyon başına tek yineleyici ve bloklara adres aralığıyla dağıtma; komut adı dökümü (`mnemonics`) korunur (CFG-iso adımı okuyor: `karadul/pipeline/steps/cfg_iso_match.py:43-62`).
4. Akış biçimli yazım: büyük çıktılar (`cfg`, `xrefs`, `call_graph`, `functions`, `strings`) üretilirken dosyaya yazılır (aynı JSON şeması; `json.JSONEncoder` ile parça parça); `scripts_output`'ta bu anahtarlar için özet + yol tutulur. Aşağı akışın okuduğu alanlar (`summary`, sayaçlar) aynı.
5. `macho.py`: `static/ghidra_<ad>.json` = `ghidra_output/<ad>.json`'ın kopyası (aynı disk → `os.link`, olmazsa `shutil.copyfile`). Not: bugün iki dosya `ensure_ascii` farkıyla bayt düzeyinde farklı (`headless.py:2455` False, `workspace.py:248` True); kabul ölçütü JSON eşitliği.
6. Testler: sahte program nesneleriyle eski ve yeni çıkarımın JSON eşitliği (xref, CFG, çağrı grafiği); akış yazıcının büyük listede bellek kullanımı (tracemalloc tepe < eski yolun yarısı).
7. Mutasyon tanımı.

**Kabul ölçütü.** (a) T25: xref ≤ 100 sn (bugün 348,7), CFG ≤ 150 sn (bugün 600,9); çıktılar JSON-eşit. (b) S8 alt kümesinde `ghidra_output/*.json` JSON-eşit, `.c` bayt eşit. (c) T25 tepe RSS (ÖLÇ-A örnekleyicisi) bugünkünden ≥ 0,5 GiB düşük (gerekçe: köprü sözlüğünde tutulan JSON 202,7 MB × 3,46–6,14 bellek çarpanı = 0,65–1,16 GiB; BULGULAR §3.4).
**Ön kayıt (`on_kayit_ol3.md`).** "Profil adımında baskın neden H-a / H-b / H-c'den biri olacak (hangisi olduğu ön kayıtta yazılmaz; payı ≥ %50 olan neden 'baskın' sayılır, yoksa 'belirsiz'). Değişiklikten sonra T25 xref ≤ 100 sn, CFG ≤ 150 sn, tepe RSS ≥ 0,5 GiB düşük; JSON eşitliği 9 / 9 hedefte."
**Sınama beklentisi.** Yeni testler; `tests/test_p16a_ghidra_sonuc.py`, `tests/test_large_binary_support.py` geçer; mutantlar ölür; tam takım 0 hata.
**Bayrak.** `analysis.akis_yazimi` (öntanım açık; kapalıyken eski yol) — geri dönüş için.

### ÖL-3b — İkili istihbarat aşamasının süresi

> **HIZ ile birleşme notu:** taramanın hızlandırılması (adım 1–2) HIZ hattının işidir (`HIZ.md` kalem 2: "istihbarat taraması 26 MB'de 14,7 dk neden"). ÖLÇEK için gerekli olan adım 3'tür (süre bütçesi + kısmi rapor).

**Amaç.** Gösteride statik aşamanın köprü dışı kısmı 912 sn (örneklem modeli 35 [10; 77] sn); bunun 14,8 dk'sı ikili istihbarat (`MachOAnalyzer.analyze_static` → `BinaryIntelligence.analyze` + `analyze_decompiled`, `karadul/analyzers/macho.py:472-531`). Nedeni ölçüp sınırlamak.

**Dokunacağı dosyalar.** `karadul/analyzers/binary_intelligence.py` (`analyze` ≈ 2088, `analyze_decompiled` ≈ 2142, `_cluster_strings` ≈ 2211), `tests/test_ol3b_istihbarat.py` (yeni), `scripts/measurement/mutation_specs_ol3b.json` (yeni).
**Dokunmayacağı.** `karadul/analyzers/macho.py` (ÖL-3), kural tabloları ve iddia kapıları (IMZA-01 / yayın D2'nin alanı: aynı dosya → **D2 ile sıralı**).

**Adımlar.**
1. Profil: gösteri girdisi (73 467 dizgi, 13 554 `.c`) ile `analyze` ve `analyze_decompiled`'ı Ghidra'sız, var olan çalışma alanından ayrı ayrı zamanla (`cProfile`; betik `scripts/arge/olcek/profil_istihbarat.py`, yeni). Girdi: `~/karadul_olcum/runs/gosteri-2026-11-19/ollama/ws/…/static/` (salt okur; koşu bittiyse).
2. Baskın kalemi (≥ %50) ön kayıtta adlandırmadan bul; dizgi sayısına göre karesel bir döngü varsa doğrusala indir (aynı sonuç), dosya taramasında süreç havuzu ek yükü baskınsa parça boyunu büyüt.
3. Süre bütçesi `analysis.istihbarat_butcesi_sn` (öntanım 300): aşılırsa kısmi rapor + `intel_status: "kismi"`.
4. Testler: eski / yeni çıktının JSON eşitliği (S8 ve gösteri çalışma alanı); bütçe aşımında kısmi.
5. Masum kapı doğrudan kip (`scripts/measurement/masum_kapi.py`, `bi` katmanı) sayıları değişmez.
6. Mutasyon tanımı.

**Kabul ölçütü.** Gösteri girdisinde ikili istihbarat ≤ 120 sn (bugün 887 sn: 12:14:43 → 12:29:30), `intelligence_report.json` JSON-eşit; S8'de eşit; masum kapı `bi` sayıları aynı.
**Ön kayıt (`on_kayit_ol3b.md`).** "Gösteride ≤ 120 sn; JSON eşitliği 9 / 9; masum kapı aynı."
**Bayrak.** `analysis.istihbarat_butcesi_sn` (öntanım 300; 0 = sınırsız).

### ÖL-5a — Paket yöneticisi: envanter → yineleme / bağ ayıklama → öncelik → bütçe → kalıcı kuyruk (D3, BICIM-09)

**Amaç.** `.app` analizini sınırlı ve öngörülebilir yapmak: aynı dosya bir kez, ana bileşen önce, bileşen başına ve toplam süre bütçesi, bütçe dışı ve kapsam dışı bileşenler için ucuz katman (üst veri), her bileşen bitince durum dosyası.

**Dokunacağı dosyalar.** `karadul/core/target.py` (`_detect_app_bundle` ≈ 227–366), `karadul/analyzers/app_bundle.py` (`analyze_static` ≈ 393–481, yeni yardımcılar), `karadul/stages.py` (yalnız `StaticAnalysisStage._execute_app_bundle` ≈ 595–683 ve ≈ 438'deki eskimiş "paralel" yorumu), `karadul/config.py` (yeni `PaketConfig` bölümü), `tests/test_ol5a_paket.py` (yeni), `scripts/measurement/mutation_specs_ol5a.json` (yeni).
**Dokunmayacağı.** `DeobfuscationStage._execute_app_bundle` ve `ReconstructionStage._execute_app_bundle` (`stages.py` ≈ 1086, ≈ 1425), `karadul/analyzers/macho.py`, `karadul/core/pipeline.py`, `karadul/cli.py` (devam ÖL-5b'de).

**Adımlar.**
1. Bileşen listesi (`target.py`): yolu `realpath`'e çevir, aynı gerçek dosya bir kez; sha256'ya göre aynı içerik bir kez (ilk görülen bileşen, ötekiler `yineleme_of=<ilk>` ile listede kalır, analiz edilmez). Envanterle: Ollama.app 26 → 16, FreeCAD.app 1 903 → 867. (Aynı kod farklı imzayla — KiCad'de `_pcbnew.kiface` ↔ `_pcbnew.so` — sha256 ile yakalanmaz; ÖL-11'e not.)
2. Kapsam dışı Mach-O listesi: `Contents/` altında bileşen kurallarına girmeyen her Mach-O (sihirli sayı; `envanter.py`'deki mantık) `kapsam_disi` türüyle listeye eklenir (analiz edilmez, raporda görünür). Bayrak `paket.genis_kapsam` açıksa `Contents/Resources`, `Contents/Helpers`, `Contents/PlugIns` altındaki çalıştırılabilir / bundle'lar ve `Contents/Frameworks/*.dylib` analiz kuyruğuna girer (öntanım kapalı; Ollama.app'te asıl sunucu `Resources/ollama`, KiCad.app'te asıl kod `PlugIns/*.kiface` bu yolla girer).
3. Öncelik ve ana bileşen ÖNCEDEN: katman (`app_bundle.component_tier`: uygulama kodu > MacOS ikilisi > çerçeve / dylib) + katman içinde dosya boyutu büyükten küçüğe; ana bileşen analizden önce seçilir (bugün sonradan, fonksiyon sayısıyla: `app_bundle.py:89-99`); seçim gerekçesi kayıtta. Ana bileşen kuyruğun başında.
4. Bütçe: `paket.toplam_butce_sn` (öntanım 7 200), `paket.bilesen_butce_sn` (öntanım 3 600). Bileşen analizine geçen ayarın kopyasında `timeouts.ghidra` ve `timeouts.ghidra_adim` (ÖL-2) kalan bütçeyle sınırlanır. Toplam bütçe dolunca kalan bileşenler `butce_disi` + ucuz katman.
5. Ucuz katman (Ghidra yok): bileşen başına yol, boyut, sha256, mimari, `LC_ID_DYLIB` / `LC_UUID` (lief; `macho.py` `_run_lief`'in yaptığı okuma, kod kopyalanmadan çağrılır), üçüncü taraf sınıfı (yol adından; `scripts/arge/olcek/envanter.py` `BILESEN_KALIPLARI` ürün modülüne taşınır: `karadul/core/bilesen_sinifi.py`, yeni). Sınıf "doğrulanmamış" etiketiyle; hiçbir bileşen adından ötürü sessizce atlanmaz (BICIM-11 sınıfı risk).
6. Kalıcı kuyruk: her bileşen bitince `static/bundle_queue.json` atomik yazılır (`durum`: `bekliyor` / `bitti` / `basarisiz` / `butce_disi` / `yineleme` / `kapsam_disi`; süre; fonksiyon sayısı). `bundle_analysis.json` bugünkü şemayla sonda yine yazılır (+ yeni alanlar).
7. İlerleme olayı: `asama=paket adim=paket.bilesen bilesen="…" islenen=i toplam=n durum=…`.
8. Testler (Ghidra yok; sahte analizci, `tests/test_ps4_app_bundle.py` kalıbı): bağ / yineleme ayıklama, kapsam dışı liste, öncelik sırası, bütçe dolunca `butce_disi`, kuyruk dosyası her bileşenden sonra güncel, ana bileşen ilk; mutasyon tanımı (≥ 10 mutant).

**Kabul ölçütü.** (a) Ollama.app (MIT): analiz edilen bileşen 16 (bugün 26); kapsam dışı Mach-O listesi raporda (18 satır, envanterle aynı); ana bileşen (`Contents/MacOS/Ollama`) ilk biten. FreeCAD.app'te bileşen listesi 867 tekil (bugün 1 903); KiCad.app'te `paket.genis_kapsam: true` ile `PlugIns/_pcbnew.kiface` kuyrukta. (b) PAKET hedefinde (ÖLÇ-1) toplam süre ≤ `paket.toplam_butce_sn` + 600 sn; ilk rapor (ana bileşenin `static/ghidra_status.json`'u) toplam bütçenin ilk yarısında. (c) Tek bileşenli `.app`'te (`tests/test_app_bundle_pipeline.py` örneği) çıktı bugünküyle aynı.
**Ön kayıt (`on_kayit_ol5a.md`).** "Ollama.app 26 → 16 bileşen; kapsam dışı 18; PAKET hedefinde toplam ≤ bütçe + 10 dk; bütçe dışı kalan bileşenlerin hepsinde ucuz katman satırı var (eksik 0)."
**Sınama beklentisi.** Yeni testler, `tests/test_app_bundle_pipeline.py`, `tests/test_ps4_app_bundle.py`, `tests/test_app_bundle_jvm_exit.py` geçer; mutantlar ölür; tam takım 0 hata.
**Bayrak.** `paket.yonetici` (öntanım açık; kapalıyken bugünkü sıralı döngü), `paket.genis_kapsam` (öntanım kapalı), `paket.toplam_butce_sn`, `paket.bilesen_butce_sn`.

### ÖL-6 — Bellek ve disk bekçisi

**Amaç.** Koşudan önce disk tahmini ve yetersizse açık ret; koşu sırasında süreç tepe belleği (Python + JVM aynı süreçte) bütçeyi aşarsa sonraki adımları durdurup kısmi bitirmek.

**Dokunacağı dosyalar.** `karadul/core/pipeline.py` (`run` ≈ 257–492: ön denetim + bekçi iş parçacığı), `karadul/core/workspace.py` (boş alan ve tahmin yardımcıları), `karadul/ghidra/headless.py` (yalnız decompile parça döngüsünde ve `_extract_*` döngülerinde ÖL-2'nin `son_an` denetimine "bellek bayrağı" eklenmesi), `karadul/config.py` (`KaynakConfig`), `tests/test_ol6_kaynak.py` (yeni), `scripts/measurement/mutation_specs_ol6.json` (yeni).
**Dokunmayacağı.** `karadul/analyzers/*`, reconstruct adımları (ÖL-7).

**Adımlar.**
1. Disk tahmini (Ghidra'dan önce, yalnız bölüm başlığı): kod baytı (`lief`) × kod baytı başına disk oranı. Oran 119'dan: çalışma alanı diski ↔ kod baytı modeli (BULGULAR §3.2; `olcek_egri.py` `disk_calisma_alani_bayt|metin_bayt`) — ürüne sabit olarak değil, ölçülmüş tablo olarak (`karadul/core/kaynak_tahmini.py`, yeni; kaynak ve tarih yorumda).
2. Boş alan < tahmin × `kaynak.disk_guvenlik_carpani` (öntanım 1,5) ise: koşu başlamaz, çıkış 2, ileti "tahmini disk X GB, boş Y GB; --output-dir başka diske verin ya da kaynak.disk_on_denetim: false". Paket hedefinde bileşen başına.
3. Bellek bekçisi: 10 sn'de bir `resource.getrusage(RUSAGE_SELF).ru_maxrss` (macOS'ta bayt; süreç içi JVM dahil). `kaynak.azami_bellek_orani` (öntanım 0,85 × RAM) aşılınca paylaşılan iptal bayrağı → decompile ve çıkarım döngüleri (ÖL-2 `son_an` denetimiyle aynı yerde) kısmi biter; `step_errors["bellek"]`.
4. Kısmi bitiş çıkış 3; `ILERLEME … durum=kismi neden="bellek sınırı"`.
5. Testler: sahte boş alan / sahte RSS ile ret ve iptal; öntanımda 119'luk bir ikilide davranış aynı.
6. Mutasyon tanımı.

**Kabul ölçütü.** (a) `kaynak.azami_bellek_orani: 0.05` ile Debian sqlite3 koşusu sınır aşımından sonra ≤ 30 sn'de kısmi biter (çıkış 3). (b) Sahte boş alan 1 GB iken T100 için ret iletisi ve çıkış 2, Ghidra başlamadan (≤ 5 sn). (c) Öntanımla S8 alt kümesinde çıktı aynı.
**Ön kayıt.** "Bellek sınırı aşımından sonra kısmi bitiş ≤ 30 sn; disk ön denetimi ≤ 5 sn; alt küme 8 / 8 aynı."
**Bayrak.** `kaynak.disk_on_denetim` (öntanım açık), `kaynak.disk_guvenlik_carpani` (1,5), `kaynak.azami_bellek_orani` (0,85; 0 = kapalı).

### ÖL-5b — Yarıda kalan koşuyu sürdürme

**Amaç.** Ölmüş ya da durdurulmuş paket koşusunu bitmiş bileşenleri yeniden yapmadan sürdürmek.
**Dokunacağı dosyalar.** `karadul/cli.py` (`analyze`'a `--devam <çalışma alanı>`), `karadul/core/pipeline.py` (verilen çalışma alanını yeniden kullanma: `Workspace(workspace_dir=…)`, `karadul/core/workspace.py:47-61`), `karadul/analyzers/app_bundle.py` (`bundle_queue.json`'dan bitenleri atlama), `tests/test_ol5b_devam.py` (yeni), `scripts/measurement/mutation_specs_ol5b.json` (yeni).
**Dokunmayacağı.** `karadul/core/target.py` (ÖL-5a bitti), `karadul/ghidra/*`.
**Adımlar.** 1. `--devam`: çalışma alanında `static/bundle_queue.json` ve `raw/target_info.json` var mı, hedefin sha256'sı aynı mı denetle; değilse çıkış 2. 2. Kuyrukta `bitti` olan bileşen atlanır; `bekliyor` / `basarisiz` (isteğe bağlı) yeniden. 3. Tek ikili hedefte `--devam` bugün desteklenmez: açık ileti (ÖL-9 önbelleği gelince). 4. Aşamalar: statik bittiyse ve `ghidra_output` tamsa reconstruct'tan devam (`pipeline_result` ara kayıtları her aşama sonunda yazılır). 5. Testler: yarıda kesilmiş sahte kuyrukla devam; sha256 uyuşmazlığında ret; bitmiş bileşen yeniden çağrılmaz (sayaç). 6. Mutasyon tanımı.
**Kabul ölçütü.** Ollama.app'te koşu ana bileşenden sonra SIGTERM ile durdurulur, `--devam` ile sürdürülür: bitmiş bileşen 0 kez yeniden analiz edilir; son `bundle_analysis.json` kesintisiz koşununkiyle (süreler hariç) JSON-eşit.
**Ön kayıt.** "Yeniden analiz edilen bitmiş bileşen 0; kesintisiz koşuyla eşitlik (süre alanları hariç)."
**Bayrak.** Yok (yeni seçenek).

---

## 4. Yayından sonra

Bu paketler yayını beklemez; her biri ÖLÇ-2 sayılarıyla yeniden önceliklendirilir.

### ÖL-7 — Reconstruct belleği ve kopyaları
**Amaç.** Fonksiyon başına ~10 kopya `.c` (BULGULAR K12) ve bütün metinlerin bellekte tutulması (K11).
**Dosyalar.** `karadul/pipeline/steps/feedback_loop.py` (`_refresh_file_cache` ≈ 321–352), `karadul/pipeline/steps/_feedback_loop_iter.py`, ara dizin yazan adımlar (önce `grep -rn "get_stage_dir(\"reconstructed\")" karadul/pipeline/steps` ile liste çıkar), yeni testler. **Dokunmaz:** ad kanallarının mantığı.
**Adımlar.** 1. Hangi ara dizini kim okuyor: okuyucu haritası (betik). 2. Okuyucusu olmayan ara kopya → yazılmaz (bayrak). 3. Değişmeyen dosya → sabit bağ. 4. `file_cache` → isteğe bağlı okuma (LRU, sınırlı bayt). 5. Yineleme süre sınırını yineleme İÇİNDE denetle (`feedback_loop.py:180-191` bugün sonradan). 6. Testler + mutasyon.
**Kabul.** 119'da ad haritası 119 / 119 aynı; çalışma alanı dosya sayısı fonksiyon başına 12,2 → ≤ 4; disk ≥ %50 düşük.
**Ön kayıt.** "Ad haritası aynı; dosya / fonksiyon ≤ 4; disk ≥ %50 düşüş." **Bayrak.** `reconstruct.ara_kopyalar` (öntanım: ölçümden sonra karar).

### ÖL-8 — Arayüz ölçeği
**Amaç.** `build_model` bütün `.c` dosyalarını okuyor ve bütün fonksiyonları tek JSON'da veriyor (K13).
**Dosyalar.** `ui/server.py` (`build_model` ≈ 351–460, `/api/model`, `/api/functions`), `ui/index.html` (liste), yeni testler.
**Adımlar.** 1. ÖLÇ-0'da gösteri çıktısıyla bugünkü `/api/model` süresi ve sunucu RSS'i. 2. Çağrı kenarları yalnız `call_graph.json`'dan (metin taraması yalnız yedek). 3. Fonksiyon metni tıklayınca okunur. 4. `/api/functions?baslangic=&adet=&ara=` sayfalama. 5. Liste sayaçları gerçek toplamdan (sahte sayı yok). 6. Testler.
**Kabul.** 13 559 fonksiyonlu gösteri çalışma alanında `/api/model` ilk yanıt ≤ 2 sn, sunucu RSS artışı ≤ 300 MB. **Bayrak.** Yok.

### ÖL-9 — sha256 anahtarlı önbellek (Ghidra projesi + `ghidra_output`) (E3, B-C4)
**Amaç.** Aynı ikiliyi yeniden açınca Ghidra'yı baştan koşmamak; tek ikilide `--devam`; KaradulLM'in "yeniden hesapla"sı.
**Dosyalar.** `karadul/analyzers/macho.py` (`_run_ghidra_legacy` ≈ 1247–1300), `karadul/ghidra/project.py`, `karadul/core/onbellek.py` (yeni), `karadul/config.py` (`OnbellekConfig`), yeni testler.
**Adımlar.** 1. Anahtar = sha256(analiz edilen dilim) + Ghidra sürümü + çözümleyici ayarlarının özeti + Karadul sürümü. 2. Proje silinmek yerine önbelleğe taşınır (boyut sınırı, LRU). 3. Önbellek varsa `open_program(analyze=False)` + `shouldAskToAnalyze` false → otomatik analiz atlanır. 4. `ghidra_output` de anahtarla saklanır; eşleşirse köprü hiç açılmaz. 5. Disk sınırı `onbellek.azami_gb`. 6. Testler + mutasyon.
**Kabul.** T25 ikinci koşu / birinci koşu ≤ 0,3 (köprü süresi); çıktılar JSON-eşit; önbellek boyutu dilim başına ölçülür (gösteride proje 84 704 KiB = dilimin 3,3 katı).
**Ön kayıt.** "İkinci koşu oranı ≤ 0,3; eşitlik 9 / 9." **Bayrak.** `onbellek.ghidra` (öntanım kapalı; ölçümden sonra karar).

### ÖL-10 — Tembel derinlik (büyük ikili kipi)
**Amaç.** 100 MB+ tek ikilide ilk raporu saatler yerine dakikalarda vermek: ucuz katman + otomatik analiz + fonksiyon listesi + çağrı grafiği; decompile ve ad hattı yalnız seçilen fonksiyonlarda (giriş noktası komşuluğu, dizgisi olanlar, analistin / KaradulLM'in istediği).
**Dosyalar.** `karadul/ghidra/headless.py` (decompile kümesi parametresi), `karadul/analyzers/macho.py`, `karadul/stages.py` (reconstruct girişinde küme), `karadul/config.py` (`BuyukIkiliConfig`), önkoşul ÖL-9 (proje önbelleği: sonradan decompile için).
**Adımlar.** 1. Eşik: kod baytı `buyuk_ikili.esik_mb` (öntanım: ÖLÇ-2'den). 2. Seçim kuralı ve sayısı (ör. ilk 5 000 fonksiyon; kural ön kayıtlı). 3. Seçilmeyen fonksiyonlar raporda "decompile edilmedi (büyük ikili kipi)" — kayıp sayacı (D1) bunu sayar. 4. İsteğe bağlı decompile komutu (`karadul decompile <ws> <adres…>`) önbellekteki projeden. 5. Ad ölçümü: 119'da kip kapalıyken aynı; kip açıkken seçilen fonksiyonlarda ad haritası tam kipteki ile aynı (kesinlik bozulmaz). 6. Testler.
**Kabul.** T100'de ilk rapor ≤ 60 dk; seçilen fonksiyonlarda ad / `.c` tam kiple aynı.
**Ön kayıt.** "T100 ilk rapor ≤ 60 dk; seçilen kümede eşitlik %100." **Bayrak.** `buyuk_ikili.tembel` (öntanım kapalı).

### ÖL-11 — Bilinen bileşen (KİMLİK hattı ve C5 ile)
**Amaç.** Üçüncü taraf çalışma zamanını (Electron / Chromium / Qt / Python / LLVM) yol adından değil kimlikten (sha256 izin listesi; `LC_ID_DYLIB` + sürüm; KİMLİK hattının başvuru eşlemesi) tanıyıp ucuz katmanda bırakmak.
**Dosyalar.** `karadul/core/bilesen_sinifi.py` (ÖL-5a'nın), yeni veri dosyası (konumu `karadul/config.py` `resolve_data_root` ile; önce `grep -n resolve_data_root karadul/config.py`), `karadul/analyzers/app_bundle.py`.
**Adımlar.** 1. Kimlik kaynakları ve güven düzeyi. 2. Yol adı sınıfı yalnız "aday". 3. Kimlik doğrulanmadan hiçbir bileşen analiz dışı bırakılmaz (yalnız sıra sonuna). 4. Masum / zararlı deney: zararlı bir dylib'e üçüncü taraf adı verilince sınıflama "doğrulanmadı" kalır ve bileşen analiz kuyruğunda kalır. 5. Testler.
**Kabul.** Masum kapı benzeri deneyde yanlış "bilinen bileşen" 0; envanterdeki üçüncü taraf baytının ≥ %50'si kimlikten tanınır.
**Bayrak.** `paket.bilinen_bilesen` (öntanım kapalı).

---

## 5. Gerekli veri ve araç

- İndirme gerekmiyor: T25, T100 makinede; T300 ve PAKET için §2 tablosu (envanterden; açık kaynak).
- Araç: `/opt/homebrew/Cellar/llvm/23.1.6/bin/llvm-size`, `llvm-objdump` (yalnız açık kaynak dosyalarda bölüm başlığı ve `LC_FUNCTION_STARTS`); `/usr/bin/time`, `ps`. Profil için ek araç (py-spy, async-profiler) kurulmaz; JVM GC günlüğü `JAVA_TOOL_OPTIONS` ile.
- Makine: ölçümler başka ajan yokken (E-serisi ölçümleri "boş makine" ister: `YON.md` §4).

## 6. Riskler ve bilinmeyenler

- **Örneklem dışı sapma açıklanmadı.** xref / CFG / BSim / ilk adım gösteride örneklem modelinin 2,2–9,7 katı. Yük, JVM yığın baskısı ve Go'ya özgülük ayrılmadı (ÖL-3 adım 1). Tahminlerin üst uçları bu yüzden çok geniş.
- **Gösteri koşusu sürüyordu;** reconstruct ve tepe RSS bu turda yok (ÖLÇ-0).
- **"Kapsam küçültülmez" ile bütçe arasındaki gerilim:** bütçe dışı bileşen ya da adım silinmiyor, kısmi / ertelenmiş ve görünür kalıyor. Berke'nin kararı gerekirse: büyük ikilide BSim ingest'inin bütçelenmesi (ÖL-2 adım 4) ve paket bütçesi öntanımları (ÖL-5a adım 4).
- **Yol adından üçüncü taraf sınıflaması doğrulanmadı;** yalnız rapor / sıra için kullanılır, atlama için değil (ÖL-11'e kadar).
- **`rglob` davranışı Python sürümüne bağlı:** 3.12.7'de bağlı dizine inmiyor (deney: DEFTER); 3.13'te `recurse_symlinks` öntanımı değişirse bileşen sayısı değişebilir; ÖL-5a testi bunu sabitler.
