# ÖL-10 — tembel derinlik / büyük ikili kipi: tasarım (2026-11-23)

Paket: OL10 (KARARLAR A-18, A-24). Yalnız belge; kod, test, ayar yazılmadı; Ghidra koşulmadı. Bu belge kendi başına uygulanabilir olacak biçimde yazıldı: uygulayan Opus ajanları bu oturumu görmeyecek.

## Berke için özet

1. Bugün Karadul her fonksiyonu baştan sona işliyor; bu yüzden 26,6 MB'lık Ollama dilimi 2 saat 9 dakika sürdü, 100 MB'lık bir program için yalnız Ghidra kısmı 14–39 saat tahmin ediliyor.
2. Büyük ikili kipi işi üç katmana böler. **Katman 0** (Ghidra yok): programda yazılı adlar, dizgiler, içe aktarımlar, fonksiyon sınırları. 95 MB'lık programda bunun çekirdeği 0,65 saniyede okundu.
3. **Katman 1:** Ghidra programı çözümler; fonksiyon listesi, çağrı grafiği, dizgi başvuruları çıkar. Kod üretilmez. 100 MB'ta 38–72 dakika (TAHMİN).
4. **Katman 2:** okunabilir C kodu yalnız seçilen fonksiyonlar için üretilir: programın kendi kodu önce; dilin standart kitaplığı ve çalışma zamanı kendiliğinden hiç. Ollama'da kendiliğinden seçilebilen küme 13 160 fonksiyonun 4 619'u (%35,1) çıktı; gösterinin ad verdiği 17 fonksiyonun 17'si de sıranın ilk 4 028'inde.
5. Analist ne görür: birkaç dakikada ilk özet; 100 MB'lık programda yaklaşık 1–2 saatte (TAHMİN 60–110 dk) öncelikli 3 000–5 000 fonksiyonun okunabilir kodu ve adları. Kötü senaryoda süre bütçesi keser; kısmi ama açık etiketli rapor çıkar.
6. Seçilmeyen her fonksiyon listede "kodu üretilmedi" diye görünür; adı programın içinde yazılıysa adıyla. Analist istediği fonksiyonu sonradan tek komutla ya da tıklayarak açtırır; KaradulLM de isteyebilir, ama onay analisttedir.
7. Bilerek sonraya bırakılanlar: dilin kendi kitaplığına ait fonksiyonların kodu, seçilmeyen fonksiyonların ayrıntılı dökümü, benzerlik araması (BSim). Hiçbiri silinmez; "ertelendi" diye sayılır ve istenince yapılır. Böyle biten koşu "tam" değil "kısmi" görünür: yapılmayan iş başarı gibi gösterilmez.
8. Planın eski hedefi ("100 MB'ta ilk rapor ≤ 60 dakika") bu hâliyle tutmaz: Ghidra'nın kendi çözümlemesi tek başına 38–72 dakika (TAHMİN) ve tembel kip onu kısaltmaz. Hedef üç parçaya bölündü (§6).
9. Bu turda ölçülen yeni bulgu: pahalı "çapraz başvuru" adımının fonksiyon başına çıktısı, Katman 1'in iki dosyasından Ghidra'sız türetilebiliyor (Ollama: 13 559 / 13 559 fonksiyonda aynı). Bu hem süreyi düşürür hem kısmi analizde ad kurallarını bozulmaktan korur.
10. İş 10 alt pakete bölündü. İlk üçü bugün yazılabilir ve en büyük bilinmeyenleri ürüne dokunmadan ölçer; ürün değişikliği, Ghidra köprüsü dosyasında sırada bekleyen altı paketten sonra girer.

## Karar listesi (Berke / ana oturum)

| No | Karar | Kimin | Öneri | Gerekçe (tek satır) |
|---|---|---|---|---|
| K-1 | T100 kabul hedefi "ilk rapor ≤ 60 dk" üç parçaya bölünsün (§6.1) | ana oturum (ön kayıt değişikliği) | evet | Katman 1 TAHMİN [38; 72] dk, 60 dakikayı içeriyor; tembel kip Katman 1'i kısaltmıyor |
| K-2 | Seçilen kümede "ad eşitliği %100" yerine "tam kipte olmayan ad 0, farklı ad 0; eksik ad sayılır" | ana oturum | evet | ad hattının teklik / susturma / çakışma kuralları nüfusa bağlı (§3.3); eşitlik yapı gereği garanti değil, yanlış ad üretmemek garanti edilebilir |
| K-3 | Tembel kipte biten koşunun durumu `kismi`, çıkış kodu 3 (yeni kod yok) | ana oturum | evet | "decompile edilmedi" başarı gibi görünmemeli; var olan `partial_reasons` yolu yeter (`karadul/core/pipeline.py:80-85`) |
| K-4 | Tembel kipte BSim ertelenir (koşmaz; `bsim_status: "ertelendi"`) | ana oturum ("kapsam küçültülmez" ile ilişkisi) | evet | gölge kipte, ad haritasına girmiyor; T100'de TAHMİN 6,6 saatten fazla; ertelenen iş sayılıyor ve istenince koşuyor |
| K-5 | Kitaplık / çalışma zamanı sınıfı (Go `runtime`, standart kitaplık) kendiliğinden hiç seçilmez; yalnız istekle | Berke (ürün davranışı) | evet | Ollama'da kodun %58,5'i bu sınıf; adları üst veriden %99,99 kesinlikle biliniyor, kaynağı açık |
| K-6 | KaradulLM decompile'ı kendisi başlatmaz; "decompile isteği" önerisi açar, analist onaylar | Berke (ürün davranışı) | evet | var olan sözleşme süreç başlatan aracı yasaklıyor (`karadul/lm/tools/__init__.py:50-55`) |
| K-7 | İki yeni ayar alanı: `buyuk_ikili.decompile_butcesi_sn`, `buyuk_ikili.secim_ust_sinir`; ayrıca `esik_mb = 0`'ın anlamı "eşik yok: `tembel` açıkken her ikili tembel kipte" olarak düzeltilsin (yama ile; A-19) | ana oturum | evet | seçim sayısı süre bütçesinden türemeli (A-9); bugünkü yorum ("0 = kip devreye girmez") küçük ikilide kipi denemeyi olanaksız kılıyor (`esik_mb` tam sayı MB) |
| K-8 | Öntanım: kip kapalı kalır (`buyuk_ikili.tembel = False`, `esik_mb = 0`); açılış eşiği OL10-J ölçümünden sonra | ana oturum | evet; aday eşik 16 MiB kod | A-14 mantığı: ölçülmeden öntanım değişmez; 16 MiB = gösteri kodunun (5,25 MiB) 3 katı, TAHMİN |
| K-9 | Ghidra projesi tembel kipte silinmez (çalışma alanında kalır) | ana oturum (disk) | evet | sonradan decompile ve sürdürme için şart; T100'de TAHMİN [0,3; 0,9] GB |
| K-10 | Katman 1'i kısaltacak "bölgesel çözümleme" (yalnız seçilecek adres aralıklarını çözümlemek) bu planda yok; OL10-C ölçümünden sonra ayrı Ar-Ge | ana oturum | evet | çıktıyı tam kipten farklılaştırır (çağıran listeleri eksilir); önce Katman 1'in gerçek süresi ölçülmeli |
| K-11 | Boş makine gecesi (A-26) gelince OL10-C'nin süre kolu aynı geceye eklensin (T100; `--tek`) | Berke (gece izni) | evet | tasarımın en büyük iki bilinmeyeni (Katman 1 süresi, kayıtlı projeyi yeniden açma süresi) yalnız böyle kesinleşir |

## 0. Künye, yöntem, terimler

- **Taban:** main `f2b0db5` (2026-11-23 08:11; worktree `git merge --ff-only main`). Bütün dosya:satır atıfları bu commit'te `grep` / `sed -n` ile doğrulandı (liste Ek A). P16e (`karadul/ghidra/headless.py`) ve PUV6a (`karadul/stages.py`, `karadul/pipeline/steps/_feedback_naming_*.py`, `karadul/core/naming_labels.py`) bugün yazılıyor; main'e girince satır numaraları kayar. Her atfın yanında işlev adı var: uygulayan ajan `grep -n "def <ad>"` ile yeniden bulur, satır numarasına güvenmez.
- **Sayıların kaynağı:** belge yolu ya da komut her sayının yanında. Bu turda üretilen sayılar salt okur komutlardan gelir (Ek B; komut metinleri ve çıktıları depo dışında, `~/karadul_olcum/runs/dalga1-2026-11-23/OL10/`). Yeni Ghidra / `karadul analyze` koşusu yok. Süre içeren iki küçük ölçüm (üst veri okuma) "yük altında" etiketlidir.
- **TAHMİN** etiketli her sayı dış değerlemedir; aralığıyla ve kaynağıyla yazıldı. 119 küçük ikiliden kurulan ölçek modeli gösteride 10 öngörünün 7'sinde tutmadı (`olcek/OLC0.md`); bu yüzden büyük ikili TAHMİN'leri karar için değil, bütçe ve ön kayıt aralığı için kullanılır.
- **Terimler:**
  - *Katman 0 (K0):* Ghidra'sız okuma (ikilinin baytları).
  - *Katman 1 (K1):* Ghidra içe aktarma + otomatik analiz + fonksiyon listesi + dizgiler + çağrı grafiği (decompile yok).
  - *Katman 2 (K2):* seçilen fonksiyonların decompile'ı + onlara bağlı döküm (CFG, P-code) + ad hattı.
  - *Seçili küme (S):* K2'ye giren fonksiyonlar. *Ertelenen:* K2'ye girmeyen fonksiyon.
  - *Gövdeli / gövdesiz fonksiyon:* `.c` dosyası olan / olmayan.
  - *Tam kip:* bugünkü davranış (her fonksiyon decompile edilir).

## 1. Zemin: bugünkü akış ve eldeki sayılar

### 1.1 Köprünün sırası (kod okuması)

`GhidraHeadless._analyze_pyghidra` (`karadul/ghidra/headless.py:329-744`) tek `pyghidra.open_program` bağlamında (`:377-382`) şu sırayla koşar; her adım çıktısını biter bitmez `_save_output` ile yazar:

| # | Adım | Satır | Çıktı | Tembel kipte |
|---|---|---|---|---|
| 0 | otomatik analiz (`_run_auto_analysis`, `:786-830`) | `:387-394` | — | K1: aynen |
| 1 | fonksiyon listesi (`_extract_functions`, `:868-905`) | `:434-445` | `functions.json` | K1: aynen |
| 2 | dizgiler + başvuranları (`_extract_strings`, `:926-993`) | `:447-456` | `strings.json` | K1: aynen |
| 3 | çağrı grafiği (`_extract_call_graph`, `:996-1084`) | `:458-472` | `call_graph.json` | K1: aynen |
| 4 | **decompile** (`_decompile_functions`, `:1243-1296`) | `:474-508` | `decompiled/*.c`, `decompiled.json` | K2: yalnız S |
| 5 | tipler | `:510-525` | `types.json` | K2: aynen (program geneli; gösteride 6,7 sn) |
| 6 | xref (`_extract_xrefs`, `:1874-1971`) | `:527-542` | `xrefs.json` | **koşmaz; K1 çıktılarından türetilir** (§1.3) |
| 8 | P-code yazımı (`_write_pcode_jsonl`, `:2122`) | `:544-576` | `pcode.jsonl`, `pcode.json` | K2: yalnız S (decompile sonucundan) |
| 9 | CFG (`_extract_cfg`, `:2182`) | `:578-593` | `cfg.json` | K2: yalnız S |
| 11 | FunctionID eşleşmeleri | `:595-610` | `function_id.json` | K1 sonunda: aynen (gösteride 0,1 sn) |
| 11.5 | BSim ingest + sorgu | `:612-677` | `bsim_matches.json` | ertelenir (K-4) |
| 10 | birleşik özet | `:679-711` | `combined_results.json` | K1 ve K2 sonunda |

Seçim için gereken her girdi (fonksiyon listesi, dizgi başvuruları, çağrı grafiği) decompile'dan ÖNCE diskte: seçim kuralı adım 3 ile 4 arasına girer, başka hiçbir adımın çıktısını beklemez.

Decompile tarafında işe yarayan var olan düzenek:
- Fonksiyon başına iş `_decompile_single_function` (`:1543-1744`): `.c` dosyası (başlık + C + disassembly yorumu), fonksiyonun xref'i (`_extract_func_xrefs`, `:1143`), yığın çerçevesi, seçici P-code. Fonksiyonlar arası durum taşımıyor: bir fonksiyonun çıktısı öbürünün decompile edilip edilmediğine bağlı değil (sonuç programa geri yazılmıyor). **Bu, "seçilen fonksiyonun `.c`'si tam kiptekiyle aynı" beklentisinin dayanağıdır; ölçülecek (§6, H-C1).**
- Dosya adı planı `_plan_decompile_filenames` (`:1467-1483`) bütün fonksiyonlar üstünden, adres sırasıyla yapılıyor (`:1335-1337`). Tembel kipte de BÜTÜN fonksiyonlar üstünden yapılmalı; yoksa aynı adlı fonksiyonların dosya adı eki değişir.
- Decompile edilmeyen fonksiyon için kayıt kalıbı var: `_lost_entry(func, error, skipped=True)` (`:1486-1494`), sayaçları `_finalize_decompile_result` (`:1497-1540`; `losses.decompile_skipped`). Bugün yalnız "toplam decompile süresi doldu" durumunda kullanılıyor (`:1355-1361`). Tembel kip bunun yanına AYRI bir durum ekler ("ertelendi"); `skipped` ile karıştırılmaz (§4).
- Başarı hükmü `_judge_outcome` (`:833-861`): en az bir fonksiyon decompile edilmiş olmalı. Tembel kipte K1 için ayrı hüküm gerekir (OL10-D adım 2). Seçili küme olağan durumda boş değildir (giriş fonksiyonu, kendi kod, bilinmeyenler); boş kalırsa (ör. sınırlar 0 fonksiyon bıraktı ya da bütün decompile'lar başarısız) koşu K1 sonucuyla `kismi` biter ve yeniden kurma aşaması "gövde yok" nedeniyle atlanır: bugün `.c` yoksa `binary_prep` hata fırlatıyor (`karadul/pipeline/steps/binary_prep.py:67-71`) ve aşama başarısız sayılıyor; tembel kipte bu bir hata değildir (OL10-F adım 6).

Köprünün dışı:
- Statik aşama köprüyü `MachOAnalyzer._run_ghidra_legacy` içinden çağırır (`karadul/analyzers/macho.py:1254-1307`; çağrı `:1281-1287`) ve **Ghidra projesini her koşunun sonunda siler** (`:1293-1307`; `GhidraProject.cleanup`, `karadul/ghidra/project.py:47-66`). Sonradan decompile için proje kalmalı (K-9).
- Köprü dönünce her çıktı ikinci kez `static/ghidra_<ad>.json` olarak yazılır (`macho.py:434-438`); ad hattı bu kopyaları okur (`karadul/pipeline/steps/ghidra_metadata.py:94-133`).
- **Köprünün ikinci çağıranı var:** hedef türü `GO_BINARY` ise (ince Go ikilisi; hedef setinin keşif ikilisi docker-cli bu türden: Ek B-5; sınama ikilisi docker-compose açılmadı, aynı türden olması beklenir) statik aşama Go çözümleyicisinden sonra `MachOAnalyzer._run_ghidra`'yı DOĞRUDAN çağırır, `analyze_static`'ten geçmez (`karadul/stages.py:490-537`; yapıtları kendisi yazar `:501-507`; `_record_ghidra_outcome` çağrılmadığı için bu yolda `ghidra_status.json` yazılmıyor). Tembel akış bu yüzden iki çağıranın ortak noktasına, `_run_ghidra_legacy`'ye bağlanır (OL10-E).
- Yeniden kurma aşaması `.c` dosyalarını dizinden toplar: `binary_prep` `decompiled_dir.rglob("*.c")` (`karadul/pipeline/steps/binary_prep.py:58-71`; dosya yoksa hata). Yani ad hattı "bütün fonksiyonların `.c`'si var" varsaymıyor, var olan dosyalarla çalışıyor; ama bazı adımlar `ghidra_functions.json`'daki BÜTÜN fonksiyonlar üstünde dönüyor (en önemlisi `c_namer`, `karadul/reconstruction/c_namer.py:2245`). Ayrıntı §3.

### 1.2 Sayılar

| Sayı | Değer | Kaynak |
|---|---|---|
| Gösteri (Ollama 0.40.3 arm64 dilimi, 26 627 984 B; yük altında, yük 40–60): toplam | 7 729,1 sn | `olcek/OLC0.md` |
| ↳ Ghidra köprüsü / statik aşamanın köprü dışı / deobfuscate / reconstruct | 3 815,4 / 912,0 / 663,5 / 2 353,1 sn | `olcek/OLC0.md` |
| ↳ köprü adımları: ilk adım (JVM + içe aktarma + otomatik analiz + liste) / dizgi / çağrı grafiği | 320,6 / 2,6 / 55,6 sn → **K1 = 378,8 sn** | `olcek/OLC0.md` (dosya zamanlarından) |
| ↳ decompile / tip / xref / P-code / CFG / FunctionID / BSim | 523,9 / 6,7 / 348,7 / 3,1 / 600,9 / 0,1 / 1 951,9 sn | `olcek/OLC0.md` |
| ↳ fonksiyon: toplam / program / taslak (thunk) | 13 559 / 13 160 / 399 | `static/ghidra_status.json` (gösteri çalışma alanı) |
| ↳ program fonksiyonlarının gövde baytı toplamı | 5 414 161 B | Ek B-1 (`ghidra_functions.json` `size` toplamı) |
| ↳ decompile hızı | 523,9 / 13 559 = 0,0386 sn / fonksiyon; 101,5 sn / MiB gövde (9 iş parçacığı, duvar süresi, yük altında) | türetme |
| ↳ ad haritasındaki fonksiyon adı | 17 (13 160 fonksiyonda) | `karsi/KARSI.md` İ-1; Ek B-1 |
| ↳ üst veriden okunan ad | Go 10 600 + ObjC 151 | `docs/arge/2026-11-20_dalga0/DURUM.md` (PUV1, PUV2) |
| T100 (`mlir-transform-opt`, 94 869 440 B; kod 56 755 068 B; 163 141 fonksiyon başlangıcı): K1 | TAHMİN [2 282; 4 327] sn = [38,0; 72,1] dk; kötümser 22 079 sn (6,1 sa) | `~/karadul_olcum/runs/arge-2026-11-19/olcek/egri.json` → `dis_degerleme_TAHMIN` → T100 (ilk adım [1 830; 3 811] + dizgi 27 + çağrı grafiği [426; 490]); aynı toplam `olcek/on_kayit_olc1.md` Ö7 |
| ↳ decompile (bütün fonksiyonlar) | TAHMİN [16 214; 58 634] sn → 0,099–0,359 sn / fonksiyon | aynı dosya |
| ↳ xref / CFG / BSim | TAHMİN [3 204; 3 999] / [6 933; 10 711] / [23 638; 64 149] sn | aynı dosya |
| T300 (`libtensorflow_cc.2.dylib`, 646 577 920 B; 746 814 başlangıç): K1 | TAHMİN [6 535; 17 924] sn = [1,8; 5,0] sa; kötümser 237 682 sn | aynı dosya |
| Genel 100 MB / 300 MB / 1 GB: K1 | TAHMİN [1 723; 5 392] / [4 032; 17 046] / [10 475; 61 816] sn | aynı dosya |
| K0 çekirdeği, T100: görüntüyü açma + fonksiyon başlangıçları | 0,62 + 0,03 sn → 163 141 başlangıç (yük altında, yük 5,0) | Ek B-3 |
| K0 çekirdeği, T300 | 3,68 + 0,14 sn → 746 814 başlangıç (yük altında) | Ek B-3 |
| K0, Ollama dilimi: Go + ObjC üst verisi | 0,46 sn (yük altında, yük 2,8) | Ek B-1 |
| Hedef seti (GT fonksiyon adresi): terminal-notifier / docker-cli / docker-compose / iTerm2 / llama-server | 92 / 35 050 / 90 257 / 108 776 / 17 210 | `ustveri/olcum/HEDEF.md` |
| ↳ bugünkü ürünle TAHMİNİ süre: llama-server / docker-cli / docker-compose / iTerm2 | 164–215 / 334–983 / 859–7 378 / 1 046–11 219 dk | `ustveri/olcum/HEDEF.md` |

Okuma: tembel kip gösteride K1'i (378,8 sn) kısaltmaz; decompile, CFG, xref, BSim ve reconstruct'ı küçültür. T100'de K1 tek başına [38; 72] dk (TAHMİN): "ilk okunabilir kod" bu süreden önce gelemez. İlk özet (K0) ise saniyeler mertebesinde.

### 1.3 Bu turda ölçülen bulgu: xref dökümü K1'den türetilebiliyor

`ghidra_xrefs.json`'ın fonksiyon başına üç alanı (`strings_used`, `functions_called`, `called_by`; üretildiği yer `headless.py:1896-1941`) gösteri çalışma alanında K1'in iki dosyasından (`ghidra_strings.json` `xrefs[].from_func_addr`, `ghidra_call_graph.json` `nodes[].callers / callees`) yeniden kurulup adres kümesi düzeyinde karşılaştırıldı (Ek B-2):

| Karşılaştırma | Sonuç |
|---|---|
| fonksiyon → başvurduğu dizgi adresleri kümesi | 13 559 / 13 559 fonksiyonda aynı; (fonksiyon, dizgi) çifti 2 993 = 2 993 |
| dizgi → başvuran fonksiyon kümesi | 1 803 / 1 803 dizgide aynı; tek başvuranlı dizgi 1 533 = 1 533 |
| `called_by` ↔ `call_graph.callers` | 13 559 / 13 559 aynı |
| `functions_called` ↔ `call_graph.callees` | 13 559 / 13 559 aynı |

Sonuçları:
1. Tembel kipte xref adımı Ghidra'da hiç koşmaz; `function_xrefs` **bütün** fonksiyonlar için (seçilmeyenler dahil) saf Python'la türetilir. T100'de TAHMİN 3 204–3 999 sn'lik adım saniyelere iner.
2. Ad hattının nüfus düzeyindeki girdileri (dizgi → başvuran fonksiyon kümesi) tembel kipte de tam nüfustan gelir; teklik kuralları bozulmaz (§3.3).
3. Sınırı: tek ikilide (Go ağırlıklı) ve küme düzeyinde ölçüldü. Alan düzeyinde JSON eşitliği (sıra, `name` / `value` alanları) ve C / C++ ikilileri OL10-A'da S8 + gösteri üstünde ölçülür (H-A3). Tutmazsa xref adımı seçili küme için Ghidra'da koşar, türetme yalnız seçilmeyenler için kullanılır ve fark kayda geçer.
4. Türetmeye girmeyen tek alan `statistics.total_globals_with_xrefs` (sembol tablosu döngüsü, `headless.py:1946-1960`); köprüde yalnız günlük satırında kullanılıyor (`:533-539`; başka okuyucusu olup olmadığı OL10-A adım 6'da `grep` ile denetlenir). Türetilen dosyada `null` yazılır ("ölçülmedi"); 0 yazılmaz.
5. Aynı türetme tam kipte de xref adımının yerine geçebilir (HIZ HZ-4a'nın "tek başvuru geçişi" ile aynı kazanç); bu ÖL-10'un kapsamı değil, ana oturuma not.

## 2. Seçim kuralı

### 2.1 Girdiler (hepsi decompile'dan önce var)

| Girdi | Kaynak | Katman |
|---|---|---|
| fonksiyon: adres, boyut, taslak / dış, Ghidra adı | `ghidra_output/functions.json` (`_extract_functions`, `headless.py:868-905`) | K1 |
| fonksiyon → başvurduğu farklı dizgi sayısı | `strings.json` `xrefs[].from_func_addr` (`headless.py:971-985`) | K1 |
| fonksiyon → çağırdığı fonksiyon kümesi | `call_graph.json` `nodes[].callees` (`headless.py:1060-1067`) | K1 |
| giriş adresi | `Goruntu.giris_adresi` (`karadul/analyzers/ustveri/goruntu.py:204`) | K0 |
| üst veri adı ve sınıfı | Go: `go_pclntab.oku` → `GoFonksiyon.sinif` (`karadul/analyzers/ustveri/go_pclntab.py:870-885`, sınıf `paket_sinifi` `:272-289`, ana modül `ana_modul_bul` `:292-303`); ObjC: `objc.oku` → `yontemler[].imp` | K0 |
| istek listesi | analist / KaradulLM (§5) | — |

Kural çağıran LİSTELERİNİN sırasına hiç bakmaz (P16e'ye kadar belirlenimsiz: `docs/arge/2026-11-20_dalga0/DURUM.md` "HZ1 → yeni bulgu"). Yalnız kümeler, küme boyutları ve adresler kullanılır.

### 2.2 Sınıf (her fonksiyona tek değer)

| Sınıf | Tanım | Kendiliğinden seçilir mi |
|---|---|---|
| `TASLAK` | Ghidra'da `is_thunk` ya da `is_external` (içe aktarım taslağı; birkaç bayt) | evet, en sonda (B6); sınırlar izin verirse |
| `KENDI` | Go sınıfı `kendi` (ana paket ya da ana modülün paketi); ObjC yöntemi (IMP'si bu ikilide) | evet, en önce |
| `BAGIMLILIK` | Go sınıfı `ucuncu_taraf` (ilk yol öğesinde nokta olan modül; ana modülün `vendor/` kopyaları) | evet, en sonda |
| `STANDART` | Go sınıfı `standart`, `calisma_zamani`, `derleyici` | hayır (yalnız istekle; K-5) |
| `BILINMIYOR` | yukarıdakilerin hiçbiri (üst veri adı yok; ya da Go `paketsiz` / `adsiz`) | evet |

- Go sınıf adları okuyucunun sabitleridir (`go_pclntab.py:95-101`); seçim modülü bu sabitleri içe aktarır, kendi dizgisini yazmaz.
- Swift (P-ÜV3) ve C++ RTTI (P-ÜV4) okuyucuları main'e girince tabloya birer satır eklenir (Swift: tipin modülü ana modülse `KENDI`; C++: `std::` / `__cxxabiv1::` ad alanı `STANDART`). O zamana dek bu fonksiyonlar `BILINMIYOR`'dur; kural sürüm numarası artar (§2.6).
- Sınırı (bilinen): ikiliye statik bağlanmış üçüncü taraf ObjC kitaplığının yöntemleri de `KENDI` sayılır; üst verisi olmayan gömülü C kitaplığı (Ollama'da sqlite3) `BILINMIYOR`'dur. Bunları ayıracak olan kimlik eşlemesidir (KİMLİK PK-4, ÖL-11); o gelince `BAGIMLILIK`'a iner.

### 2.3 Basamaklar (sıra sözlük sırasıdır: önce basamak, sonra basamak içi anahtar)

| Basamak | Üyeler | Basamak içi sıra anahtarı |
|---|---|---|
| B0 `istek` | analistin / KaradulLM'in istediği adresler (sınıfı ne olursa olsun) | isteğin verildiği sıra |
| B1 `giris` | giriş kümesi E ve E'den çağrı grafiğinde en çok 2 adımda ulaşılanlar; genişleme `STANDART` ve `TASLAK` fonksiyona girmez, onlardan geçmez. En çok 256 fonksiyon | (derinlik, adres) |
| B2 `kendi` | sınıfı `KENDI` | (−kanıt, adres) |
| B3 `bilinmiyor_kanitli` | sınıfı `BILINMIYOR`, kanıt ≥ 1 | (−kanıt, adres) |
| B4a `bilinmiyor_komsu` | sınıfı `BILINMIYOR`, kanıt = 0, B0–B3'teki en az bir fonksiyonun çağırdığı | adres |
| B4b `bilinmiyor_kalan` | sınıfı `BILINMIYOR`, kanıt = 0, kalanlar | adres |
| B5 `bagimlilik` | sınıfı `BAGIMLILIK` | (−kanıt, adres) |
| B6 `taslak` | sınıfı `TASLAK` | adres |

`STANDART` hiçbir basamağa girmez (yalnız B0). B6'nın gerekçesi: tam kip taslakları da decompile ediyor (gösteride 13 559 denemenin 399'u taslak); taslaklar en sonda seçilince "sınır yok + `STANDART` sınıfı yok" durumunda (düz C ikilisi) tembel kipin seçili kümesi bütün fonksiyonlardır ve çıktı tam kiple dosya dosya karşılaştırılabilir (§6, H-E2). Büyük ikilide B6'ya sıra gelmez; taslaklar ertelenen sayılır.

- **E (giriş kümesi):** ikilinin giriş adresini içeren Ghidra fonksiyonu (sınıfı `STANDART` olsa da seçilir; ELF'te `main` kurtarma bu fonksiyonun `.c`'sini okur: `karadul/stages.py:1816-1875`); üst veride adı `main.main` olan Go fonksiyonu; Ghidra'nın `entry` adını verdiği fonksiyon. Dışa aktarılan fonksiyonlar (dylib) E'ye girmez (sayıları binleri bulabilir); onlar B2–B4'te kanıtlarıyla sıralanır.
- **kanıt(f)** = f'nin başvurduğu farklı dizgi adresi sayısı + f'nin çağırdığı farklı `TASLAK` fonksiyon (içe aktarım) sayısı. İkisi de küme boyutudur.
- Bir fonksiyon ilk girdiği basamakta sayılır.
- **Ana modül bulunamazsa** (Go üst verisi var ama `ana_modul_bul` `None` döndü: `go_pclntab.py:292-303`) programın kendi paketleri bağımlılıklardan ayırt edilemez (`main` paketi dışındakiler `ucuncu_taraf` görünür). O durumda `BAGIMLILIK` sınıfı B5 yerine B2'ye alınır (`KENDI` ile aynı basamak, aynı anahtar) ve künyeye `ana_modul: "bilinmiyor"` yazılır. Programın kendi kodunu ertelemektense fazladan bağımlılık decompile etmek seçilir.
- Adres karşılaştırması tam sayıyladır (onaltılık dizgi olarak değil).
- Sabitler (`GIRIS_DERINLIGI = 2`, `GIRIS_UST_SINIR = 256`, `KURAL_SURUMU = 1`) tek yerde, seçim modülünde tanımlanır (`karadul/core/tembel_secim.py`, yeni); başka dosya bu sayıları yazmaz, içe aktarır.

Gerekçe (neden bu sıra):
- Decompile'ın iki ayrı değeri var: analistin okuyacağı gövde ve ad kanallarına girdi. Adı üst veriden bilinen fonksiyonda ikinci değer sıfıra yakın (ad zaten %99,99 kesinlikle var: docker-compose 90 077 / 90 077, `DURUM.md` PUV1); geriye birinci değer kalır ve o yalnız programın kendi kodunda yüksektir. Bu yüzden `KENDI` en önce, `STANDART` hiç.
- `BILINMIYOR` sınıfı ad kanallarının iş yapabildiği tek yerdir (gösterinin 17 adının 17'si bu sınıfta: Ek B-1); kanıtı olan önce gelir çünkü analistin ve KaradulLM'in tutunacağı dizgi / içe aktarım orada.
- `c_namer` adlarının bağımsız nüfustaki kesinliği %79,8 (A-29), ad eşiğinin (0,909; A-13) altında. Sıra "c_namer daha çok ad üretsin" diye kurulmadı; ölçüt okunacak koddur.

### 2.4 Bütçe ve kesim

- Sıralı liste L = B0 ‖ B1 ‖ … ‖ B6. İki sınır:
  1. `buyuk_ikili.secim_ust_sinir` (fonksiyon sayısı; 0 = sınır yok): L'nin ilk N öğesi seçili kümedir (disk ve bellek güvencesi).
  2. `buyuk_ikili.decompile_butcesi_sn` (süre; 0 = sınırsız): decompile L sırasıyla ilerler; bütçe dolunca yeni fonksiyon alınmaz. Seçilmiş ama bütçeye sığmamış fonksiyon `ertelendi (bütçe)` durumunu alır; sırası korunur ve sürdürme oradan devam eder (§5.6).
- Öneri öntanımlar (kip açıkken): `decompile_butcesi_sn = 1200`, `secim_ust_sinir = 5000`. İkisi de TAHMİN'e dayanır; OL10-C / OL10-J ölçümünden sonra yeniden yazılır. Sayı sınırının gerekçesi ad hattıdır: yeniden kurma aşamasının kendi süre bütçesi yok (`olcek/BULGULAR.md` K11) ve süresi S'nin boyutuyla büyür (gösteride 0,174 sn / fonksiyon, yük altında → 5 000 fonksiyon ≈ 14,5 dk TAHMİN). Yalnız süre bütçesi olsaydı hızlı decompile eden makinede 20 dakikada 31 000 fonksiyon seçilir, ad hattı 90 dakika sürerdi.
- İlk geçişten sonrası dilimlerle sürer: `karadul decompile <ws> --sonraki` L'nin sıradaki `secim_ust_sinir` kadar fonksiyonunu alır (§5).
- Sayı donanımdan türemez, süre bütçesinden türer (A-9): hızlı makinede aynı bütçeyle (üst sınıra kadar) daha çok fonksiyon decompile edilir; kural ve sıra değişmez.
- Bütçe kesimi koşudan koşuya farklı yerde olabilir (süreye bağlı). Belirlenimci olan SIRADIR; "seçili küme" eşitliği isteyen ölçümler süre bütçesini kapatıp (`0`) sayı sınırıyla koşar (§6).

### 2.5 Sayısal örnekler

**Ollama dilimi (ölçüldü: kuru seçim, kural sürümü 1; Ek B-1).** Program fonksiyonu 13 160, gövde 5 414 161 B. Sınıf: `KENDI` 1 406, `BILINMIYOR` 2 619, `BAGIMLILIK` 594, `STANDART` 8 541; `TASLAK` 399.

| Basamak | Fonksiyon | Gövde (B) | Kümülatif fonksiyon | Kümülatif gövde |
|---|---|---|---|---|
| B1 giriş (E = `main.main`) | 36 | 24 444 | 36 (%0,3) | 24 444 (%0,5) |
| B2 kendi | 1 373 | 624 256 | 1 409 (%10,7) | 648 700 (%12,0) |
| B3 bilinmiyor, kanıtlı | 1 236 | 938 516 | 2 645 (%20,1) | 1 587 216 (%29,3) |
| B4a bilinmiyor, komşu | 547 | 227 380 | 3 192 (%24,3) | 1 814 596 (%33,5) |
| B4b bilinmiyor, kalan | 836 | 132 589 | 4 028 (%30,6) | 1 947 185 (%36,0) |
| B5 bağımlılık | 591 | 298 060 | 4 619 (%35,1) | 2 245 245 (%41,5) |
| B6 taslak (program fonksiyonu değil) | 398 | 3 664 | — | — |
| seçilmeyen (`STANDART`) | 8 541 | 3 168 916 | — | (%58,5) |

- Gösterinin ad verdiği 17 fonksiyon: B3'te 10, B4a'da 5, B4b'de 2; en geç sıra 3 831. B4 sonuna kadar (4 028 fonksiyon) seçilirse 17'sinin de gövdesi var. Adların aynı çıkıp çıkmadığı OL10-B'de ölçülür.
- Giriş adresindeki (`0x100081fb0`) Ghidra fonksiyonu `entry`, 4 baytlık bir taslaktır (`is_thunk`; Go çalışma zamanının başlangıcına atlar). Yüzdeler program fonksiyonları üstündendir; E'nin öbür üyesi olan bu taslak B1'de ayrıca seçilir (E üyesi sınıfına bakılmadan seçilir), genişleme ondan `STANDART` çalışma zamanına girmez. Kalan 398 taslak (toplam 399; gövdeleri 3 668 B) B6'dadır (Ek B-1).
- TAHMİN (B1–B4 seçilirse; yük altındaki gösteri sürelerinden; decompile / CFG / deobfuscate gövde baytıyla, reconstruct `.c` sayısıyla orantılı varsayımı): K1 378,8 sn (değişmez); decompile 523,9 × 0,360 = 189 sn; CFG 600,9 × 0,360 = 216 sn; tip + P-code + FunctionID ≈ 8 sn; xref türetme saniyeler; BSim ertelenir; statik aşamanın köprü dışı kısmı 912 sn (içindeki ikili istihbaratın 887 sn'sinin nasıl bölündüğü ölçülmedi; aynen alındı); deobfuscate 663,5 × 0,360 = 239 sn; reconstruct [699; 994] sn (2 353,1 × 0,297 doğrusal; üs 0,71 ile 2 353,1 × 0,297^0,71; 0,297 = 4 028 / 13 554 `.c`). Toplam TAHMİN [2 642; 2 937] sn = [44; 49] dk; tam kip 7 729 sn (129 dk). Varsayımların hiçbiri ölçülmedi; OL10-B (reconstruct kısmı) ve OL10-J ölçer.

**T100, 100 MB (TAHMİN; C++, üst veri sınıfı yok → 163 141 fonksiyonun hepsi `BILINMIYOR`).**
- K0 çekirdeği 0,65 sn (ölçüldü, yük altında; dizgi taraması ve `lief` ayrıca, ölçülmedi).
- K1 [38,0; 72,1] dk; kötümser 6,1 sa.
- K2 decompile, bütçe 1 200 sn ve üst sınır 5 000: hız 0,0386 sn / fn (gösteri) ile 0,359 sn / fn (T100 modelinin üst ucu) arasında → **3 339–5 000 fonksiyon** (%2,0–%3,1), süre [3,2; 20] dk. Sıra: B1 (≤ 256), sonra B3 kanıt sırasıyla.
- Deobfuscate + ad hattı (S üstünde): TAHMİN [12; 19] dk (gösteride deobfuscate 0,049, reconstruct 0,174 sn / fn, yük altında; 3 339–5 000 fonksiyon). İkili istihbarat: ölçülmedi (ÖL-3b bütçesi 300 sn).
- K2 toplamı: hızlı uçta 5 000 fonksiyon (3,2 + 18,6 = 21,8 dk), yavaş uçta 3 339 fonksiyon (20 + 12,4 = 32,4 dk); istihbarat bütçesiyle en çok + 5 dk.
- Toplam ilk okunabilir kod: TAHMİN [60; 110] dk (38,0 + 21,8 alt uç; 72,1 + 32,4 + 5 üst uç). Kötümser senaryoda K1 otomatik analiz sınırına (`timeouts.ghidra` 7 200 sn, `karadul/config.py:345`; dosya 100 MB'ı aşarsa × 4: `headless.py:303-316`) dayanır, analiz `timeout` durumuyla kısmi kalır ve akış kısmi programla sürer (`headless.py:395-403`).
- Disk (TAHMİN): Ghidra projesi [0,3; 0,9] GB (gösteride proje 84 704 KiB = dilimin 3,3 katı, kodun 15,7 katı; `olcek/BULGULAR.md` §4 S3); K1 JSON'ları `functions.json` ≈ 48 MB (gösteride 297 B / fn), `call_graph.json` ≈ 228 MB (1 396 B / fn); S'nin `.c` + ara kopyaları fonksiyon başına 80 900–93 900 B (`olcek/BULGULAR.md` K12) → 5 000 fonksiyonda ≈ 0,4–0,5 GB.

**T300, 300 MB üstü (TAHMİN; 746 814 fonksiyon).**
- K0 çekirdeği 3,8 sn (ölçüldü, yük altında).
- K1 [1,8; 5,0] sa; kötümser 66 sa → otomatik analiz 28 800 sn sınırında kesilir (dosya > 100 MB), akış kısmi programla sürer.
- K2, aynı öntanımlar (1 200 sn, 5 000) → 3 339–5 000 fonksiyon (%0,4–%0,7). 746 814 fonksiyonluk ikilide ilk geçiş çok küçük bir dilimdir; asıl iş analistin isteğiyle ve `--sonraki` dilimleriyle yürür.
- Bellek (TAHMİN): `call_graph.json` ≈ 1,04 GB, `functions.json` ≈ 0,22 GB; Python'da × 3,46–6,14 (`olcek/BULGULAR.md` §3.4) = 4,4–7,7 GB + JVM yığını 14,7 GB. ÖL-3 (akış biçimli yazım) girmeden T300 bu makinede sınırdadır.

**Çok GB'lık paket (FreeCAD.app, 2,48 GiB; 867 tekil bileşen; `olcek/BULGULAR.md` §1).**
- Paket yöneticisi ÖL-5a'dır; ÖL-10 bileşen düzeyinde çalışır. Her bileşen kendi kod baytıyla eşiğe bakar: eşiğin altındaki bileşen (1 817 Mach-O'nun 1 464'ü 1 MB'tan küçük) tam kipte, üstündeki tembel kipte koşar.
- K0 bütün bileşenler için koşar ve paket raporunun ilk hâlini verir (bileşen listesi, her bileşende yazılı adlar ve sınıf sayımı). Süre ölçülmedi; okuma hızı T300'de 646,6 MB / 3,8 sn idi, bileşen başına sabit gider bilinmiyor.
- Ana bileşen önce (ÖL-5a adım 3), K1 + K2; kalanlar paket bütçesi içinde. Paket bütçesi dolduğunda sıradaki bileşen K0'da kalır ve "bütçe dışı" görünür (ÖL-5a adım 4–5); K0 katmanı ÖL-5a'nın "ucuz katman"ının yerine geçer (aynı okuyucu iki kez yazılmaz).
- Sayısal süre örneği verilmedi: paket hiç koşulmadı, bileşen başına K1 dağılımı bilinmiyor ("ölçülmedi").

### 2.6 Belirlenimcilik ve ön kayıt

- Kural saf bir fonksiyondur: `sec(girdi) → sıralı liste`. Aynı girdi → aynı liste (bayt bayt). Girdinin sırası karıştırılsa da (fonksiyon listesi, dizgi listesi, çağrı grafiği düğümleri, çağıran / çağrılan listeleri) çıktı aynıdır; bu bir testtir (OL10-A).
- Her koşu seçimin künyesini yazar: `KURAL_SURUMU`, sınıf sayımı, basamak sayımı, sıralı listenin sha256'sı, sınırlar. Kural değişirse sürüm artar; eski sürümle seçilmiş çalışma alanı "kural sürümü 1 ile seçildi" diye görünür.
- Ön kayıtlanabilirlik: bir ölçümden önce yalnız kural sürümü ve sınırlar yazılır; hangi fonksiyonların seçileceği girdiden hesaplanır, elle seçim yoktur.
- Sınama ikilileri (docker-compose, iTerm2, llama-server) kural yazılırken açılmaz (ORTAK_D1 §3). Kural sürümü 1 bu belgeyle dondurulmuştur (yalnız Ollama dilimi ve kod okumasıyla yazıldı); sınama ikililerindeki ilk sayım OL10-A'nın dondurma commit'inden sonra bir kez yapılır.

## 3. Kısmi analizde ad kanallarının sözleşmesi

### 3.1 İlkeler

- **S-1 (ad haritası tam nüfusu görür).** Ad adayları Ghidra'nın fonksiyon adına (`FUN_<adres>`) anahtarlıdır, `.c` dosyasına değil (`collect_candidates`, `karadul/pipeline/steps/_feedback_naming_candidates.py:25-109`; anahtar çözümü `GhidraFunctionIndex`, `:194-215`). Gövdesiz fonksiyon ad haritasına girebilir; ad, gövdeli fonksiyonların `.c`'sindeki çağrı yerlerine de uygulanır (`_apply_aho_replace`, `karadul/pipeline/steps/_feedback_naming_merger.py:516-580`: harita bütün `.c` dosyalarına Aho-Corasick ile basılır). Yani S'deki bir fonksiyonun kodunda, seçilmemiş ama adı üst veriden bilinen bir fonksiyonun çağrısı adıyla görünür.
- **S-2 (gövde isteyen kanal gövdesiz fonksiyona ad vermez).** Girdisinin bir kısmı decompile edilmiş C olan kanal, o kısım yokken kalan girdiyle ad üretmez. Gerekçe: kanalın ölçülmüş kesinliği tam girdiyle ölçüldü; eksik girdiyle çalışması ölçülmemiş yeni bir kanaldır (A-14). Aday kaybolmaz: kanıt satırı olur (`govde: "yok"`).
- **S-3 (nüfus kapısı tam nüfustan beslenir).** "Bu dizgiye tek fonksiyon başvuruyor", "bu ad ikilide tek", "bu ad N fonksiyona önerildi" gibi nüfus düzeyindeki her hüküm tembel kipte de BÜTÜN fonksiyonlar üstünden hesaplanır. Tam nüfusu yalnız `.c` taramasından bilen kapı, ertelenen fonksiyon varken "bilinmiyor" sayılır ve ad yazmaz. (Somut tehlike §3.3.)
- **S-4 (etiket yükselmez).** Tembel kip hiçbir adın etiketini yükseltmez; kanal, etiket ve güven tam kiptekiyle aynıdır. Yalnız köken kaydına iki alan eklenir (§3.4).
- **S-5 (kip kapalıyken hiçbir şey değişmez).** `buyuk_ikili.tembel = False` iken ad haritası, köken kaydı ve `.c` çıktıları bugünküyle bayt bayt aynıdır (119 / 119; §6 H-J5).

### 3.2 Kanal tablosu

"Girdi" sütunu: **B** = ikilinin baytları (K0), **J** = Ghidra döküm JSON'u (K1; tam nüfus), **Jx** = türetilen `xrefs.json` (tam nüfus; §1.3), **C** = decompile edilmiş C (yalnız S), **P** = `pcode.jsonl` / `cfg.json` (yalnız S). "Gövdesiz ad": seçilmemiş fonksiyona ad yazabilir mi.

| Kanal | Kod (main `f2b0db5`) | Girdi | Tembel kipte | Gövdesiz ad | Etiket / kanıt satırı |
|---|---|---|---|---|---|
| Ön ad: `main` (ELF `__libc_start_main`) | `karadul/stages.py:1816-1875` (düzenli ifade `:1720`; `.c` taraması `:1848-1859`) | C (giriş fonksiyonunun `.c`'si) | evet: giriş fonksiyonu B1'de her zaman seçili | evet (adı alan `main`'in gövdesi gerekmez; B1'de zaten seçili) | bugünkü: `on_ad:main_giris` (ölçülmüş 110 / 110, alt 0,966: `karadul/core/naming_labels.py:51`) |
| Ön ad: Mach-O `main` (`LC_MAIN`; P-ÜV5) | bayrak `enable_macho_entry_main` (`karadul/config.py:773`; kod PUV5 paketinde, main'de yok) | B | evet | evet | P-ÜV5 / P-ÜV6b'nin vereceği (`üst veriden`) |
| Ön ad: gnulib parmak izi | `karadul/stages.py:1877-2212` (`.c` taraması ve "bütün dizgi değişmezleri" `:1938-1944`; çağrı grafiği `:1973-1978`) | C + J | **kanıt satırı** (ad yazmaz): adayın tekliği ve varlık kanıtı yalnız S'nin `.c`'lerinden hesaplanabiliyor (S-3) | hayır | aday `static/gnulib_candidates.json`'a "kısmi nüfus" nedeniyle (var olan yol: `:1902`, `:2211`); OL10-B ölçer, sonuca göre gevşetilir |
| Ön ad: ELF önyükü | `karadul/stages.py:2253-2323` (yalnız `call_graph.json`: `:2272-2287`) | J | evet (girdi tam nüfus; teklik çağrı grafiği üstünden) | evet | bugünkü: `on_ad:elf_onyuk` (458 / 458, alt 0,992: `naming_labels.py:50`) + `govde` alanı |
| KS-1 kesin çapalar | `karadul/reconstruction/tarif/kesin.py:245-272` (dizgi başvuruları `ghidra_xrefs.json`'dan `:251-264`; disassembly `.c`'nin sonundan `:271-280`); zorunlu dosyalar `karadul/reconstruction/tarif/baglama.py:115` | J + Jx + C (gömülü disassembly) | kısmen: yalnız S'deki fonksiyona; dizgi → fonksiyon kümesi Jx'ten tam nüfusla (S-3) | hayır | bugünkü (`kesin`); **Jx tam nüfus değilse kanal kapatılır** (§3.3) |
| Faz 1 adları: bayt kalıbı | `karadul/pipeline/steps/byte_pattern.py:53-55` (`binary_for_byte_match`, `functions_json_path`) | B + J | evet | evet (bugünkü davranış; girdisi değişmiyor) | bugünkü (`doğrulanmadı`) + `govde` alanı |
| Faz 1 adları: `BinaryNameExtractor` | çağrı `karadul/pipeline/steps/parallel_algo_eng.py:140` | B (+ C: OL10-F adım 1 envanteri kesinleştirir) | kısmen | envanter sonucuna göre; C isteyen alt kol S-2 | bugünkü |
| İmza veritabanı (`sig_matches`) | `karadul/pipeline/steps/ghidra_metadata.py:187-` (`sig_db.match_all(functions, strings, call_graph, decompiled_dir)`) | J + C | kısmen (J kolu tam nüfus; C kolu yalnız S) | J kolu için evet | bugünkü |
| `c_namer`: `string_context` (`oz_ad` dahil) | `karadul/reconstruction/c_namer.py:3469-3568` (JSON'dan dizgi `:3480`; gövdeden dizgi `:3483-3485`) | J + C | **yalnız S** (S-2: gövdesiz fonksiyonda kanıtın yarısı yok) | hayır | bugünkü (`doğrulanmadı`; bağımsız nüfusta `oz_ad` %79,8, A-29); gövdesiz adayın JSON kolu kanıt satırı |
| `c_namer`: `api_call`, `call_graph` | `c_namer.py:3574-3594`, `:3692-3710` | J + C | yalnız S | hayır | bugünkü |
| `c_namer`: `dataflow`, `api_param_propagation`, `body_param_naming`, `local_var_naming`, `type_based` (parametre / yerel ad) | `c_namer.py:3856-3867`, `:4088-4095`, `:4183-4198`, `:4335-4350`, `:4009` | C (ilk dördü gövde yoksa zaten dönüyor); `type_based` J | yalnız S | hayır (parametre adı gövdesiz fonksiyonda yazılacak yer bulmaz) | bugünkü `per_function` haritası |
| Üst veri: Go `pclntab`, ObjC yöntem (P-ÜV6 / PUV6a) | üretici adımlar `karadul/pipeline/steps/go_metadata_recovery.py:59` (`requires=["binary_for_byte_match"]`), `objc_metadata_recovery.py`; kanal PUV6a'da (`docs/arge/2026-11-23_dalga1/gonderim/PUV6a.md` kalem 2: `_add_go_pclntab`, `_add_objc_methods`; girdi `ghidra_functions.json` + ikili) | B + J (fonksiyon listesi) | **evet, tam nüfus** | **evet** (tembel kipin asıl ad kaynağı) | `üst veriden` (PUV6a hüküm 4), `ozgun_ad`, güven ölçülmüş tablodan |
| K-4 kanalları: DWARF, PDB, Rust / Go ayrıştırıcı, BN, TRex, RTTI | `add_k4_channels`, `_feedback_naming_candidates.py:341-383`; dizin `load_ghidra_index` `:218-248` | B + J (+ dış araç çıktısı) | evet | evet | bugünkü (bayrağı açık olan) |
| FunctionID | `_add_fid`, `_feedback_naming_candidates.py:832`; döküm `headless.py:2541` | J (Ghidra'nın otomatik analizde verdiği eşleşmeler) | evet | evet | bugünkü |
| BSim | `_add_bsim`, `_feedback_naming_candidates.py:946`; köprü `headless.py:612-677` | Ghidra (ingest + sorgu) | ertelenir (K-4); öntanımda zaten gölge kip | — | `bsim_status: "ertelendi"` |
| BinDiff / başvuru farkı (bugünkü yollar; PK-1 kapılayacak) | `karadul/pipeline/steps/_feedback_naming_bindiff.py:56-`, `_feedback_naming_refdiff.py:29-31` (`functions_json`, `strings_json`, `call_graph_json`, `cfg_json`) | J + P (CFG) | kısmen: CFG yalnız S'de | hayır (CFG'siz eşleme ölçülmedi) | PK-1'in kapısına tabi |
| KİMLİK PK-4 (çapalı başvuru eşleme) | plan `kimlik/PLAN.md` PK-2 (satır 198-200): `ghidra_functions.json`, `ghidra_call_graph.json`, `ghidra_strings.json`, `ghidra_xrefs.json`, `ghidra_cfg.json`, `ghidra_output/pcode.jsonl` | J + Jx + P | **kısmen: eşleme yalnız S'de** (CFG ve P-code sabitleri gövdesiz fonksiyonda yok); çapalı yayılım komşuluğu kısmi | hayır | PK-4'ün vereceği; kabul ölçümüne "tembel kol" eklenir (KARŞI İ-2 düzeltme 2): aynı çiftte S ⊂ nüfus iken kesinlik ve kapsam |
| Hesaplama / mühendislik / P-code adları | `_add_computation` `:863`, `_add_pcode` `:923`, `_add_engineering_naming` `:1131` (`decompiled_dir` + `functions_json`: `collect_candidates` `:96-107`) | C + P | yalnız S | hayır | bugünkü |
| Kayıt çifti (ÖK-4a; ÖK-4b yazılmıyor, A-29) | plan `ozkod/PLAN.md` satır 63-65: çağrı yeri çiftleri decompile edilmiş C'den, veri sözcükleri ikiliden | B + C | kısmen: veri tablosu kolu tam nüfus, çağrı yeri kolu yalnız S | — (ad vermez) | yalnız kanıt satırı |
| `oz_ad` teklik kapısı (ÖK-2; yeniden ele alınacak, A-29) | plan `ozkod/PLAN.md` satır 235-236: kapının girdisi `_string_refs_by_func`'un tersi (JSON'dan: `c_namer.py:2834-2843`) | J | evet (girdi tam nüfus; S-3 sağlanıyor) | — | — |
| Tip / yapı kurtarma | `struct_recovery`, `computation_struct_recovery`, `type_recovery_consumer` adımları (Faz 1 / Faz 2 listesi `karadul/stages.py:2500-2533`, `:2598-2602`) | C + P | yalnız S | — | bugünkü |
| Elle ad (analist) | `force_manual_names`, `_feedback_naming_merger.py:187`; tohum `stages.py:2324` | — | evet | evet | etiketsiz (bugünkü) |

Tablonun kod okumasıyla doldurulamayan iki hücresi (`BinaryNameExtractor`'ın C kolu, imza veritabanının C kolunun payı) OL10-F adım 1'in envanteriyle ve OL10-B'nin ölçümüyle kesinleşir: OL10-B köken kaydından kanal × (gövdeli / gövdesiz) ad sayısını çıkarır; bu tablo o sayımla karşılaştırılır.

### 3.3 Nüfusa bağlı kapılar: somut tehlike ve kural

Kısmi nüfus ad hattını üç yerden bozabilir; üçü de "yanlış ad" yönünde:

1. **KS-1'in dizgi tekliği.** KS-1 "dizgi → başvuran fonksiyon kümesi"ni `ghidra_xrefs.json` `function_xrefs[].strings_used`'tan kurar (`kesin.py:251-264`). Bu dosya yalnız S'yi taşısaydı, iki fonksiyonun başvurduğu bir `__func__` dizgisi tek başvuranlı görünür ve KS-1 **`kesin` etiketli yanlış ad** yazardı. Önlem: tembel kipte `xrefs.json` tam nüfus için türetilir (§1.3). Koruma: türetilen dosyanın `kapsam` alanı `"tam_nufus"` değilse KS-1 adımı ad bağlamaz (`kesin_anchors` çıktısı "girdi kısmi" durumuyla boş).
2. **gnulib adayının tekliği ve varlık kanıtı.** Aday listesi ve "ikilinin bütün dizgi değişmezleri" `.c` taramasından geliyor (`stages.py:1938-1944`). Kısmi nüfusta iki adaylı bir parmak izi tek adaylı görünebilir. Önlem: tembel kipte gnulib ad yazmaz, adayı kanıt dosyasına yazar (tablo). OL10-B bu kanalın kısmi nüfustaki davranışını ölçer; "tam kipte olmayan ad 0" çıkarsa kural gevşetilebilir (ayrı ön kayıtla).
3. **`c_namer`'ın çözümleme aşaması.** Ad seçimi fonksiyon başına yalıtık değil: çakışma eki (`used_new_names`, `c_namer.py:2394`), kebap dizgi dizini (`KebabIndex(self._func_bodies)`, `:4154`), parametre mirası (`_propagate_passthrough_params`, `:2381`) ve geri besleme döngüsünün turları (bir turda verilen ad sonrakinin girdisi) nüfusun tamamına bakar. (Alt kanal susturmasının nüfusa bakan bir kolu olup olmadığı bu turda okunmadı; OL10-F adım 1 envanteri yazar.) Kısmi nüfusta aynı fonksiyon farklı ek alabilir ya da tam kipte çakışma yüzünden yazılmayan bir ad yazılabilir. Önlem yapı değil ölçüm: OL10-B, S üstünde tembel ↔ tam farkını kanal kanal sayar (aynı / eksik / fazla / farklı). Kabul kuralı K-2'dir: fazla = 0 ve farklı = 0 beklenir; tutmazsa farkı üreten kural bulunur ve o kural tembel kipte "kanıt satırı"na indirilir (yeni yanlış ad üretilmez), eksik ad sayısı raporlanır.

`c_namer` için ayrıca iki yapısal kural (OL10-F):
- Strateji döngüsü yalnız gövdesi olan fonksiyonlarda döner (bugün `ghidra_functions.json`'daki her fonksiyon için süreç havuzuna iş gönderiliyor: `c_namer.py:2245`, `:2285-2295`; toplam süre sınırı 1 200 sn `:2295`). T100'de bu 163 141 iş ve gövdesiz fonksiyonlarda JSON koluyla ad demektir.
- Var olan adla çakışma denetimi tam nüfusla kalır (fonksiyon dizini `self._func_by_name` bütün fonksiyonlardan kurulur; süzülmüş bir `functions.json` verilmez).

### 3.4 Köken kaydına eklenenler

Köken kaydı (`naming_provenance.json`, `karadul/core/naming_labels.py:24`) ve temiz çıktının ad kayıtları iki alan kazanır; yalnız tembel kipte yazılır (kip kapalıyken dosya bayt bayt aynı kalsın: S-5). Temiz çıktıyı üreten biçimlendiricinin köken alanlarını nasıl taşıdığı bu turda okunmadı; OL10-F adım 1 envanteri yazar.

| Alan | Değerler | Anlamı |
|---|---|---|
| `govde` | `"var"` / `"yok"` | adın verildiği fonksiyonun `.c`'si var mı |
| `nufus` | `"kismi"` | ad, nüfusun bir kısmı ertelenmişken verildi (tam kipte değişebilir: ek, susturma) |

Rapor ve arayüz bu iki alanı gösterir (§4); etiket sözlüğü (`NAME_LABELS`, `naming_labels.py:21`) değişmez. PUV6a etiket sözlüğüne `üst veriden` değerini ekliyor; ÖL-10 yeni etiket eklemez.

## 4. "Decompile edilmedi" sayacı

### 4.1 Tek kaynak: `static/tembel_durum.json`

Tembel kipte statik aşama bu dosyayı yazar; rapor, arayüz, KaradulLM, isteğe bağlı decompile ve sürdürme yalnız bunu okur (aynı sayım ikinci bir yerde hesaplanmaz). Kip kapalıyken dosya yoktur.

```
{
  "surum": 1,
  "kural_surumu": 1,
  "kip": "tembel",
  "neden": "kod 54,1 MiB ≥ eşik 16 MiB",          // ya da "istek (--derinlik tembel)"
  "sinirlar": {"secim_ust_sinir": 5000, "decompile_butcesi_sn": 1200},
  "katman": {"k0": "tamam", "k1": "tamam", "k2": "kismi"},   // tamam / kismi / yok
  "sayim": {
    "fonksiyon_toplam": 163141, "taslak": 0,
    "program": 163141,
    "decompile_edildi": 4200, "decompile_basarisiz": 3,
    "ertelendi": {"secilmedi": 158141, "butce": 797, "istek_bekliyor": 0},
    "sinif": {"KENDI": 0, "BILINMIYOR": 163141, "BAGIMLILIK": 0, "STANDART": 0},
    "basamak": {"B0": 0, "B1": 212, "B2": 0, "B3": 61000, "B4a": 30000, "B4b": 71929, "B5": 0, "B6": 0}
  },
  "secim_sha256": "…",                               // sıralı listenin özeti
  "ana_modul": null,                                 // Go: ana modül yolu / "bilinmiyor"; Go değilse null
  "sira_dosyasi": "tembel_sira.jsonl",               // satır: {"a": adres, "b": basamak, "s": sınıf, "d": durum}
  "proje": {"yol": "static/ghidra_project", "saklandi": true},
  "dilimler": [ {"no": 1, "kaynak": "ilk", "istenen": 5000, "biten": 4200, "basladi": "…", "bitti": "…"} ]
}
```
(Sayılar örnek biçimdir, ölçüm değil: 4 200 + 3 + 158 141 + 797 = 163 141.) `basamak` bütün fonksiyonları sayar (yalnız seçilenleri değil); `STANDART` hiçbir basamakta değildir, `sinif` sayımında görünür. `durum` değerleri: `decompile_edildi`, `basarisiz`, `ertelendi:secilmedi`, `ertelendi:butce`, `ertelendi:istek_bekliyor`. Sayım BÜTÜN Ghidra fonksiyonları üstündendir (taslaklar dahil; `program` yalnız bilgi alanıdır). Değişmez kural (testle kilitli): `fonksiyon_toplam = decompile_edildi + decompile_basarisiz + Σ ertelendi`. Sıra dosyası JSON Lines'tır (746 814 fonksiyonda tek JSON belgesi bellekte gereksiz yer tutar); dilim bitince atomik yeniden yazılır (`os.replace`).

### 4.2 Köprü ve durum dosyaları

- `decompiled.json` ve `ghidra_status.json` `decompile` bölümü (`macho.py:1137-1143`) yeni alan kazanır: `deferred` (ertelenen sayısı) ve `selection` (kural sürümü, sınırlar, basamak sayımı). `total_attempted` yalnız S'yi sayar; `functions_total` (bugün "sonuç kaydı sayısı", `headless.py:1533`) tembel kipte de BÜTÜN fonksiyonları sayar.
- Ertelenen fonksiyon `skipped` DEĞİLDİR. `skipped` / `losses.decompile_skipped` bugünkü anlamını korur: seçilmiş ama toplam decompile süresi dolduğu için yapılamamış (`headless.py:1355-1361`). Kayıp sayacı (`losses`) yalnız kayıpları sayar: başarısız, süreyle atlanmış, kesilmiş. Ertelenen ayrı alandadır. Böylece kip kapalıyken `losses` bugünküyle aynı kalır ve "kayıp 0" cümlesi tembel kipte de doğru anlam taşır: seçilenlerin hiçbiri kaybolmadı.
- `ghidra_status.json` `project` alanı (`macho.py:1146`; bugün `kept: false`) tembel kipte `kept: true` ve yolu taşır.

### 4.3 Rapor, CLI, çıkış kodu

- **Durum:** statik aşama `stats["partial"] = True` ve `partial_reasons = ["tembel derinlik: E / T fonksiyon decompile edilmedi (büyük ikili kipi; kural sürümü 1)"]` yazar. `analysis_outcome` (`karadul/core/pipeline.py:55-95`) bunu `kismi` sayar; çıkış kodu 3 (`EXIT_ANALYSIS_PARTIAL`, `:52`). Yeni çıkış kodu yok (K-3). Ertelenen fonksiyon varken hiçbir yol "tam" / çıkış 0 üretmez.
- **Ayırt edilebilirlik:** `pipeline_result.json` ve raporda `depth` nesnesi (`tembel_durum.json`'ın `kip`, `katman`, `sayim` alanları). Ölçüm araçları "kısmi, yalnız tembel erteleme" ile "kısmi, hata" durumunu buradan ayırır: `partial_reasons`'ın her öğesi `tembel derinlik:` ile başlıyorsa ve `losses` sıfırsa birincisidir.
- **CLI:** koşu sonunda `--quiet` olmayan her kipte stderr'e tek satır: `TEMBEL KİP: 4 200 / 163 141 fonksiyon decompile edildi; 3 başarısız; 158 938 ertelendi (158 141 seçilmedi, 797 bütçe); sürdürmek için: karadul decompile <ws> --devam`.
- **Rapor ("Derinlik" bölümü; `karadul/reporting/report_data.py`, fonksiyon sayacı `:734`):** dört gözlü tablo, yüzde yanında her zaman sayı:

  | | gövde var | gövde yok |
  |---|---|---|
  | adı var | … | … (kanal kırılımıyla: üst veri, ELF önyükü, FunctionID …) |
  | adı yok | … | … |

  "Adlandırılan fonksiyon oranı" tek sayı olarak verilmez; "programın kendi kodu" (`KENDI`) ayrı satırdır (`ustveri/PLAN.md` §risk 6: Go adlarının %72–94'ü kitaplık).
- **Sahte başarı denetimi (kabul ölçütü olarak yazılır):** (a) özet satırlarında "decompile edilen" sayısı `decompiled/` altındaki `.c` sayısına eşit; (b) `fonksiyon_toplam = edildi + başarısız + ertelenen`; (c) ertelenen > 0 iken çıkış ≠ 0; (d) hiçbir çıktıda ertelenen fonksiyon için boş ya da yer tutucu `.c` yok.

### 4.4 Arayüz

- Bugün düğümler `.c` dosyalarından kuruluyor (`ui/server.py:351`, dosya listesi `:370`): gövdesiz fonksiyon arayüzde hiç görünmez. Tembel kipte fonksiyon listesi `ghidra_functions.json` + `tembel_sira.jsonl`'den gelir; gövdesiz düğüm ayrı sınıfla (`cls: "ertelendi"`) listelenir: adı (varsa, etiketiyle), sınıfı, basamağı, kanıt sayısı, çağıran / çağrılan sayısı (türetilen `xrefs.json`'dan).
- Gövdesiz düğüme tıklayınca kod yerine durum ve tek eylem görünür: "Decompile edilmedi (büyük ikili kipi; sıra 12 345 / 158 141). [Decompile et]". Yer tutucu kod, sahte ilerleme, tahmini içerik gösterilmez (sahte veri yasağı).
- Sayaç şeridi: `decompile edildi D / program P`, `ertelendi E`; değerler `tembel_durum.json`'dan.
- Ölçek: 163 141 düğümün tek yanıtta gitmesi K13'ün aynısıdır; gövdesiz düğüm listesi sayfalı uçtan verilir (ÖL-8 `/api/functions?baslangic=&adet=&ara=`). ÖL-8 main'de değilse OL10-H yalnız sayaçları ve "ertelenenler" için sayfalı ayrı ucu ekler, var olan model yanıtına gövdesiz düğüm eklemez.

### 4.5 KaradulLM

- `get_decompiled` gövdesiz fonksiyonda bugün `veri_yok` döndürür (`karadul/lm/tools/read.py:71-75`; `ERR_NO_DATA`, `karadul/lm/tools/__init__.py:101`). Model bunu "veri bozuk" ile karıştırır. Yeni hata kodu: `ERR_NOT_DECOMPILED = "decompile_edilmedi"`; zarfında `durum`, `sinif`, `basamak`, `sira` ve "analist isteyebilir" notu.
- `get_evidence` / `get_xrefs` gövdesiz fonksiyonda da çalışır (türetilen `xrefs.json` tam nüfus); sonuçta `govde: "yok"` alanı ve sınırlama notu: "Gövde decompile edilmedi; geri çağrı kaydı ve satır sayısı yok."
- Ad araması / ters arama sonuçlarında her fonksiyonun `govde` alanı bulunur; model "kodu oku" adımını gövdesiz fonksiyonda denemeden önce bilir.
- Oturum açılış özetine (sistem bağlamı) tek satır: "Bu çalışma alanı büyük ikili kipinde: D / P fonksiyonun gövdesi var." Sayılar `tembel_durum.json`'dan; dosya yoksa satır yok.
- Model decompile başlatamaz (K-6; §5.5).

### 4.6 Kayıp sayacıyla ilişki (özet)

| Durum | Sayaç | Hata mı | Çıkış |
|---|---|---|---|
| seçildi, decompile edildi | `success` | hayır | — |
| seçildi, decompile başarısız | `failed`, `losses.decompile_failed` | evet (kayıp) | 3 |
| seçildi, toplam süre dolduğu için yapılamadı | `skipped`, `losses.decompile_skipped` | evet (kayıp) | 3 |
| seçildi, decompile bütçesi doldu | `deferred` (`ertelendi:butce`) | hayır (ertelenen) | 3 |
| seçilmedi | `deferred` (`ertelendi:secilmedi`) | hayır (ertelenen) | 3 |

## 5. İsteğe bağlı decompile ve sürdürme

### 5.1 Komut

```
karadul decompile <çalışma alanı> <adres | ad> …        # verilen fonksiyonlar (B0)
karadul decompile <çalışma alanı> --dosya liste.txt       # satır başına adres / ad
karadul decompile <çalışma alanı> --komsu <adres> [--komsu-derinligi 1]   # fonksiyon + çağırdıkları (STANDART / TASLAK hariç)
karadul decompile <çalışma alanı> --sonraki [N]           # kural sırasındaki sonraki N (öntanım secim_ust_sinir)
karadul decompile <çalışma alanı> --devam                 # yarıda kalmış dilimi sürdür
        [--adlandir | --adlandirma-yok]                   # ad hattını şimdi yeniden koş / koşma
```
`karadul/cli.py`'de `decompile` adlı komut bugün yok (komutlar: `version`, `analyze` `:634`, `run` `:1127`, `list` `:1318`, `rtti` `:2315` …); ad çakışması yok.

### 5.2 Akış: K2 her zaman kayıtlı projeden koşar

İlk koşunun K2'si, sürdürme ve isteğe bağlı decompile **aynı kod yolunu** kullanır:

1. K1, `pyghidra.open_program` bağlamında koşar ve bağlam kapanırken program kaydedilir (bağlam çıkışı = programın kaydı ve projenin kapanışı: `headless.py:712-714` `ADIM_KAPATMA`).
2. Seçim JVM bağlamının DIŞINDA, K1'in diske yazdığı JSON'lardan yapılır (saf Python).
3. K2: proje `analyze=False` ile yeniden açılır, verilen fonksiyon listesi decompile edilir, S için CFG çıkarılır, bağlam kapanır. Dayanak (kurulu pyghidra 3.0.0'ın kaynağı okundu: `site-packages/pyghidra/core.py`): proje varsa açılır ve program adı (öntanım: ikili dosyanın adı) projede kayıtlıysa `project.openProgram` ile açılır, yeniden içe aktarılmaz (`:121-127`); `open_program` bağlamı çıkışta `project.save(program)` ve `project.close()` çağırır (`:262-264`). Çözümlenmiş programda `shouldAskToAnalyze`'ın yanlış dönmesi ve `_run_auto_analysis`'in `already_analyzed` ile çıkması (`headless.py:802-804`) koşuyla doğrulanmadı: OL10-C adım 1'in fizibilitesi. (Aynı varsayım `olcek/PLAN.md` ÖL-9 adım 3'te de var.)

Bu düzenin gerekçesi: (a) tek yol → ilk koşu ile sonradan decompile'ın çıktısı yapı gereği aynı kuralla üretilir; (b) K1 bittiği anda diskte kalıcı bir denetim noktası vardır (süreç K2'de ölürse K1 yeniden koşmaz); (c) seçim kuralı köprüye gömülmez, saf modülde kalır. Bedeli: ilk koşuda bir ek "projeyi yeniden aç" süresi. Bu süre **ölçülmedi** (büyük programda saniyeler mi dakikalar mı bilinmiyor); OL10-C ölçer. Kabul edilemez çıkarsa (ön kayıt: T100'de > 300 sn) ilk koşunun K2'si K1 ile aynı bağlamda koşar, kayıt K1 sonunda açıkça istenir; sonradan decompile yine kayıtlı projeden koşar.

Proje: tembel kipte silinmez (K-9). Yeri bugünkü yer (`static/ghidra_project`, `karadul/ghidra/project.py:33`). ÖL-9 (sha256 anahtarlı önbellek) geldiğinde proje önbelleğe taşınır ve `tembel_durum.json` `proje.yol` onu gösterir; ÖL-10, ÖL-9'u beklemez. İlişki: ÖL-9 "aynı ikiliyi yeniden açınca Ghidra'yı baştan koşma" işidir; ÖL-10'un gereksindiği yalnız "bu çalışma alanının projesi yerinde dursun"dur. ÖL-9'un anahtarına (dilimin sha256'sı + Ghidra sürümü + çözümleyici ayarı özeti + Karadul sürümü; `olcek/PLAN.md` ÖL-9 adım 1) ÖL-10 bir şey eklemez: proje K1'in ürünüdür, seçimden bağımsızdır.

Tutarlılık denetimi (komutun ilk işi): `tembel_durum.json` var mı; `proje.saklandi` doğru ve dizin yerinde mi; `raw/` altındaki dilimin sha256'sı `target_info.json`'dakiyle aynı mı; Ghidra sürümü K1'inkiyle aynı mı (`ghidra_status.json`). Biri tutmazsa çıkış 2 ve açık ileti ("proje yok: K1 yeniden koşmalı; `karadul analyze … --derinlik tembel`"). Sessiz yeniden analiz yok.

### 5.3 Çıktının çalışma alanına eklenmesi

- `.c` dosyaları `static/ghidra_output/decompiled/` altına eklenir; dosya adı K1 sonunda bütün fonksiyonlar üstünden yapılmış plandan gelir (plan `tembel_sira.jsonl`'de saklanmaz; `_plan_decompile_filenames` belirlenimci olduğu için `functions.json`'dan yeniden üretilir: `headless.py:1467-1483`).
- `decompiled.json`, `pcode.jsonl`, `cfg.json`, `ghidra_status.json` ve `static/ghidra_*.json` kopyaları: yeni kayıtlar eklenir, sayaçlar güncellenir, her dosya atomik yeniden yazılır. Bu dosyalar tembel kipte yalnız S'yi taşıdığı için küçüktür. Kayıt sırası adres sırasıdır (ekleme sırası değil): böylece dosya içeriği "hangi sırayla istendiği"nden bağımsızdır.
- `tembel_durum.json` ve `tembel_sira.jsonl` güncellenir; `dilimler`'e bir satır eklenir (kaynak: `istek` / `sonraki` / `devam`).
- Yol bağımsızlığı (ön kayıtlı, H-I1): S₀ ile koşup sonra Δ'yı istemek ↔ baştan S₀ ∪ Δ ile koşmak, `static/` altında aynı içeriği verir (süre alanları ve `dilimler` hariç).

### 5.4 Ad hattı: iki hız

- **Hemen (saniyeler; ad hattı koşmaz):** yeni `.c`'ye var olan ad haritası basılır (Aho-Corasick, `_apply_aho_replace` ile aynı işlev) ve dosya `reconstructed/` altındaki son dizine eklenir. Analist kodu, bilinen adlarla hemen okur. Yeni fonksiyonun kendisine ad üretilmez; durumu `ad_hatti: "bekliyor"`.
- **Toplu (`--adlandir`; `--sonraki` ve `--devam` dilimlerinin sonunda öntanım olarak koşar, `--adlandirma-yok` ile kapatılır; tek tek isteklerde öntanım koşmaz):** yeniden kurma aşaması birikmiş S üstünde BAŞTAN koşar. Artımlı ad hattı yok: `c_namer`'ın çözümlemesi nüfusa bağlı olduğu için (§3.3) yalnız yeni fonksiyonu adlandırmak, aynı kümeyi baştan seçmiş bir koşudan farklı ad verebilir. Baştan koşmak yol bağımsızlığını korur; maliyeti S ile sınırlıdır (TAHMİN: 5 000 fonksiyon ≈ 14,5 dk yük altında; HZ-7 paketleriyle düşer).
- Hangi kanal yeniden koşar: gövde isteyen kanallar (tablo §3.2'de "yalnız S") baştan; B / J girdili kanallar (üst veri, ELF önyükü, FunctionID, K-4) aynı girdiyle aynı sonucu verir, yeniden koşmaları zararsızdır (ayrı önbellek yazılmaz).
- Analistin elle verdiği adlar korunur (var olan yol: `force_manual_names`, `_feedback_naming_merger.py:187`).

### 5.5 Arayüzden ve KaradulLM'den tetikleme

- **Arayüz:** gövdesiz düğümdeki "Decompile et" düğmesi sunucuda `karadul decompile <ws> <adres>` işini başlatır (var olan iş kuyruğu; ilerleme `_job_progress`, `ui/server.py:2477`). Aynı çalışma alanında aynı anda tek decompile işi (proje kilidi); ikinci istek kuyruğa girer. İş bitince düğüm gövdeli olur; sayfa yenilenmeden yalnız o düğüm güncellenir.
- **KaradulLM:** model süreç başlatamaz ("süreç başlatan araç hiçbir kipte yoktur": `karadul/lm/tools/__init__.py:50-55`). Yeni "Ö" sınıfı araç `request_decompile(addr, neden)`: bir **öneri kaydı** açar (`ACTION_PROPOSE`, `:54-55`); analist onaylarsa arayüz yukarıdaki işi başlatır. Model sonucu aynı turda göremez; bir sonraki turda `get_decompiled` çalışır. Oturum başına öneri sayısı sınırlıdır (öneri: 20; sabit araç kaydında tek yerde). Öneri kayıtları P22e'nin öneri altyapısına bağlıdır; P22e main'de değilse araç kayıt defterine girmez (`arac_kapali`) ve model yalnız "bu fonksiyon decompile edilmedi; analist isteyebilir" bilgisini verir.

### 5.6 Sürdürme (kaldığı yerden)

| Kesinti anı | Diskte ne var | Sürdürme |
|---|---|---|
| K0 sırasında | hiçbir şey ya da `static/k0_ozet.json` | baştan (saniyeler) |
| K1 sırasında | adım adım yazılmış K1 JSON'ları olabilir; proje kaydedilmemiş | K1 baştan (bağlam kapanmadığı için kayıt yok). Otomatik analizin ortasından sürdürme bu tasarımda YOK; ÖL-1 bekçisi ve ÖL-2 bütçeleri K1'i sınırlar. OL10-C'nin fizibilitesi bağlam kapanmadan açık kaydın mümkün olduğunu gösterirse kayıt otomatik analiz biter bitmez alınır; o zaman döküm adımlarında (fonksiyon listesi, dizgi, çağrı grafiği) kesilen koşu analizi yinelemez |
| K1 bitti, K2 başlamadı | K1 JSON'ları + kayıtlı proje + `tembel_durum.json` (`k2: "yok"`) | `karadul decompile <ws> --devam`: seçim yeniden hesaplanır (belirlenimci), K2 baştan |
| K2 decompile sırasında | biten partilerin `.c`'leri + `tembel_gunluk.jsonl` (parti bitince eklenen satırlar) | `--devam`: günlükte bitmiş görünen fonksiyon yeniden decompile edilmez; kalan aynı sırayla |
| ad hattı sırasında | `static/` tam; `reconstructed/` yarım | ad hattı baştan (S ile sınırlı) |

Parti günlüğü (`static/tembel_gunluk.jsonl`): her parti bitince tek satır (parti no, adresler, başarı / hata sayısı) `flush` + `fsync` ile eklenir. Dilim bitince `tembel_sira.jsonl` yeniden yazılır ve günlük boşaltılır. Sürdürmenin kabul ölçütü ön kayıtlıdır (H-I2): kesilip sürdürülen koşunun `static/` içeriği kesintisiz koşununkiyle aynı; yeniden decompile edilen bitmiş fonksiyon 0.

Paket hedefinde sürdürme ÖL-5b'dir (bileşen kuyruğu); ÖL-10 bileşenin İÇİNDEKİ sürdürmeyi verir. İkisi birleşince: paket kesilir → bitmiş bileşenler atlanır (ÖL-5b), yarım bileşen K1 bittiyse K2'den sürer (ÖL-10).

## 6. Kabul ve ön kayıt

### 6.1 Plandaki ön kayıt neden bu hâliyle kullanılamaz

`olcek/PLAN.md` ÖL-10 (satır 350-351): "T100'de ilk rapor ≤ 60 dk; seçilen fonksiyonlarda ad / `.c` tam kiple aynı … seçilen kümede eşitlik %100." Üç sorun:

1. **"İlk rapor" tanımsız ve 60 dakika TAHMİN aralığının içinde.** K1 tek başına [38,0; 72,1] dk (TAHMİN); `olcek/on_kayit_olc1.md`'nin kuralıyla bu "belirsiz" bir öngörüdür (aralık eşiği içeriyor), tuttu / tutmadı hükmü verilemez. Tembel kip K1'i kısaltmaz.
2. **T100'de tam kip tabanı yok.** T100'ün tam kip koşusu TAHMİN 14,5–39,4 saat (yalnız köprü); "seçilen kümede tam kiple eşitlik" T100'de ölçülemez. Eşitlik yalnız tam kipin bittiği yerde ölçülür: S8 (8 ikili) ve T25 (Ollama dilimi).
3. **Ad eşitliği yapı gereği garanti değil** (§3.3 madde 3). Garanti edilebilen ve L = 10 kuralının (A-2) istediği şey "tembel kip yeni yanlış ad üretmez"dir.

Yerine (K-1, K-2):

| Parça | Ölçüt | Nerede ölçülür |
|---|---|---|
| (a) süre | K0 özeti ≤ 300 sn (kaba sınır: K0 çekirdeği T100'de 0,65 sn ölçüldü; statik aşamanın Ghidra'dan önceki öbür adımları — kopya, `strings`, `nm`, `lief`: `macho.py:265-423` — T100'de ölçülmedi); K1 biter ya da bütçeyle kısmi biter (süresi kayda geçer, hüküm yok); **K2: K1'in bitişinden rapora ≤ 2 700 sn** (öntanım sınırlarla: 1 200 sn decompile + ≤ 5 000 fonksiyonda ad hattı + proje açma; TAHMİN üst ucu 37 dk + 5 dk proje açma) | T25, T100 (boş makine, `--tek`) |
| (b) çıktı eşitliği | S'deki her fonksiyonun ham `.c`'si tam kiptekiyle bayt eşit; `decompiled.json` / `cfg.json` S kayıtları JSON-eşit, `pcode.jsonl` S satırları bayt eşit; türetilen `function_xrefs` tam nüfusta JSON-eşit | S8, T25 |
| (c) ad | kip kapalı: 119 / 119 `naming_map.json` bayt eşit. Kip açık: S'deki anahtarlarda tam kipte olmayan ad 0, farklı ad 0; eksik ad sayılır ve raporlanır; gövdesiz fonksiyona ad yalnız §3.2'nin "evet" dediği kanallardan | 119 (kapalı); S8 + T25 (açık) |
| (d) görünürlük | §4.3'teki dört sahte başarı denetimi; değişmez `fonksiyon_toplam = edildi + başarısız + ertelenen` | her tembel koşu |
| (e) sürdürme | yol bağımsızlığı (H-I1) ve kesip sürdürme (H-I2) | T25 |
| (f) gerçek uygulama | hedef setinde tembel kip uçtan uca biter; üst veri kaynaklı doğru ad sayısı tam nüfusta, Ghidra'sız aday sayımıyla aynı | terminal-notifier, docker-cli (keşif); docker-compose, iTerm2, llama-server (sınama, bir kez) |

### 6.2 Ön kayıt metni (OL10-J; ölçümden önce `olcek/on_kayit_OL10J.md` olarak commit'lenir; sayıları uygulayan ajan değiştirmez)

> **Ürün:** OL10-A … OL10-I main'de olan commit (hash koşu künyesinde). **Ayar:** `buyuk_ikili.tembel: true`, `esik_mb: 0`, `secim_ust_sinir: 5000`, `decompile_butcesi_sn: 1200` ("öntanım sınırlar"); eşitlik kollarında `secim_ust_sinir: 0`, `decompile_butcesi_sn: 0`. Üst veri bayrakları (`enable_go_pclntab_naming`, `enable_objc_metadata_naming`, o gün main'de olan öbürleri) açık. Koşucu `scripts/measurement/olcek_kos.py`; Ghidra kuyruğu; süre hükmü verilen koşular `--tek` ve boş makinede (1 dk yük < 0,25 × çekirdek sayısı).
>
> H-J1 (T100, süre; duvar 10 800 sn): K0 özeti (`static/k0_ozet.json`) koşunun başından ≤ 300 sn sonra yazılır. K1 süresi kayda geçer (belirsiz öngörü [2 282; 4 327] sn; hüküm yok). K1 duvar içinde biterse: K1'in bitişinden `reports/report.json`'a ≤ 2 700 sn. K1 duvara dayanırsa: koşu `zaman_asimi` ile biter, "K1 bitmedi" yazılır, H-J1'in K2 kısmı "ölçülmedi" kalır.
> H-J2 (T100, kaynak): tepe ağaç RSS'i ≤ 0,85 × RAM; çalışma alanı diski ≤ 10 GB; Ghidra projesi boyutu raporlanır (öngörü [0,3; 0,9] GB).
> H-J3 (T25, eşitlik; taban = aynı commit'in tam kip koşusu): `secim_ust_sinir: 0` iken S'deki bütün `.c` dosyaları tabanla bayt eşit; `function_xrefs` JSON-eşit. S8'de aynısı 8 / 8.
> H-J4 (T25 ve S8, ad): S'deki anahtarlarda tam kipte olmayan ad 0 ve farklı ad 0. Eksik ad sayısı raporlanır; öngörü: OL10-B'nin aynı kümede ölçtüğü sayının ± %20'si (yoksa öngörü yok).
> H-J5 (kip kapalı): 119'luk birleşik koşuda `naming_map.json` 119 / 119 tabanla bayt eşit; doğru / yanlış ad sayıları aynı.
> H-J6 (T25, süre; boş makine): tembel kip uçtan uca ≤ 0,5 × aynı commit'in tam kip süresi (TAHMİN oran 0,38–0,41: öntanım sınırlarla S = 4 619 program fonksiyonu + 381 taslak → [2 909; 3 200] / 7 729; §2.5'in hesabının aynısı, yük altındaki gösteri sayılarından).
> H-J7 (görünürlük; bütün tembel koşular): çıkış kodu 3; `partial_reasons`'ın her öğesi `tembel derinlik:` ile başlar (başka hata yoksa); `decompile_edildi` = `decompiled/` altındaki `.c` sayısı; değişmez tutar; ertelenen fonksiyon için yer tutucu dosya 0.
> H-J8 (hedef seti, keşif; soyulmuş kopyalar): terminal-notifier (`esik_mb: 0` ile tembel): üst veri kaynaklı doğru ad ≥ 30 / 32, yanlış 0 (PUV6a H3 ile aynı sayı: tembel kip üst veri adını eksiltmez). docker-cli (duvar 7 200 sn): koşu biter (çıkış 3); üst veri kaynaklı ad sayısı, aynı commit'in Ghidra'sız aday sayımının (PUV6a `ustveri_urun.py`) ≥ %99'u; GT'ye göre yanlış ≤ %0,1.
> H-J9 (hedef seti, SINAMA; bir kez, kurallar dondurulduktan sonra; duvar 7 200 sn): docker-compose, iTerm2, llama-server için: bitti mi, K0 / K1 / K2 süreleri, doğru / yanlış ad sayısı (HEDEF.md kalem 4'ün tanımıyla; llama-server ve iTerm2'de soyulamayan semboller ölçüm nüfusundan çıkarılır: `DURUM.md` "HEDEF → ölçüm"). Öngörü: üçü de duvar içinde K0 özetini verir; K1'in bitmesi için öngörü yok.
> H-J10 (PAKET, yalnız ÖL-5a main'deyse; FreeCAD.app, duvar 7 200 sn): paket K0 özeti ≤ 600 sn; ana bileşen raporu duvar içinde; eşiği aşan her bileşende `tembel_durum.json` var. ÖL-5a main'de değilse "ölçülmedi (önkoşul yok)".
> Tutmayan hüküm silinmez; nedeni ayrıca yazılır. Aralığı eşiği içeren öngörüye hüküm verilmez.

Koşu sırası (OL10-J): gündüz, kuyrukla (iki yuva; süre hükmü yok): S8 eşitlik (H-J3 / H-J4 / H-J7), terminal-notifier, T25'in ad ve eşitlik kolu, docker-cli. Gece, `--tek`: T25 süre çifti (tam + tembel; H-J6), T100 (H-J1 / H-J2), sınama ikilileri. 119 kapalı kip koşusu (H-J5) ad ölçen sıradan birleşik koşudur (`urun_kos.py`, taban koşusu 70 dk: `karsi/KARSI.md` İ-10).

## 7. Uygulama planı

### 7.0 Paketler, sıra, zincirdeki yer

Ortak kurallar: `docs/arge/2026-11-23_dalga1/ORTAK_D1.md` ve `docs/arge/2026-11-20_dalga0/ORTAK_D0.md` (worktree, commit, ön kayıt ayrı commit, mutasyon, tam takım, Ghidra kuyruğu, sahte veri yok). `karadul/config.py`'ye hiçbir paket yazmaz; yama bırakır. Her paketin raporunun ilk satırı gerçek uygulama sayısıdır. İlerleme dosyası `docs/arge/2026-11-19_mythos/olcek/<PAKET>.md` (ör. `OL10A.md`), ön kayıt `on_kayit_<PAKET>.md`, mutasyon tanımı `scripts/measurement/mutation_specs_<paket>.json`.

| Sıra | Paket | Tema | Ortak dosya zinciri | Önkoşul | Ghidra |
|---|---|---|---|---|---|
| 1 | **OL10-A** | saf çekirdek: seçim kuralı, xref türetme, kuru seçim aracı | yok (yalnız yeni dosya) | yok — **bugün yazılabilir** | yok |
| 2 | **OL10-B** | ad hattı kesit deneyi (Ghidra'sız yeniden oynatma) | yok (yalnız yeni betik) | OL10-A main'de | yok |
| 3 | **OL10-C** | köprü kesit ölçümü (ürün kodu değişmeden) | yok (yalnız yeni betik) | OL10-A main'de; B ile paralel | var; süre kolu gece `--tek` |
| 4 | **OL10-D** | köprü: K1 kipi, kayıtlı projeden seçili decompile | `karadul/ghidra/headless.py` | zincir: P16e → ÖL-1 → ÖL-2 → HZ-2 → ÖL-3 + HZ-4a → HZ-3 → ÖL-6 → **OL10-D**; OL10-C'nin H-C1 / H-C2 / H-C5 hükmü | var |
| 5 | **OL10-E** | statik aşama: kip kararı, K0, tembel akış, durum dosyası, proje saklama | `karadul/analyzers/macho.py` (ÖL-3'ten sonra; ÖL-9'dan önce) | OL10-A, OL10-D | var |
| 6 | **OL10-F** | yeniden kurma sözleşmesi (§3) | `c_namer.py` (P12d → ÖK-1 → ÖK-2'den sonra), `stages.py` (PUV6a → PUV5'ten sonra), `kesin_anchors.py` | OL10-A; OL10-B'nin hükümleri; OL10-E ile paralel olabilir | yok (kesit düzeneği) |
| 7 | **OL10-G** | görünürlük 1: rapor, CLI satırı, `--derinlik` | `karadul/cli.py` (ÖL-4 → ÖL-5b zinciri), `karadul/reporting/` | OL10-E | yok |
| 8 | **OL10-H** | görünürlük 2: arayüz, KaradulLM | `ui/server.py`, `ui/index.html` (ÖL-4, ÖL-8, P22c / P22h ile sıralı), `karadul/lm/tools/` | OL10-E; P22e (öneri altyapısı) varsa adım 5 | yok |
| 9 | **OL10-I** | isteğe bağlı decompile ve sürdürme | `karadul/cli.py` (OL10-G'den sonra), `ui/server.py` (OL10-H'den sonra) | OL10-E, OL10-F | var |
| 10 | **OL10-J** | uçtan uca kabul ölçümü | yok | hepsi main'de; PUV6a main'de | var; gece |

- **Zinciri beklemeden yazılabilenler:** OL10-A, OL10-B, OL10-C (üçü de yalnız yeni dosya). Bunlar tasarımın ölçmeden bilinemeyen dört sorusunu (K1 süresi, proje açma süresi, kısmi nüfusta ad farkı, tembel kipte reconstruct süresi) ürün koduna dokunmadan cevaplar; OL10-D … OL10-I'nin ön kayıt sayıları onlardan gelir.
- **`headless.py` zincirindeki yer:** OL10-D zincirin SONUNDA. Gerekçe: OL10-D decompile kuyruğuna (HZ-3 yeniden yazıyor: ortak kuyruk + parti), CFG döngüsüne (HZ-4a yeniden yazıyor) ve adım atlamaya (ÖL-2'nin bütçe / kısmi sözleşmesiyle aynı yer) dokunur. Önce girerse HZ-3 ve HZ-4a "çıktı aynı" kabulünü tembel kol için de taşımak zorunda kalır. ÖL-6 ile sırası serbesttir (ikisi de döngüye koşul ekler); verilen zincirdeki sıra korunur.
- Aynı anda en çok 4 ajan kuralıyla örnek akış: (A) → (B ║ C) → … zincir biter … → (D) → (E ║ F) → (G ║ H) → (I) → (J).
- **Dalga 4'e bağımlılıklar:** ÖL-1 (K1'de takılan çözümleyici bekçisi; ilerleme olayları), ÖL-2 (K1 adım bütçeleri), ÖL-3 (K1 JSON'larının akış biçimli yazımı: T300 belleği), PUV6a / P-ÜV6b (tembel kipin ad kaynağı), ÖL-5a (paket). ÖL-9 önkoşul değildir (§5.2).

### 7.1 OL10-A — saf çekirdek: seçim kuralı, xref türetme, kuru seçim aracı

**Amaç.** §2'nin kuralını ve §1.3'ün türetmesini Ghidra'sız, saf Python modülleri olarak yazmak; var olan çalışma alanlarında kuru seçim yapan aracı vermek.

**Dokunur (hepsi yeni).** `karadul/core/tembel_secim.py`, `karadul/core/tembel_girdi.py`, `karadul/core/tembel_xref.py`, `scripts/measurement/tembel_kuru.py`, `tests/test_ol10a_secim.py`, `tests/test_ol10a_xref.py`, `scripts/measurement/mutation_specs_ol10a.json`, `docs/arge/2026-11-19_mythos/olcek/{on_kayit_OL10A,OL10A}.md`.
**Dokunmaz.** `karadul/config.py`, `karadul/ghidra/`, `karadul/analyzers/` (okuyucular yalnız içe aktarılır: `karadul/analyzers/ustveri/{goruntu,go_pclntab,objc}.py`), `karadul/stages.py`, `karadul/pipeline/`.

**Adımlar.**
1. `tembel_secim.py`: sabitler (`KURAL_SURUMU = 1`, `GIRIS_DERINLIGI = 2`, `GIRIS_UST_SINIR = 256`, sınıf ve basamak adları); veri sınıfları (`SecimGirdisi`: fonksiyon → boyut / taslak, fonksiyon → dizgi adresi kümesi, fonksiyon → çağrılan kümesi, giriş kümesi, sınıf haritası; `SecimSonucu`: sıralı (adres, basamak, sınıf, anahtar) listesi + sayım + sha256). Go sınıf sabitleri `go_pclntab.py:95-101`'den içe aktarılır.
2. `sec(girdi, istek=()) → SecimSonucu` ve `kes(sonuc, ust_sinir)`: §2.2–§2.4 birebir. Adres karşılaştırması tam sayıyla. İç yapı küme / sözlük; çıktı sırası yalnız anahtardan.
3. `tembel_girdi.py`: `girdiden_kur(functions_doc, strings_doc, call_graph_doc, goruntu=None)`: K1 JSON'larından ve (verilirse) görüntüden girdi. `tembel_secim.py` saf kalır (dosya okumaz, `karadul.pipeline`'a bağlı değildir); bağdaştırıcı ayrı modüldedir. Ghidra adresi ↔ ikili adresi farkı için `load_ghidra_index`'in taban farkı mantığı kullanılır (`karadul/pipeline/steps/_feedback_naming_candidates.py:218-248`; kopyalanmaz, işlev içinde geç içe aktarılır: çekirdek modül yüklenirken `karadul.pipeline` yüklenmez). Giriş: `Goruntu.giris_adresi` (`goruntu.py:204`) adresini içeren fonksiyon + üst veride `main.main` + Ghidra adı `entry`.
4. `tembel_xref.py`: `turet(functions_doc, strings_doc, call_graph_doc) → dict`: `function_xrefs` (bütün fonksiyonlar; alan adları ve sırası `_extract_xrefs` ile aynı: `headless.py:1896-1941`), `statistics` (`total_globals_with_xrefs: null`), ek alanlar `kapsam: "tam_nufus"`, `kaynak: "turetildi"`. `strings_used` sırası: fonksiyon içinde başvuranın adresine göre artan (dökümün gövde tarama sırası); `called_by` adrese göre artan (P16e'nin kuralı).
5. `tembel_kuru.py`: `--ws <çalışma alanı> [--ikili <dilim>] [--ust-sinir N] [--cikti <json>]`: sınıf / basamak sayımı, gövde baytı, seçim sha256'sı; `--xref-denetle`: türetilen ↔ dökülen `function_xrefs` (alan bazında fark sayımı); `--k0 <ikili>`: yalnız K0 sınıf sayımı (Ghidra çıktısı olmayan hedefler için).
6. Okuyucu envanteri: `grep -rn "function_xrefs\|total_globals_with_xrefs\|strings_used\|called_by" karadul ui scripts` çıktısından `xrefs.json`'ı okuyan her yer ve okuduğu alan ilerleme dosyasına tablo olarak; türetilen dosyada eksik kalan alan olmamalı.
7. Testler (Ghidra yok, sentetik girdi; ≥ 24): her basamağın üyeliği ve sırası; E'nin sınıf istisnası; genişleme `STANDART` / `TASLAK`'tan geçmez; derinlik ve 256 sınırı; kanıt küme boyutudur (aynı dizgiye iki başvuru 1 sayılır); `STANDART` kendiliğinden seçilmez, istekle seçilir; taslak yalnız B6'da (E üyesi taslak B1'de); ana modül bulunamazsa `BAGIMLILIK` B2'de; adres sırası tam sayıyla (`"9f0"` < `"1000"`); 20 tohumlu permütasyonda aynı sha256; `kes`; boş girdi; türetme eşitliği sentetik örnekte.
8. Ölçüm (ön kayıttan sonra; Ghidra yok) ve mutasyon.

**Kabul ölçütü.** İlk satır: Ollama dilimi (gösteri çalışma alanı) sınıf ve basamak sayıları §2.5 tablosuyla aynı. Testler geçer; mutantların hepsi ölür; tam takım 0 hata.

**Ön kayıt (`on_kayit_OL10A.md`).**
> H-A1 (Ollama dilimi, gösteri çalışma alanı): sınıf `KENDI` 1 406, `BILINMIYOR` 2 619, `BAGIMLILIK` 594, `STANDART` 8 541, `TASLAK` 399; basamak B1 36 (+ giriş taslağı `entry`), B2 1 373, B3 1 236, B4a 547, B4b 836, B5 591, B6 398. Fark çıkarsa kural metniyle hangisinin uyuştuğu yazılır (bu sayılar tasarım turunun kuru sayımıdır: `OL10_TASARIM.md` Ek B-1).
> H-A2 (belirlenimcilik): S8 tabanının 8 çalışma alanı + gösteri: 20 permütasyonda seçim sha256'sı değişmez (9 / 9). S8 tabanı ↔ A/A tekrarı (`s8_taban_b6aceb9` ↔ `s8_taban_b6aceb9_AA`) seçim sha256'sı aynı (8 / 8): çağıran sırası farkı seçimi etkilemez.
> H-A3 (xref türetme): 9 çalışma alanında türetilen `function_xrefs` dökülenle JSON-eşit (`called_by` sıra-normal karşılaştırılır; tabanlar P16e'den önce üretildi); `statistics.total_functions` ve `total_strings_with_xrefs` eşit. Eşit olmayan her fonksiyon alan türüyle sayılır.
> H-A4 (C ikilileri, S8; kural adlı olacak fonksiyonu öne alıyor mu): `ust_sinir` = bütün fonksiyonların yarısı iken, tam kipte ad verilen fonksiyonların (taban `naming_map.json` `global`, `FUN_` anahtarları) ≥ %60'ı seçili kümededir (rastgele seçimde beklenen %50). Dayanağı zayıf bir öngörüdür (tek dayanak: gösteride 17 adın 10'u B3'te); sonuç ne çıkarsa kayda geçer. `ust_sinir = 0` iken C ikilisinde seçili küme bütün fonksiyonlardır (`STANDART` sınıfı yok): bu bir testtir, öngörü değil.
> H-A5 (hedef seti, keşif, K0): terminal-notifier'da 32 ObjC yöntem adresinin 32'si `KENDI`; docker-cli'de Go sınıf dağılımı raporlanır (ilk ölçüm, öngörü yok).
> H-A6 (SINAMA; dondurma commit'inden sonra bir kez): docker-compose, iTerm2, llama-server K0 sınıf sayımı raporlanır. Öngörü: docker-compose'da `STANDART` payı ≥ %50 (dayanak: Go adlarının %72,3–%93,6'sı kitaplık, `ustveri/BULGULAR.md` satır 374).
> H-A7 (süre, kaba sınır; yük altında): `sec` gösteri girdisinde (13 160 fonksiyon) ≤ 5 sn; 163 141 fonksiyonluk sentetik girdide ≤ 60 sn.

**Mutasyon (≥ 14).** B2 ↔ B3 sırası; `STANDART` seçilir; E'nin sınıf istisnası kalkar; genişleme `STANDART`'tan geçer; derinlik 2 → 3; 256 sınırı uygulanmaz; kanıt liste uzunluğu olur (küme değil); içe aktarım kanıta katılmaz; adres dizgi olarak karşılaştırılır; B4a'nın "çağrılan" koşulu düşer; `kes` N + 1 alır; istek sırası adres sırasına döner; taslak B6 yerine B4b'ye girer; ana modül bulunamayınca `BAGIMLILIK` B5'te kalır; türetmede `called_by` ↔ `functions_called` takası; `kapsam` alanı yazılmaz; `total_globals_with_xrefs` 0 yazılır.
**Bayrak.** Yok (modül bayrak okumaz; sınırlar parametredir).

### 7.2 OL10-B — ad hattı kesit deneyi (Ghidra'sız yeniden oynatma)

**Amaç.** "Nüfusun bir kısmının gövdesi yokken ad hattı ne yapar?" sorusunu ürün koduna dokunmadan ölçmek: S üstünde tembel ↔ tam ad farkı (aynı / eksik / fazla / farklı), gövdesiz fonksiyona hangi kanal ad yazıyor, süre. §3.2 tablosu ve §3.3 riskleri bu sayılarla doğrulanır; OL10-F'nin "önce" sayıları buradan gelir.

**Dokunur (yeni).** `scripts/measurement/tembel_kesit.py`, `tests/test_ol10b_kesit.py`, `scripts/measurement/mutation_specs_ol10b.json`, `docs/…/olcek/{on_kayit_OL10B,OL10B}.md`. Koşu kökü `~/karadul_olcum/runs/dalga1-2026-11-23/OL10B/` (ya da o günün dalga kökü).
**Dokunmaz.** Ürün kodu; taban kökleri (salt okur: `~/karadul_olcum/runs/gosteri-2026-11-19/`, `…/dalga0-2026-11-20/s8_taban_b6aceb9/`, `…/urun-onarim-a62f15e/`); `scripts/arge/hiz/profil_yeniden.py` (yöntemi örnek alınır, dosya değişmez).

**Adımlar.**
1. Düzenek (`profil_yeniden.py`'nin yöntemi: çalışma alanı `reconstructed/`, `reports/`, `deobfuscated/` hariç kopyalanır; kopyada deobfuscate ve `ReconstructionStage().execute` koşar). İki kol aynı ürün ağacıyla: **tam** (kopya olduğu gibi) ve **tembel** (aşağıdaki kesitle).
2. Kesit: S dışındaki fonksiyonların `.c`'leri kopyadan çıkarılır (dosya ↔ adres eşlemesi `.c` başlığındaki `// Address:` satırından); `ghidra_decompiled.json`, `ghidra_cfg.json`, `ghidra_output/pcode.jsonl` S'ye indirilir; `ghidra_xrefs.json` iki alt kolda: (x-tam) `tembel_xref.turet` çıktısı, (x-kısmi) S'ye indirilmiş döküm.
3. S'nin seçimi `tembel_secim` ile: gösteride kural sürümü 1, üç kesim (B1–B2; B1–B4; B1–B5); C ikililerinde (üst veri sınıfı yok) `ust_sinir` = program fonksiyonlarının %25'i ve %50'si.
4. Karşılaştırıcı: S'deki `FUN_` anahtarları için `naming_map.json` `global`: aynı / eksik / fazla / farklı; `naming_provenance.json`'dan kanal kırılımı; S dışındaki fonksiyonlara verilen adlar kanal kanal; `per_function` haritasında aynı sayım; GT'si olan kümede (119) fazla / farklı adların doğru / yanlış sayısı (`scripts/measurement/urun_olc.py`'nin eşitlik tanımı içe aktarılır).
5. Kümeler: gösteri (Ollama dilimi); S8'in 8 çalışma alanı; 119'un tamamı (`urun-onarim-a62f15e`, %50 kesim, x-tam).
6. Süre: iki kolun deobfuscate ve reconstruct süreleri (`uptime` künyesiyle; "yük altında"; yalnız oran yorumlanır).
7. Testler (sentetik çalışma alanı; ≥ 10) ve mutasyon.

**Kabul ölçütü.** İlk satır: "Ollama dilimi, S = B1–B4 (4 028 + giriş taslağı): tam kolun 17 adının x'i tembel kolda aynı; fazla y; farklı z; reconstruct tembel / tam = r." Bütün ön kayıt satırları için tuttu / tutmadı; §3.2 tablosuyla uyuşmayan her kanal listelenir.

**Ön kayıt (`on_kayit_OL10B.md`).**
> H-B1 (düzeneğin gürültüsü): tam kol iki kez koşulduğunda `naming_map.json` bayt eşit (9 / 9: S8 + gösteri). Değilse deney geçersizdir, önce neden bulunur.
> H-B2 (ana hüküm; 119, %50 kesim, x-tam): S'deki anahtarlarda fazla + farklı ad ≤ tam kolun S'deki ad sayısının %1'i. Fazla / farklı adların GT'ye göre yanlış olanı ayrıca sayılır. Tutmazsa farkı üreten kanal ve kural adıyla yazılır.
> H-B3 (eksik ad; aynı küme): eksik ad ≤ %10. (Dayanak zayıf: kod okuması; ne çıkarsa kayda geçer.)
> H-B4 (gövdesiz ad): tembel kolda S dışındaki fonksiyona ad yazan kanalların listesi çıkarılır. Öngörü: `c_namer` kaynaklı gövdesiz ad > 0 (bugünkü ürün strateji döngüsünü bütün fonksiyonlarda döndürüyor: `c_namer.py:2245`); ELF önyükü ve bayt kalıbı kanalları tam koldakiyle aynı sayıda ad yazar.
> H-B5 (KS-1 tehlikesi): x-kısmi kolunda `ks1:*` kanalında fazla ad ≥ 1 (119 toplamında); x-tam kolunda 0.
> H-B6 (gnulib): `on_ad:gnulib` kanalında fazla + farklı ad sayısı raporlanır (öngörü yok).
> H-B7 (süre oranı; yük altında): gösteride, S = B1–B4: reconstruct tembel / tam ≤ 0,5 (doğrusal öngörü 0,30; üs 0,71 ile 0,42).

**Mutasyon (≥ 8).** S süzgeci tersine; fazla ↔ eksik takası; farklı ad "aynı" sayılır; x-kısmi ↔ x-tam kolu takası; kanal kırılımı yanlış alandan; taslak anahtarları paydaya girer; kopya yerine taban köküne yazma koruması kalkar; `.c` ↔ adres eşlemesi dosya adından (başlıktan değil).
**Bayrak.** Yok.

### 7.3 OL10-C — köprü kesit ölçümü (ürün kodu değişmeden)

**Amaç.** Tasarımın köprü tarafındaki dört varsayımını gerçek Ghidra koşusuyla sınamak: (1) kayıtlı projeden decompile, aynı bağlamdaki decompile ile aynı `.c`'yi verir; (2) alt küme decompile'ı öbür fonksiyonların çıktısını değiştirmez; (3) K1'in ve projeyi yeniden açmanın süresi; (4) büyük ikilide decompile hızı.

**Dokunur (yeni).** `scripts/measurement/tembel_kopru_kesit.py`, `tests/test_ol10c_kesit.py` (Ghidra'sız kısımlar), `scripts/measurement/mutation_specs_ol10c.json`, `docs/…/olcek/{on_kayit_OL10C,OL10C}.md`.
**Dokunmaz.** `karadul/ghidra/headless.py` (yalnız içe aktarılır: `_ensure_pyghidra_started` `:107`, `GhidraHeadless._run_auto_analysis` `:786`, `_extract_functions` `:868`, `_extract_strings` `:926`, `_extract_call_graph` `:996`, `_plan_decompile_filenames` `:1467`, `_decompile_single_function` `:1543`), ürünün geri kalanı.

**Adımlar.**
1. Fizibilite (tek küçük koşu: debian `cat`): K1 bağlamı kapanınca proje diskte mi; `pyghidra.open_program(..., analyze=False)` var olan programı açıyor mu (yeniden içe aktarmıyor mu); `GhidraProgramUtilities.shouldAskToAnalyze` yanlış mı. Sonuç ilerleme dosyasına; tutmazsa §5.2'nin yedek düzeni (K1 sonunda açık kayıt) denenir ve o yazılır.
2. Sürücü: K1 (ürünün statik yöntemleriyle; ayar ürünün `Config`'inden) → bağlam kapanır → `tembel_secim.sec` → proje yeniden açılır → S'nin decompile'ı (iş parçacığı sayısı ürünle aynı: `CPU_PERF_CORES`; dosya adı planı bütün fonksiyonlardan) → çıktı `<kök>/ghidra_output/`. Süre kaydı adım adım (K1 alt adımları, kapanış, yeniden açılış, decompile); `scripts/measurement/olcek_kos.py` örnekleyicisiyle tepe RSS ve disk.
3. Eşitlik (S8, kuyrukla, süre hükmü yok): S = bütün fonksiyonlar → `.c` dosyaları `s8_taban_b6aceb9` ile karşılaştırılır (`scripts/arge/hiz/s8_esitlik.py`; çağıran satırı sıra-normal, ham fark ayrıca). S = adres sırasında her ikinci program fonksiyonu → S'nin `.c`'leri.
4. T25 (Ollama dilimi; `gosteri.yaml`'ın çözümleyici ayarı; S = kural sürümü 1, B1–B4): K1, yeniden açılış, decompile süreleri ("yük altında" etiketiyle gündüz koşulabilir).
5. docker-cli (keşif; soyulmuş kopya `~/karadul_olcum/ustveri_set/docker-cli/bin`; duvar 7 200 sn): K1 biter mi; seçim sayımı; 1 200 sn bütçede decompile edilen fonksiyon.
6. T100 (duvar 10 800 sn; **yalnız boş makinede, `ghidra_kuyruk.sh --tek`**; K-11): K1 süresi, proje boyutu, yeniden açılış süresi, 1 200 sn bütçede decompile edilen fonksiyon, tepe RSS.
7. Testler (sürücünün Ghidra'sız parçaları: süre kaydı, karşılaştırıcı) ve mutasyon.

**Kabul ölçütü.** İlk satır: "T25: K1 … sn, yeniden açılış … sn, S (4 029) decompile … sn; T100: … (ya da 'gece koşusu bekliyor')." S8 eşitlik hükümleri verilmiş; T100 koşulmadıysa paket "T100 kolu bekliyor" notuyla kapanır (`## PAKET BİTTİ` yazılmaz; ana oturum gece koşusundan sonra kapatır).

**Ön kayıt (`on_kayit_OL10C.md`).**
> H-C1 (kayıtlı projeden decompile ≡ aynı bağlamda decompile): S8'in 8 ikilisinde bütün `.c` dosyaları tabanla bayt eşit (çağıran satırı sıra-normal; P16e main'deyse ham eşit).
> H-C2 (alt küme bağımsızlığı): her ikinci fonksiyon seçildiğinde S'nin `.c`'leri tabanla bayt eşit (8 / 8).
> H-C3 (T25 K1): boş makinede [303; 455] sn (gösteri 378,8 sn ± %20). Yük altında koşulursa hüküm verilmez.
> H-C4 (T100 K1; boş makine): belirsiz öngörü [2 282; 4 327] sn (hüküm yok). Kesin öngörü: K1 10 800 sn duvarında biter (kötümser B 22 079 sn bunu bozar; bozarsa B'nin yönü kayda geçer).
> H-C5 (projeyi yeniden açma): T25'te ≤ 60 sn, T100'de ≤ 300 sn. (İlk ölçüm; eşikler §5.2'deki tasarım kararının eşikleridir. T100'de aşılırsa ilk koşunun K2'si K1 ile aynı bağlamda koşacak biçimde OL10-D / OL10-E metni güncellenir.)
> H-C6 (T100 decompile hızı): 1 200 sn bütçede decompile edilen fonksiyon ∈ [3 339; 31 088].
> H-C7 (T100 kaynak): proje boyutu ∈ [0,3; 0,9] GB; tepe RSS raporlanır (öngörü yok).

**Mutasyon (≥ 6).** Karşılaştırıcıda sıra-normal adımı her satıra uygulanır (fark gizlenir); seçim yerine bütün fonksiyonlar; süre kaydında yeniden açılış K1'e katılır; bütçe aşımında döngü sürer; dosya adı planı yalnız S'den; eşitlik hükmünde eksik dosya "eşit" sayılır.
**Bayrak.** Yok.

### 7.4 OL10-D — köprü: K1 kipi ve kayıtlı projeden seçili decompile

**Amaç.** Köprüye iki yetenek: (1) yalnız K1'i koşup durmak; (2) kayıtlı projeyi açıp verilen fonksiyon listesini (öncelik sırasıyla, bütçeyle) decompile etmek ve yalnız onların CFG'sini çıkarmak. Seçim kuralı köprüye girmez.

**Önkoşul.** `headless.py` zincirinin sonu (§7.0). OL10-C'nin H-C1 / H-C2 hükümleri tutmuş olmalı; H-C5 tutmadıysa adım 3 "aynı bağlam" seçeneğini de içerir.
**Dokunur.** `karadul/ghidra/headless.py` (aşağıdaki işlevler), `tests/test_ol10d_kopru.py` (yeni), `scripts/measurement/mutation_specs_ol10d.json` (yeni), `docs/…/olcek/{on_kayit_OL10D,OL10D}.md`.
**Dokunmaz.** `.c` dosya biçimi (`_decompile_single_function`, `:1543-1744`); `_plan_decompile_filenames` (`:1467-1483`); `_extract_xrefs` (`:1874-1971`; tembel kipte çağrılmaz, tam kipte aynen); `karadul/analyzers/macho.py` (OL10-E); `karadul/config.py`.

**Adımlar.**
1. `analyze(…, yalniz_k1: bool = False)` (`:264-327`) ve `_analyze_pyghidra` (`:329-744`): `yalniz_k1` iken decompile (`:474-508`), tip (`:510-525`), xref (`:527-542`), P-code (`:544-576`), CFG (`:578-593`) ve BSim (`:612-677`) blokları atlanır; fonksiyon listesi, dizgi, çağrı grafiği, FunctionID (`:595-610`) ve birleşik özet (`:679-711`) koşar. Sonuç sözlüğüne `katman: "k1"`; BSim için `scripts_output["bsim"] = {"bsim_status": "ertelendi", "bsim_detail": {"neden": "büyük ikili kipi"}}` ve aynı şemada `bsim_matches.json`. CLI yolu (`_analyze_cli`, `:2620`) `yalniz_k1`'i desteklemez: açık hata döner.
2. `_judge_outcome` (`:833-861`) değişmez; K1 için ayrı hüküm işlevi: ölümcül hata yok ve fonksiyon listesi dolu → başarılı.
3. Yeni `decompile_secili(binary_path, project_dir, project_name, adresler, output_dir, *, timeout=None, butce_sn=0, atla=frozenset(), parti_gunlugu=None) → dict`: proje `analyze=False` ile açılır; `_run_auto_analysis`'in yaptığı denetimle program "çözümlenmiş" değilse hata (çözümlenmemiş projede decompile yok); `adresler` öncelik sırasındadır; `atla` (önceden bitmişler) decompile edilmez.
4. Decompile yoluna (`_decompile_functions` `:1243-1296`, `_parallel_decompile_java_threads` `:1299-1435`, `_serial_decompile_fallback` `:1747-1808`; HZ-3'ten sonraki hâlleri) `yalniz: Sequence[str] | None`: dosya adı planı BÜTÜN fonksiyonlardan (`:1335-1337`'nin bugünkü davranışı korunur); iş kuyruğu `yalniz` sırasıyla; sonuç listesi adres sırasında; `butce_sn` dolunca kalanlar `deferred: True` kaydı alır (yeni `_deferred_entry`; `_lost_entry` `:1486-1494` değişmez; `skipped` yazılmaz).
5. `_finalize_decompile_result` (`:1497-1540`): `deferred` sayacı; `losses` alanları değişmez. `yalniz=None` iken çıktı bugünküyle bayt eşit (yeni alan yalnız `yalniz` verildiğinde yazılır).
6. `_extract_cfg(program, yalniz=None)` (`:2182`; HZ-4a'dan sonraki hâli): verilirse yalnız o fonksiyonlar. `decompile_secili` tip dökümünü (`_extract_types`, `:1811`) çağrı başına bir kez yapar.
7. Parti günlüğü: her parti bitince `parti_gunlugu` dosyasına tek satır (adresler, başarı / hata sayısı), `flush` + `fsync`.
8. Testler (sahte program / sahte JVM; kalıp `tests/test_hz1_olcum_kancasi.py`, `tests/test_p16c_analiz_suresi.py`; ≥ 16) ve mutasyon.

**Kabul ölçütü.** İlk satır: "T25: `yalniz_k1` + `decompile_secili` (S = kural sürümü 1, B1–B4): … `.c`, K1 … sn, K2 köprü … sn." S8 (kuyrukla): ön kaydın H-D1 … H-D4'ü. Tam takım 0 hata.

**Ön kayıt (`on_kayit_OL10D.md`).**
> H-D1 (kip kapalı değişmez): `yalniz_k1=False`, `yalniz=None` iken S8'in 8 ikilisinde `ghidra_output/*.json` JSON-eşit, `.c` bayt eşit (taban: bu paketten hemen önceki main).
> H-D2 (K1 çıktıları): `yalniz_k1=True` iken `functions.json`, `strings.json`, `call_graph.json`, `function_id.json` tam kiptekiyle JSON-eşit (8 / 8).
> H-D3 (hepsi seçili): `decompile_secili(bütün fonksiyonlar)` → `.c` bayt eşit; `decompiled.json` JSON-eşit (alan dışı: `duration_seconds`, `decompiled_dir`, parti alanları, `deferred`); `pcode.jsonl` bayt eşit; `cfg.json` JSON-eşit (8 / 8).
> H-D4 (alt küme): her ikinci fonksiyon seçildiğinde S'nin `.c`'leri eşit; `deferred` = toplam − |S|; `cfg.json` yalnız S'yi taşır ve S kayıtları JSON-eşit (8 / 8).
> H-D5 (bütçe): `butce_sn = 2` ile debian sqlite3'te decompile ≤ 2 + 35 sn'de durur (fonksiyon başına sınır 30 sn: `karadul/config.py:630`); kalanlar `deferred`, `skipped` 0; ikinci çağrı (`atla` = bitenler) kaldığı yerden sürer ve iki çağrının birleşimi tek çağrıyla aynı `.c` kümesini verir.
> H-D6 (T25, gerçek uygulama): `.c` sayısı = |S| − başarısız; K1 süresi OL10-C'nin T25 ölçümünün ± %20'si (aynı yük koşulunda).

**Mutasyon (≥ 12).** K1'de decompile yine koşar; K1'de BSim koşar; dosya adı planı yalnız S'den; `deferred` → `skipped`; bütçe aşımında döngü sürer; sonuç sırası istek sırası olur; "çözümlenmiş" denetimi kalkar; `atla` yok sayılır; CFG süzgeci tersine; `yalniz=None` iken `deferred` alanı yazılır; K1 hükmü boş fonksiyon listesini başarılı sayar; parti günlüğü yazılmaz; CLI yolunda `yalniz_k1` sessizce tam kip koşar.
**Bayrak.** Yok (parametre; bayrakları OL10-E okur).

### 7.5 OL10-E — statik aşama: kip kararı, K0, tembel akış, durum dosyası, proje saklama

**Amaç.** `karadul analyze`'ın tembel kipte uçtan uca statik aşaması: kip kararı → K0 özeti → K1 → seçim → K2 → birleştirme → xref türetme → durum dosyası → kısmi sonuç.

**Önkoşul.** OL10-A, OL10-D main'de. `macho.py`'de ÖL-3'ten sonra.
**Dokunur.** `karadul/core/tembel_durum.py` (yeni), `karadul/core/tembel_k2.py` (yeni), `karadul/analyzers/macho.py` (`_run_ghidra_legacy` `:1254-1307`: tembel dal ve proje saklama; `analyze_static` içinde sonucun işlenmesi `:425-470`; `_record_ghidra_outcome` `:1103-1162`), `karadul/stages.py` (yalnız `StaticAnalysisStage.execute` içindeki Go hibrit bloğu `:490-537`: `depth` / `partial` alanlarının aşama sonucuna taşınması, ≤ 10 satır; `stages.py` zincirinde PUV6a → PUV5'ten sonra), `tests/test_ol10e_statik.py` (yeni), `scripts/measurement/mutation_specs_ol10e.json` (yeni), yama `docs/arge/<dalga>/yamalar/OL10E__config.py.patch`, `docs/…/olcek/{on_kayit_OL10E,OL10E}.md`.
**Dokunmaz.** `karadul/ghidra/headless.py`, `karadul/stages.py`'nin geri kalanı (yeniden kurma aşaması OL10-F'nin), `karadul/core/pipeline.py`, `karadul/cli.py`, ad hattı (`karadul/pipeline/`, `karadul/reconstruction/`), ikili istihbarat bloğu (`macho.py:472-531`; S'nin `.c`'leriyle bugünkü gibi çalışır).

**Adımlar.**
1. `tembel_durum.py`: §4.1 şeması; atomik yazım; `oku(static_dir)` (dosya yoksa `None`); `denetle` (değişmez); sıra dosyası için akışlı JSONL okuyucu / yazıcı; `ozet()` (rapor / LM / arayüzün okuduğu küçük sözlük).
2. Kip kararı `tembel_mi(config, kod_bayti)`: `buyuk_ikili.tembel` gerçek `True` ve (`esik_mb == 0` ya da `kod_bayti ≥ esik_mb × 2²⁰`). Kod baytı `Goruntu.kod_bolumleri()` (`goruntu.py:226`) boyutlarının toplamı. Görüntü açılamazsa ya da PyGhidra yoksa: tam kip + uyarı (kip sessizce devreye girmez, sessizce de düşmez: neden `stats`'a yazılır).
3. K0 özeti `static/k0_ozet.json`: biçim, mimari, kod baytı, fonksiyon başlangıcı sayısı, giriş adresi, üst veri okuyucularının durumu ve sınıf sayımı (okuyucular: `go_pclntab.oku`, `objc.oku`; main'de olan öbürleri). İlerleme olayı ÖL-1 sözleşmesiyle (`asama=static adim=tembel.k0 durum=bitti`; ÖL-1 main'de değilse yalnız günlük satırı).
4. `tembel_k2.ilk_kosu` (`_run_ghidra_legacy`'den çağrılır: iki çağıranın ortak noktası, §1.1): `ghidra.analyze(yalniz_k1=True)` → `tembel_secim.sec` + `kes` → `tembel_durum.json` / `tembel_sira.jsonl` (`k2: "yok"`) → `ghidra.decompile_secili` → `birlestir` (`decompiled.json`, `pcode.jsonl`, `cfg.json`; kayıtlar adres sırasında; atomik) → `tembel_xref.turet` → `ghidra_output/xrefs.json` → durum güncelle. Dönüş `ghidra.analyze`'ınkiyle aynı biçimli sözlüktür (`scripts_output` dahil; ek anahtarlar `depth`, `partial_reasons`): iki çağıran da (`analyze_static` `macho.py:434-438`; Go hibrit bloğu `stages.py:501-507`) `static/ghidra_*.json` kopyalarını bugünkü koduyla yazar. (Bütün çıktının bellekte tutulması K6'dır; çaresi ÖL-3, bu paketin değil.)
5. Proje saklama: tembel kipte `ghidra_proj.cleanup()` çağrılmaz (`macho.py:1293-1307`); `result["project"] = {"path": …, "kept": True, "reason": "büyük ikili kipi: sonradan decompile için saklandı"}`.
6. Aşama sonucu (iki çağıranda da): `stats["depth"] = tembel_durum.ozet()`; ertelenen > 0 ise `stats["partial"] = True` ve `partial_reasons` (§4.3); `ghidra_status.json` `decompile` bölümüne `deferred` / `selection` (`analyze_static` yolunda; Go hibrit yolunda bu dosya bugün de yazılmıyor: ayrı kusur, ana oturuma not; tembel kipin kaynağı `tembel_durum.json` olduğu için akış ona bağlı değil). Tam kipte bu alanların hiçbiri yazılmaz.
7. Config yaması: `BuyukIkiliConfig`'e (`karadul/config.py:1200-1206`) `decompile_butcesi_sn: int = 1200` ve `secim_ust_sinir: int = 5000`; `esik_mb` yorumunun "0 = eşik yok: `tembel` açıkken her ikili tembel kipte" olarak düzeltilmesi; `INERT_SETTINGS`'ten `buyuk_ikili.tembel` ve `buyuk_ikili.esik_mb` satırlarının (`:1379-1380`) silinmesi. Tam takım yama geçici uygulanmış hâlde koşar (`tests/test_p15a_etkisiz.py`, `tests/test_bayrak_on_paketi.py` yeşil), sonra geri alınır.
8. Testler (Ghidra yok: sahte `GhidraHeadless`; ≥ 18; ikisi Go hibrit yolunu sınar: `depth` ve `partial` aşama sonucuna ulaşıyor) ve mutasyon.

**Kabul ölçütü.** İlk satır: "T25 statik aşama, tembel (öntanım sınırlar): D / 13 559 decompile edildi, E ertelendi; süre … sn (tam kip gösteride 4 712 sn, yük altında); çıkış 3." Ön kayıt satırları; tam takım 0 hata.

**Ön kayıt (`on_kayit_OL10E.md`).**
> H-E1 (kip kapalı): S8'in 8 ikilisinde `static/` içeriği bu paketten önceki main ile aynı (süre alanları hariç); `tembel_durum.json` ve `k0_ozet.json` yok.
> H-E2 (kip açık, `secim_ust_sinir: 0`, `decompile_butcesi_sn: 0`; S8, düz C: `STANDART` sınıfı yok): seçili küme bütün fonksiyonlardır; `decompiled/` dosya kümesi tam kiptekiyle aynı ve her `.c` bayt eşit; türetilen `ghidra_xrefs.json` `function_xrefs` tam kiptekiyle JSON-eşit; ertelenen 0 ve bu durumda `partial` yazılmaz (çıkış kodu tam kiptekiyle aynı). (8 / 8)
> H-E3 (değişmez): S8 + T25'te `fonksiyon_toplam = decompile_edildi + decompile_basarisiz + Σ ertelendi`; `decompiled/` `.c` sayısı = `decompile_edildi` (9 / 9).
> H-E4 (T25, öntanım sınırlar; yük altında, yalnız oran): statik aşama süresi ≤ 0,5 × aynı commit'in tam kip statik aşaması (TAHMİN: K1 379 + decompile 217 + CFG 249 + köprü dışı 912 ≈ 1 760 sn, oran 0,37; gösteride tam kip 4 712 sn).
> H-E5 (proje): `ghidra_status.json` `project.kept` doğru, dizin yerinde; boyutu raporlanır (gösteride 84 704 KiB idi).
> H-E6 (görünürlük): çıkış 3; `partial_reasons` `tembel derinlik:` ile başlar; ertelenen için dosya 0.

**Mutasyon (≥ 12).** Eşik `≥` → `>`; `esik_mb == 0` kipi kapatır; `tembel` yanlışken dal alınır; `cleanup` yine çağrılır; ertelenen > 0 iken `partial` yazılmaz; ertelenen 0 iken `partial` yazılır; değişmez denetimi atlanır; birleştirme ekleme sırasıyla (adres değil); xref türetme yalnız S için; `deferred` yerine `skipped`; PyGhidra yokken tembel dal; K0 okuyucu hatası koşuyu düşürür; sıra dosyası durum dosyasından önce yazılmaz (tutarsız çift).
**Bayrak.** `buyuk_ikili.tembel` (öntanım kapalı), `buyuk_ikili.esik_mb` (0), `buyuk_ikili.decompile_butcesi_sn` (1 200), `buyuk_ikili.secim_ust_sinir` (5 000).

### 7.6 OL10-F — yeniden kurma sözleşmesi

**Amaç.** §3'ün kurallarını ad hattına işlemek: gövde isteyen kanal gövdesiz fonksiyona ad vermez; nüfus kapıları tam nüfustan beslenir; köken kaydı iki alan kazanır. Kip kapalıyken hiçbir şey değişmez.

**Önkoşul.** OL10-A; OL10-B'nin hükümleri (hangi kanal fark üretti); `c_namer.py`'de P12d → ÖK-1 → ÖK-2'den sonra; `stages.py`'de PUV6a → PUV5'ten sonra. Tembel kip çalışma alanının kendisinden anlaşılır (`tembel_durum.oku(static_dir)` `None` değilse); ad hattı `buyuk_ikili.*` bayraklarını okumaz.
**Dokunur.** `karadul/reconstruction/c_namer.py` (yalnız `analyze_and_rename` imzası `:2139-2150` ve strateji döngüsünün fonksiyon listesi `:2245`), `karadul/pipeline/steps/_feedback_naming.py` (`_run_c_namer`, `:256`), `karadul/stages.py` (yalnız üç yer: `_recover_gnulib_from_fingerprints` `:1877-2212` içinde tembel dalı; Faz 3 adım listesi `:2701-2712`; `ReconstructionStage.execute` `:1356` başında "seçili küme boş" atlaması), `karadul/pipeline/steps/kesin_anchors.py` (kapsam koruması), `karadul/pipeline/steps/tembel_koken.py` (yeni), `karadul/pipeline/steps/__init__.py` (adım kaydı), `tests/test_ol10f_sozlesme.py` (yeni), `scripts/measurement/mutation_specs_ol10f.json` (yeni), `docs/…/olcek/{on_kayit_OL10F,OL10F}.md`.
**Dokunmaz.** `c_namer.py`'nin stratejileri ve çözümleme kuralları; `_feedback_naming_candidates.py` / `_feedback_naming_merger.py` (S-1 bugünkü davranışla sağlanıyor); `karadul/core/naming_labels.py` (etiket sözlüğü değişmez); `karadul/config.py`.

**Adımlar.**
1. Envanter (kod değişmeden; ilerleme dosyasına tablo): Faz 1–3 adımlarında (`stages.py:2500-2533`, `:2598-2602`, `:2701-2712`) `functions_data` / `ghidra_functions.json` üstünde dönen her döngü: gövde ister mi, gövdesiz fonksiyonda ne üretir. §3.2'nin iki açık hücresi (`BinaryNameExtractor`, imza veritabanının C kolu) burada kapanır.
2. `c_namer`: `analyze_and_rename(…, only_functions: frozenset[str] | None = None)`; verilirse strateji döngüsü yalnız o adlardaki fonksiyonlarda döner; dizinler (`_functions`, `_func_by_name`, `_string_refs_by_func`, çağrı grafiği) tam nüfusla kurulur. `_run_c_namer` tembel kipte gövdesi olan fonksiyonların kümesini verir.
3. gnulib: tembel kipte ad yazılmaz; aday `static/gnulib_candidates.json`'a `neden: "kısmi nüfus (büyük ikili kipi)"` ile (var olan yazıcı: `stages.py:2211`). OL10-B H-B6 "fazla + farklı = 0" verdiyse bu adım yazılmaz ve gerekçesi ilerleme dosyasına geçer (kural gereksizse eklenmez).
4. KS-1 koruması: tembel kipte `ghidra_xrefs.json` `kapsam` alanı `"tam_nufus"` değilse `kesin_anchors` bağlama üretmez (`stats`'ta neden: "xref kapsamı kısmi").
5. `tembel_koken` adımı (Faz 3'te `finalize`'dan önce; tembel kip değilse hiçbir şey yapmaz): köken kayıtlarına `govde` ve `nufus` alanlarını yazar (§3.4); gövdesiz fonksiyona ad yazmış kanalların sayımını `stats["naming_bodiless"]`'e koyar.
6. Envanterin gösterdiği, gövde isteyip tam nüfusta dönen öbür döngüler: tek satırlık süzgeçle S'ye indirilebilenler bu pakette; daha büyüğü yama + ana oturuma not. Ayrıca: tembel kipte hiç `.c` yoksa yeniden kurma aşaması hata vermez, "seçili küme boş" nedeniyle atlanmış sayılır (`ReconstructionStage.execute`, `karadul/stages.py:1356`; bugün `binary_prep` hata fırlatıyor: `binary_prep.py:67-71`). Bu, `stages.py`'de bu paketin dokunduğu üçüncü ve son yerdir.
7. Testler (sentetik çalışma alanı; ≥ 16) ve mutasyon.
8. Ölçüm: OL10-B'nin düzeneğiyle önce / sonra (aynı kümeler).

**Kabul ölçütü.** İlk satır: "Ollama dilimi (kesit, S = B1–B4): gövdesiz fonksiyona `c_namer` adı önce x → sonra 0; üst veri kaynaklı ad (bayraklar açık) tam kolda N, tembel kolda N; reconstruct tembel / tam = r." Ön kayıt satırları; tam takım 0 hata.

**Ön kayıt (`on_kayit_OL10F.md`).**
> H-F1 (kip kapalı): 119'un yeniden oynatmasında (tam kol, bu paketten önce ↔ sonra) `naming_map.json` ve `naming_provenance.json` 119 / 119 bayt eşit.
> H-F2 (gövdesiz ad): tembel kolda S dışındaki fonksiyona ad yazan kanallar yalnız §3.2'de "gövdesiz ad: evet" olanlardır; `c_namer` kaynaklı gövdesiz ad 0 (119 + gösteri).
> H-F3 (yanlış ad üretmeme; 119, %50 kesim): S'deki anahtarlarda fazla + farklı ad 0. Sıfır değilse her biri kanalı ve kuralıyla listelenir; GT'ye göre yanlış olanı ayrıca.
> H-F4 (üst veri adı eksilmez; gösteri, üst veri bayrakları açık): `go_pclntab` ve `objc_method` kaynaklı ad sayısı tembel kolda tam koldakiyle aynı (fark 0).
> H-F5 (KS-1): x-kısmi girdide `kesin_anchors` bağlama üretmez; x-tam girdide `ks1:*` adları S'de tam koldakiyle aynı.
> H-F6 (süre oranı; yük altında): gösteride reconstruct tembel / tam, OL10-B H-B7'de ölçülen orandan büyük değildir (strateji döngüsü küçüldü).

**Mutasyon (≥ 10).** `only_functions` yok sayılır; dizinler de S'ye iner (çakışma denetimi zayıflar); gnulib tembel kipte ad yazar; KS-1 koruması `kapsam` alanına bakmaz; `govde` alanı ters yazılır; `nufus` alanı tam kipte de yazılır; `tembel_koken` kip kapalıyken dosyaya dokunur; gövdesiz sayım kanalı yanlış alandan; adım Faz 3'te `finalize`'dan sonra koşar; tembel kip bayraktan okunur (çalışma alanından değil).
**Bayrak.** Yok (davranış çalışma alanının durumuna bağlı).

### 7.7 OL10-G — görünürlük 1: rapor, CLI satırı, `--derinlik`

**Amaç.** §4.3: "decompile edilmedi" sayacının raporda ve komut satırında görünmesi; var olan sayaçların tembel kipte yanlış okunmaması.

**Önkoşul.** OL10-E main'de. `karadul/cli.py`'de ÖL-4'ten sonra.
**Dokunur.** `karadul/reporting/report_data.py` (fonksiyon sayacı `:734` ve yeni "Derinlik" bölümü), `karadul/reporting/{json_report,markdown_report,html_report,sections_render}.py` (fonksiyon sayacını okuyan yerler: `json_report.py:149`, `markdown_report.py:215`, `html_report.py:307`, `sections_render.py:60-65`), `karadul/cli.py` (`analyze` komutu `:634-703`: `--derinlik` seçeneği ve koşu sonu özet satırı), `tests/test_ol10g_rapor.py` (yeni), `scripts/measurement/mutation_specs_ol10g.json` (yeni).
**Dokunmaz.** `karadul/core/pipeline.py` (`analysis_outcome` değişmez), `ui/`, `karadul/lm/`.

**Adımlar.**
1. Tek okuma yolu: rapor `stats["depth"]`'i (`tembel_durum.ozet()`) okur; kendi sayımını yapmaz.
2. "Derinlik" bölümü: katman durumu, dört gözlü tablo (ad × gövde), kanal kırılımı (`stats["naming_bodiless"]`), `KENDI` satırı, kural sürümü ve sınırlar, sürdürme komutu. Tembel kip değilse bölüm yok.
3. Var olan "fonksiyon" sayaçları: tembel kipte "fonksiyon P, decompile edilen D" olarak iki ayrı sayı; tek sayı gösterilen yerde D "decompile edilen" etiketiyle.
4. CLI: koşu sonu özet satırı (§4.3); `--quiet` / `--json` kipinde yok (JSON çıktısında `depth` nesnesi var).
5. `analyze --derinlik {tam,tembel}`: ayarın üstüne yazar (`tembel`: `buyuk_ikili.tembel = True`, `esik_mb = 0`; `tam`: `tembel = False`).
6. Sahte başarı testleri: §4.3 (a)–(d), sentetik tembel çalışma alanıyla.
7. Mutasyon.

**Kabul ölçütü.** İlk satır: "T25 tembel çalışma alanının raporu: dört gözün toplamı = fonksiyon toplamı (13 559; 399'u taslak, ayrı satırda); 'decompile edilen' = `.c` sayısı." Kip kapalı: S8'in 8 çalışma alanında üretilen raporlar bu paketten önceki raporlarla bayt eşit (zaman damgası alanları hariç).

**Ön kayıt.** Gerekmez (gösterim; ölçüt testte ve yukarıdaki iki denetimde).
**Mutasyon (≥ 8).** Dört göz toplamı yerine yalnız gövdeli sayılır; ertelenen `skipped` alanından okunur; özet satırı ertelenen 0 iken de basılır; `--derinlik tam` tembeli kapatmaz; bölüm kip kapalıyken de yazılır; "decompile edilen" P'den okunur; `KENDI` satırı toplamdan; `--quiet`'te satır basılır.
**Bayrak.** Yok (seçenek).

### 7.8 OL10-H — görünürlük 2: arayüz ve KaradulLM

**Amaç.** §4.4 ve §4.5: gövdesiz fonksiyonun arayüzde ve KaradulLM araçlarında "decompile edilmedi" olarak, adıyla ve kanıtıyla görünmesi.

**Önkoşul.** OL10-E main'de; `ui/server.py`'de ÖL-4 (ve varsa ÖL-8) sonrası; KaradulLM arayüz paketleriyle (P22c / P22h) sıralı.
**Dokunur.** `karadul/lm/tools/__init__.py` (hata kodları `:95-105`; `Workspace` `:225`, `read_code` `:376-384`), `karadul/lm/tools/read.py` (`_stripped_code` `:71-75`, `get_evidence` `:82`, `get_decompiled` `:136`, `get_xrefs` `:193`), `ui/server.py` (`build_model` `:351` yalnız sayaçlar; yeni sayfalı uç), `ui/index.html` (ertelenenler listesi, gövdesiz düğüm görünümü), `tests/test_ol10h_gorunum.py` (yeni), `scripts/measurement/mutation_specs_ol10h.json` (yeni).
**Dokunmaz.** KaradulLM'in izin modeli ve kayıt defteri kuralları (süreç başlatan araç eklenmez); `karadul/lm/agent.py`; rapor.

**Adımlar.**
1. `Workspace.depth` (yoksa `None`) ve `Workspace.govde(hexaddr)`; kaynak `tembel_durum` / `tembel_sira.jsonl`.
2. `ERR_NOT_DECOMPILED = "decompile_edilmedi"`; `get_decompiled` gövdesiz adreste bu kodu ve durum alanlarını döndürür; gövdeli adreste değişmez; kip kapalıyken `veri_yok` davranışı aynen.
3. `get_evidence` / `get_xrefs`: `govde` alanı ve sınırlama notu; gövdesiz fonksiyonda `lines` alanı `null` (0 değil).
4. Oturum açılış satırı (D / P); dosya yoksa satır yok.
5. `request_decompile` ("Ö" sınıfı; yalnız P22e'nin öneri altyapısı main'deyse kayıt defterine girer; değilse araç `arac_kapali`).
6. Sunucu: sayaç şeridinin verisi; `/api/ertelenenler?baslangic=&adet=&ara=&sinif=` (sayfalı; kaynak sıra dosyası; toplam gerçek sayıdan).
7. Arayüz: ertelenenler listesi; gövdesiz düğüm paneli (durum, sınıf, basamak, sıra, kanıt, çağıran / çağrılan sayısı); "Decompile et" düğmesi yalnız OL10-I'nin iş ucu varsa görünür. Yer tutucu kod ve canlandırma yok.
8. Testler (≥ 14) ve mutasyon.

**Kabul ölçütü.** İlk satır: "T25 tembel çalışma alanı: `/api/ertelenenler` toplamı = `ertelendi` (… = …); ilk sayfa … ms; `get_decompiled` gövdesiz adreste `decompile_edilmedi`." Kip kapalı: S8 çalışma alanlarında LM araç çıktıları ve `/api/model` yanıtı bu paketten öncekiyle bayt eşit.

**Ön kayıt.** Gerekmez (gösterim). Ölçülen tek sayı: T25'te ertelenenler ucunun ilk sayfası ≤ 2 sn (kaba sınır).
**Mutasyon (≥ 10).** Gövdesiz adreste `veri_yok` döner; gövdeli adreste yeni kod döner; `lines` 0 yazılır; açılış satırı dosya yokken yazılır; sayfalama toplamı sayfa boyundan; `sinif` süzgeci yok sayılır; `request_decompile` süreç başlatır (yasak yolun testi); düğme iş ucu yokken görünür; `govde` alanı ters; sayaç `skipped`'tan.
**Bayrak.** Yok.

### 7.9 OL10-I — isteğe bağlı decompile ve sürdürme

**Amaç.** §5: `karadul decompile` komutu; ek dilim, kaldığı yerden sürdürme, ad hattının yeniden koşması; arayüzün iş ucu.

**Önkoşul.** OL10-E, OL10-F main'de; `karadul/cli.py`'de OL10-G'den sonra; `ui/server.py`'de OL10-H'den sonra.
**Dokunur.** `karadul/core/tembel_k2.py` (`ek_dilim`, `devam`, tutarlılık denetimi, "hemen" ad basma), `karadul/cli.py` (yeni `decompile` komutu), `ui/server.py` (yalnız yeni iş ucu ve kilit), `tests/test_ol10i_istek.py` (yeni), `scripts/measurement/mutation_specs_ol10i.json` (yeni), `docs/…/olcek/{on_kayit_OL10I,OL10I}.md`.
**Dokunmaz.** `karadul/ghidra/headless.py`, `karadul/analyzers/macho.py`, ad hattının kuralları, KaradulLM araçları.

**Adımlar.**
1. Tutarlılık denetimi (§5.2): durum dosyası, proje, dilim sha256'sı, Ghidra sürümü; tutmazsa çıkış 2 ve açık ileti.
2. `ek_dilim(ws, adresler=None, sonraki=None, komsu=None)`: istekler B0 olarak sıra dosyasına işlenir (ad → adres çözümü `ghidra_functions.json` ve ad haritasından; bilinmeyen ad hata); `decompile_secili`; `birlestir`; durum ve `dilimler`.
3. "Hemen" yol: yeni `.c`'ye var olan ad haritası basılır ve `reconstructed/` altındaki son dizine eklenir; `ad_hatti: "bekliyor"`.
4. `--adlandir`: yeniden kurma aşaması var olan çalışma alanında S üstünde baştan (çalışma alanını yeniden kullanma: `Workspace(workspace_dir=…)`, `karadul/core/workspace.py:47-61`); önceki `reconstructed/` atomik olarak değiştirilir (yeni dizine kur, sonra yer değiştir); elle adlar korunur.
5. `--devam`: parti günlüğünden bitmişleri oku, kalanları aynı sırayla sürdür.
6. CLI: çıkış 0 (bu çağrıda istenen fonksiyonların hepsi decompile edildi), 3 (istenenlerden başarısız ya da bütçeye sığmayan var), 2 (tutarsız çalışma alanı / bilinmeyen adres). Çalışma alanında ertelenen kalması bu komutun hatası değildir; özet satırı her çağrıda kalan sayıyı yazar (`analyze`'ın çıkış kodu anlamı değişmez: §4.3).
7. Sunucu iş ucu (`POST /api/decompile`): aynı çalışma alanında aynı anda tek iş (kilit dosyası); ilerleme var olan iş günlüğünden.
8. Testler (sahte köprü; ≥ 18) ve mutasyon.

**Kabul ölçütü.** İlk satır: "T25: tek fonksiyon isteği … sn; S₀ (B1–B2) + `--sonraki` ≡ baştan B1–B4 (fark 0 dosya); kesip sürdürmede yeniden decompile edilen 0." Ön kayıt satırları; tam takım 0 hata.

**Ön kayıt (`on_kayit_OL10I.md`).**
> H-I1 (yol bağımsızlığı; T25, `decompile_butcesi_sn: 0`): S₀ = B1–B2 ile koşup `--sonraki` ile B3–B4'ü eklemek ↔ baştan B1–B4 ile koşmak: `static/ghidra_output/decompiled/` aynı dosya kümesi ve bayt eşit içerik; `decompiled.json`, `cfg.json`, `pcode.jsonl`, `ghidra_xrefs.json` JSON-eşit (süre alanları ve `dilimler` hariç); `--adlandir` sonrası `naming_map.json` bayt eşit.
> H-I2 (kesip sürdürme; T25): K2 decompile sırasında SIGTERM, sonra `--devam`: sonuç kesintisiz koşuyla H-I1'deki anlamda aynı; günlükte bitmiş görünen fonksiyonlardan yeniden decompile edilen 0.
> H-I3 (tek fonksiyon gecikmesi; yük altında, kaba sınır): T25'te komutun başından `.c`'nin yazılmasına ≤ 120 sn. (Dayanak: OL10-C H-C5; orada ölçülen yeniden açılış süresi + JVM açılışı.)
> H-I4 (tutarlılık): dilim dosyası değiştirilmiş çalışma alanında komut çıkış 2 verir ve Ghidra başlamaz (≤ 5 sn).
> H-I5 (T100; gece, OL10-J ile birlikte): tek fonksiyon isteği ≤ 600 sn (dayanak: H-C5'in T100 eşiği 300 sn + JVM + decompile).

**Mutasyon (≥ 12).** Tutarlılık denetimi sha256'ya bakmaz; proje yokken sessizce K1 koşar; birleştirme ekleme sırasıyla; bitmiş fonksiyon yeniden decompile edilir; `--devam` günlüğü yok sayar; "hemen" yol ad üretir; `--adlandir` yalnız yeni fonksiyonları adlandırır; elle ad kaybolur; istenenlerden biri başarısızken çıkış kodu 0; kilit alınmadan ikinci iş başlar; bilinmeyen ad sessizce atlanır; B0 istekleri sıra dosyasına işlenmez.
**Bayrak.** Yok (yeni komut).

### 7.10 OL10-J — uçtan uca kabul ölçümü

**Amaç.** §6.2'nin ön kaydını ölçmek; "şu boyuta kadar denendi" cümlesini (ÖLÇ-2'nin şablonu) tembel kip için doldurmak; öntanım eşik önerisini (K-8) vermek.

**Dokunur.** `docs/…/olcek/{on_kayit_OL10J,OL10J}.md`; koşu kökleri depo dışında. Ürün kodu değişmez.
**Adımlar.** 1. Ürün ağacını sabitle (ORTAK_D0 §3). 2. Ön kaydı commit'le. 3. Gündüz kolları (kuyruk, iki yuva): S8, terminal-notifier, T25 ad / eşitlik, docker-cli. 4. Gece kolları (`--tek`, boş makine): T25 süre çifti, T100, sınama ikilileri, (ÖL-5a varsa) PAKET. 5. 119 kapalı kip koşusu + `urun_olc karsilastir`. 6. Her hüküm için tuttu / tutmadı; ölçülemeyen "ölçülmedi" (0 değil). 7. Öntanım eşik önerisi: tam kipin uçtan uca süresi ile tembel kipin süresinin kesiştiği kod boyutu, ölçülen iki noktadan (T25 ve bir küçük ikili) kaba olarak; "TAHMİN" etiketiyle.
**Kabul ölçütü.** İlk satır: "T100 (94,9 MB): K0 … sn, K1 … sn, K2 … sn; D / 163 141 decompile edildi; tepe RSS … GB; disk … GB." Ön kaydın her satırı hükme bağlanmış.
**Mutasyon.** Yok (ölçüm; kod yok).

## 8. Riskler ve açık sorular

### 8.1 Ölçmeden bilinemeyenler

| No | Soru | Bugün bildiğimiz | Kim ölçer |
|---|---|---|---|
| R-1 | **K1, 100 MB'lık ikilide ne kadar sürer?** | TAHMİN [38; 72] dk, kötümser 6,1 sa; 119'un modeli gösteride ilk adımı 4,4 kat az öngörmüştü (`olcek/BULGULAR.md` §3.3) | OL10-C (T100, gece); ÖLÇ-1 Ö6 / Ö7 aynı sayıyı verir |
| R-2 | Kayıtlı projeyi yeniden açmak ne kadar sürer? | hiç ölçülmedi | OL10-C H-C5 |
| R-3 | Büyük ikilide decompile hızı (fonksiyon / sn) | gösteri 0,0386; T100 modeli 0,099–0,359 sn / fn (9 kat aralık) | OL10-C H-C6; ÖLÇ-1 Ö8 |
| R-4 | Kısmi nüfusta ad hattı kaç adı değiştirir / kaybeder? | kod okuması: çözümleme nüfusa bağlı (§3.3); sayı yok | OL10-B |
| R-5 | Tembel kipte reconstruct süresi S ile nasıl ölçeklenir? | gösteride tam kip 2 353 sn (yük altında; tek tur 1 311 sn sürdüğü için kalan iki tur atlandı: `karsi/KARSI.md` İ-1) | OL10-B H-B7 |
| R-6 | K1 belleği (Python + JVM) 300 MB üstünde sığar mı? | TAHMİN 4,4–7,7 GB Python + 14,7 GB JVM; ÖL-3'e bağlı | ÖLÇ-1 Ö9; OL10-J H-J2 |
| R-7 | xref türetmesi C / C++ ikililerinde alan düzeyinde eşit mi? | Go ağırlıklı tek ikilide küme düzeyinde 13 559 / 13 559 | OL10-A H-A3 |
| R-8 | Seçim kuralı sınama ikililerinde programın kendi kodunu öne alıyor mu? | yalnız Ollama'da bakıldı (17 / 17 ad B3–B4'te) | OL10-A H-A6; OL10-J H-J9 |
| R-9 | İkili istihbarat aşaması tembel kipte ne kadar sürer? | gösteride 887 sn; dizgi kolu ile `.c` kolunun payı bilinmiyor | ÖL-3b profili; OL10-E H-E4 |
| R-10 | Hedef setindeki Go / Swift ikililerinde K1 biter mi? | bugünkü ürünle tahmini toplam süre 164–11 219 dk; K1 payı bilinmiyor | OL10-C (docker-cli); OL10-J H-J9 |

### 8.2 Gece koşusunun (ÖLÇ-1 + HZ-0; A-26 ile ertelendi) cevaplayacakları

Gece 2'nin T100 / T300 kolu (duvar 7 200 sn; `olcek/on_kayit_olc1.md`) ürün kodu değişmeden şu sayıları verir:
- **R-1:** Ö6 (ilk adım süresi) ve Ö7 (`call_graph.json` yazıldı mı) → T100 K1'in gerçek süresi. Tasarımın en büyük bilinmeyeni budur.
- **R-3:** Ö8 (duvar anında yazılmış `.c` sayısı) → büyük ikilide decompile hızı (K1 bittikten sonra kalan süreye bölünür).
- **R-6:** Ö9 (tepe RSS), T300'de otomatik analiz sırasındaki bellek.
- T300 ilk adımı 7 200 sn'de biter mi (ön kayıt Ö'leri): 300 MB üstü için K1'in mertebesi.

Cevaplamadıkları: R-2 (proje yeniden açma), R-4, R-5, R-7 (hepsi OL10-A / B / C). Bu yüzden OL10-C'nin T100 kolu aynı geceye eklenmelidir (K-11); gece koşusu yapılmadan da OL10-A, OL10-B ve OL10-C'nin gündüz kolları (S8 eşitliği, T25, docker-cli) yürür.

Gece koşusu olmadan kesinleşmeyecek sayılar (belgede TAHMİN olarak duranlar): T100 K1 [2 282; 4 327] sn; T100 decompile hızı [0,0386; 0,359] sn / fn; T100 toplam [60; 110] dk; T300 K1 [1,8; 5,0] sa; T100 proje boyutu [0,3; 0,9] GB; T25 tembel toplam [2 642; 2 937] sn (B1–B4 kesimi; yük altındaki gösteri sayılarından; boş makine değeri yok); öntanım eşik adayı 16 MiB.

### 8.3 Riskler

1. **K1 60 dakikayı aşarsa "makul sürede ilk sonuç" yalnız K0 özetidir.** K0 gerçek ama sığ (C++ ikilisinde: dizgiler, içe aktarımlar, fonksiyon sayısı; üst veri adı yok). Karşı önlem bu planda yok; aday: bölgesel çözümleme (K-10). Bedeli: çağıran listeleri ve çağrı grafiği eksilir, tam kiple eşitlik bozulur; ayrı ön kayıt ve ölçüm ister.
2. **Otomatik analiz yarıda kesilirse (bütçe) K1 kısmi programla sürer** (`headless.py:395-403`): fonksiyon listesi eksik, seçim eksik liste üstünden yapılır. `tembel_durum.json` `katman.k1 = "kismi"` yazar; rapor bunu ilk satırda söyler. Yarıda kesilmiş analizi sürdürme bu tasarımda yok (§5.6).
3. **Ad eşitliği tutmayabilir** (§3.3). Tasarım "yeni yanlış ad 0"ı hedefler; OL10-B bunun bile tutmadığını gösterirse farkı üreten kural tembel kipte kanıt satırına iner. En kötü durumda tembel kipte `c_namer` adları bütünüyle "kanıt satırı" olur ve adlar yalnız üst veri + ön ad kanallarından gelir; bu, kanalın bağımsız nüfustaki %79,8 kesinliğiyle (A-29) zaten gündemde olan karardır.
4. **Sınıflandırma yanılırsa programın kendi kodu ertelenir.** Örnek: ana modülü `buildinfo`'dan okunamayan Go ikilisi (programın `main` dışındaki paketleri `ucuncu_taraf` görünür). Koruma kuralın içinde (§2.3: ana modül bulunamazsa `BAGIMLILIK` B2'ye alınır; OL10-A testi). Kalan risk: `STANDART` sınıfına yanlış düşen kod (ör. adı standart kitaplık paketine benzetilmiş kod) kendiliğinden hiç seçilmez; yalnız istekle açılır. Üst verisi kurcalanmış ikilide bu bir saklanma yoludur; P-ÜV7'nin tutarlılık damgası gelene kadar açık kalır (madde 5).
5. **Üst veri adına güven.** Seçilmeyen fonksiyonun adı yalnız üst veriden gelir; bozulmuş / sahte üst veri (P-ÜV7 tutarlılık denetimi main'de değil) yanlış adı gövdesiz, yani analistin gözle denetleyemeyeceği biçimde gösterir. Koruma: gövdesiz + `üst veriden` adlar arayüzde ayrı işaretlenir; `kisa` / `tasan` kayıtlar zaten ad olmuyor (PUV6a hüküm 1); P-ÜV7 gelince `tutarsiz` damgalı fonksiyon B3'e yükseltilir (gövdesi öncelikle decompile edilir). Bu son kural sürüm 2'dir, bu planda yazılmaz.
6. **Disk.** Proje saklanır ([0,3; 0,9] GB T100, TAHMİN); T300'de [2,1; 3,5] GB (aynı oranlarla: dilimin 3,3 katı, kodun 15,7 katı). Çalışma alanı silinince proje de silinir; ayrı temizlik komutu yok. ÖL-6'nın disk ön denetimi tembel kipte proje + K1 JSON'ları + S'nin çıktısını hesaba katmalı (ÖL-6'ya not).
7. **İki "kısmi".** Çıkış 3 hem hatayı hem ertelemeyi taşır (K-3). Ölçüm araçları `depth` alanına bakmadan çıkış koduyla karar verirse tembel koşuları "bozuk" sayabilir. `urun_kos.py` / `masum_kapi.py` gibi araçlara tembel kol eklenirken bu ayrım testle kilitlenmeli (OL10-J adım 3'ün önkoşulu).
8. **`headless.py` zincirinin uzunluğu.** OL10-D altı paketin arkasında; zincir gecikirse ürün tarafı gecikir. Bu yüzden ölçmeden bilinemeyenler zincirden bağımsız üç pakete (A, B, C) alındı; zincir bittiğinde OL10-D'nin ön kayıt sayıları hazır olur.

### 8.4 Bu tasarımın bilerek yapmadıkları

- Otomatik analizin ortasından sürdürme; bölgesel çözümleme; çözümleyici profilini büyük ikili için değiştirme (çıktıyı değiştirir: P16c).
- Artımlı ad hattı (yalnız yeni fonksiyonu adlandırma).
- Seçimde kimlik eşlemesi (gömülü açık kaynak kitaplığı `BAGIMLILIK`'a indirmek): KİMLİK PK-4 / ÖL-11 gelince kural sürümü 2.
- Tam kipte xref adımının türetmeyle değiştirilmesi (HIZ'ın kararı).
- `.app` paket yönetimi (ÖL-5a / ÖL-5b).

## Ek A — atıf doğrulama

- Yöntem: belgedeki her dosya:satır atfı için "o satırda (ya da verilen aralığın içinde) beklenen metin var mı" denetimi; ayrıca "var" denen dosyalar var mı, "yeni" denen dosyalar bugün yok mu. Komut metni: `~/karadul_olcum/runs/dalga1-2026-11-23/OL10/atif_denetimi_komutu.txt` (depo dışı; worktree kökünden `/opt/anaconda3/bin/python - < <dosya>`).
- Sonuç (main `f2b0db5`, 2026-11-23 08:53): satır atfı 181 denetimin 177'si birebir satırda tuttu; kalan 4'ü belgede verilen ARALIĞIN içinde (çapa metni aralığın başka satırında: `stages.py:1976`, `stages.py:2277`, `c_namer.py:2836`, `pipeline.py:80`); belge bu dördünde aralıkla yazılıdır. Var olması gereken 18 dosyanın 18'i var; "yeni" denen 9 dosyanın 9'u bugün yok.
- Depo dışı tek kod atfı: kurulu pyghidra 3.0.0, `/opt/anaconda3/lib/python3.12/site-packages/pyghidra/core.py` `:121-127` (`openProject` / `openProgram`) ve `:262-264` (`project.save(program)`, `project.close()`); `sed -n` ile okundu.
- Denetlenmeyen atıf türü: başka belgelere "§" ile yapılan atıflar (ör. `olcek/BULGULAR.md` §3.4) satır numarasıyla değil bölüm adıyla verildi; sayıların kendisi bu turda o belgelerden okunarak yazıldı.
- Satır numaraları P16e ve PUV6a main'e girince kayar (§0). Kaymayacak olan çapalar (işlev adları):

| Dosya | Çapalar (işlev / sabit) |
|---|---|
| `karadul/ghidra/headless.py` | `analyze`, `_analyze_pyghidra`, `_run_auto_analysis`, `_judge_outcome`, `_extract_functions`, `_extract_strings`, `_extract_call_graph`, `_extract_func_xrefs`, `_decompile_functions`, `_parallel_decompile_java_threads`, `_plan_decompile_filenames`, `_lost_entry`, `_finalize_decompile_result`, `_decompile_single_function`, `_serial_decompile_fallback`, `_extract_types`, `_extract_xrefs`, `_write_pcode_jsonl`, `_extract_cfg`, `_extract_function_id_matches`, `_analyze_cli`, `ADIM_*` |
| `karadul/analyzers/macho.py` | `analyze_static`, `_record_ghidra_outcome`, `_run_ghidra_legacy` |
| `karadul/stages.py` | `_recover_main_from_entry`, `_recover_gnulib_from_fingerprints`, `_recover_elf_boilerplate`, `_apply_manual_overrides`, `_execute_binary` (üç `PipelineRunner(steps=[…])` listesi) |
| `karadul/reconstruction/c_namer.py` | `analyze_and_rename`, `_load_strings_full`, `_strategy_*`, `_propagate_passthrough_params` |
| `karadul/pipeline/steps/` | `collect_candidates`, `GhidraFunctionIndex`, `load_ghidra_index`, `add_k4_channels`, `_add_*`, `run_name_merger`, `_apply_aho_replace`, `force_manual_names`, `_run_c_namer`, `BinaryPrepStep.run`, `GhidraMetadataStep._resolve_json_paths` |
| `karadul/config.py` | `BuyukIkiliConfig` (`tembel`, `esik_mb`), `INERT_SETTINGS`, `Timeouts.ghidra` |
| `karadul/lm/tools/` | `TOOL_CLASS_ACTIONS`, `ERR_NO_DATA`, `Workspace.read_code`, `get_decompiled`, `get_evidence`, `get_xrefs` |

## Ek B — bu turda koşulan komutlar ve çıktıları

Hepsi salt okur; Ghidra yok; ürün kodu ve taban kökleri değişmedi. Komut metinleri depo dışında (`~/karadul_olcum/runs/dalga1-2026-11-23/OL10/`); worktree kökünden `PYTHONDONTWRITEBYTECODE=1 /opt/anaconda3/bin/python - < <komut dosyası>` ile yeniden üretilir. Bunlar ölçüm aracı değildir; ürün aracı OL10-A'nın `tembel_kuru.py`'sidir.

**B-1. Kuru seçim, Ollama dilimi** (`kuru_secim_v1_komutu.txt`; girdi: gösteri çalışma alanının `static/ghidra_{functions,strings,call_graph}.json`'ı ve `raw/Ollama_arm64`; okuyucular bu worktree'nin `karadul/analyzers/ustveri/`'si). Çıktı (2026-11-23 08:3x):

```
sinif {'BAGIMLILIK': 594, 'BILINMIYOR': 2619, 'KENDI': 1406, 'STANDART': 8541} taslak 399
giris kumesi [('FUN_10038e740', 'main.main', 'KENDI')]
B1 giris                                   36 fn     24444 B | kumulatif     36 fn (0.3%)     24444 B (0.5%)
B2 kendi                                 1373 fn    624256 B | kumulatif   1409 fn (10.7%)    648700 B (12.0%)
B3 bilinmiyor+kanit                      1236 fn    938516 B | kumulatif   2645 fn (20.1%)   1587216 B (29.3%)
B4a bilinmiyor, secilenin cagirdigi       547 fn    227380 B | kumulatif   3192 fn (24.3%)   1814596 B (33.5%)
B4b bilinmiyor, kalan                     836 fn    132589 B | kumulatif   4028 fn (30.6%)   1947185 B (36.0%)
B5 bagimlilik                             591 fn    298060 B | kumulatif   4619 fn (35.1%)   2245245 B (41.5%)
otomatik secilmeyen (STANDART) 8541 fn 3168916 B; program 13160 fn 5414161 B
B1 sinif dagilimi {'KENDI': 33, 'BAGIMLILIK': 3}
secim sirasi sha256 16fd504d3548fb68
gosterinin ad verdigi 17 fonksiyonun basamagi {'B4a': 5, 'B3': 10, 'B4b': 2} | en gec konum 3831
```

Notlar: (1) kuru sayım giriş adresini yalnız program fonksiyonları arasında aradı; adresteki `entry` taslağı (`100081fb0`, 4 B, `is_thunk`) ayrı bir sorguyla bulundu, tabloya girmedi. (2) İlk keşif sayımı (`kuru_secim_komutu.txt`): okuyucunun Go sınıf sayımı `kendi` 1 257, `ucuncu_taraf` 594, `standart` 6 657, `calisma_zamani` 1 580, `derleyici` 435, `paketsiz` 77, `adsiz` 1 (toplam 10 601); Ghidra program fonksiyonlarına eşlenen: `kendi` 1 256, ObjC 150; üst veri okuma 0,46 sn (yük 2,8); en az bir dizgiye başvuran program fonksiyonu 1 040; en az bir içe aktarım çağıran 702; çağıranı olmayan 5 585. (3) Gösterinin ad haritası `reconstructed/src/naming_map.json` `global`: 17 anahtar, 17'si `FUN_`.

**B-2. xref türetme denetimi, Ollama dilimi** (`xref_turetme_komutu.txt`; girdi: aynı çalışma alanının `static/ghidra_{xrefs,strings,call_graph}.json`'ı). Çıktı:

```
fonksiyon (xrefs.json) 13559 | dizgi kullanan fonksiyon: xrefs.json 1040 strings.json 1040
dizgi kumesi esit fonksiyon 13559 / 13559
farkli 0 | xrefs.json fazlasi olan 0 | strings.json fazlasi olan 0
(fonksiyon, dizgi) cifti: xrefs.json 2993 strings.json 2993
dizgi basina basvuran kumesi esit 1803 / 1803
tek basvuranli dizgi: xrefs.json 1533 strings.json 1533
called_by == call_graph.callers: 13559 | farkli 0
functions_called == call_graph.callees: 13559 | farkli 0
```

**B-3. K0 çekirdeği, T100 ve T300** (satır içi komut: `goruntu.ac` → `fonksiyon_baslangiclari` → `go_pclntab.oku` → `objc.oku`; `uptime` yük ortalaması 5,00). Çıktı:

```
T100 ac 0.62 sn fonksiyon_baslangiclari 0.03 sn 163141 go 0.01 sn veri_yok objc 0.00 sn veri_yok 0 giris 0x100001380
T300 ac 3.68 sn fonksiyon_baslangiclari 0.14 sn 746814 go 0.10 sn veri_yok objc 0.00 sn veri_yok 0 giris None
```

Süreler yük altında ve tek ölçümdür; yalnız mertebe için kullanıldı.

**B-4. TAHMİN tablosunun kaynağı.** `~/karadul_olcum/runs/arge-2026-11-19/olcek/egri.json` → `dis_degerleme_TAHMIN` (ÖLÇEK tur 1'in dış değerlemesi; `olcek/BULGULAR.md` §3.5'in verisi). Bu turda yalnız okundu: T100 `otomatik_analiz+fonksiyonlar` alt / üst / kötümser 1 829,9 / 3 810,7 / 19 846,7 sn; `dizgiler` 26,8 sn; `cagri_grafigi` 425,6 / 489,6 / 2 206,0 sn; `decompile` 16 213,5 / 58 633,5 sn; `xref` 3 203,6 / 3 999,2 sn; `cfg` 6 932,6 / 10 711,4 sn; `bsim` 23 638,1 / 64 149,0 sn. T300: ilk adım 5 040 / 16 085 (kötümser 218 802), çağrı grafiği 1 390 / 1 735, dizgi 104 sn. K1 = ilk adım + dizgi + çağrı grafiği toplamıdır (bu belgenin türetmesi).

**B-5. Hedef türü denetimi** (satır içi komut: `TargetDetector().detect(...)`, soyulmuş keşif kopyaları `~/karadul_olcum/ustveri_set/<ad>/bin/`). Çıktı:

```
docker-cli docker-cli TargetType.GO_BINARY 37706992
terminal-notifier terminal-notifier TargetType.MACHO_BINARY 108048
```

Gösteri hedefi (evrensel Ollama) `universal_binary` türündeydi (`raw/target_info.json`); statik aşaması `analyze_static` yolundan geçti.

## PAKET BİTTİ
