# ÖL-10 — tembel derinlik / büyük ikili kipi: tasarım (2026-11-23)

Paket: OL10 (KARARLAR A-18, A-24). Yalnız belge; kod, test, ayar yazılmadı; Ghidra koşulmadı. Bu belge kendi başına uygulanabilir olacak biçimde yazıldı: uygulayan Opus ajanları bu oturumu görmeyecek.

## Berke için özet

1. Bugün Karadul her fonksiyonu baştan sona işliyor; bu yüzden 26,6 MB'lık Ollama dilimi 2 saat 9 dakika sürdü, 100 MB'lık bir program için yalnız Ghidra kısmı 14–39 saat tahmin ediliyor.
2. Büyük ikili kipi işi üç katmana böler. **Katman 0** (Ghidra yok): programda yazılı adlar, dizgiler, içe aktarımlar, fonksiyon sınırları. 95 MB'lık programda bunun çekirdeği 0,65 saniyede okundu.
3. **Katman 1:** Ghidra programı çözümler; fonksiyon listesi, çağrı grafiği, dizgi başvuruları çıkar. Kod üretilmez. 100 MB'ta 38–72 dakika (TAHMİN).
4. **Katman 2:** okunabilir C kodu yalnız seçilen fonksiyonlar için üretilir: programın kendi kodu önce, hazır kitaplıklar hiç. Ollama'da bu seçim 13 160 fonksiyonun 4 028'i (%30,6) çıktı; gösterinin ad verdiği 17 fonksiyonun 17'si de bu kümenin içinde.
5. Analist ne görür: birkaç dakikada ilk özet; 100 MB'lık programda yaklaşık 1–2 saatte (TAHMİN 60–110 dk) öncelikli 3 000–5 000 fonksiyonun okunabilir kodu ve adları. Kötü senaryoda süre bütçesi keser; kısmi ama açık etiketli rapor çıkar.
6. Seçilmeyen her fonksiyon listede "decompile edilmedi" diye görünür; adı üst veriden biliniyorsa adıyla. Analist ya da KaradulLM istediği fonksiyonu sonradan tek komutla ya da tıklayarak açtırır.
7. Bilerek sonraya bırakılanlar: kitaplık ve çalışma zamanı fonksiyonlarının gövdesi, seçilmeyenlerin akış grafiği, BSim. Hiçbiri silinmez; "ertelendi" diye sayılır ve istenince yapılır.
8. Planın eski hedefi ("100 MB'ta ilk rapor ≤ 60 dakika") bu hâliyle tutmaz: Ghidra'nın kendi çözümlemesi tek başına 38–72 dakika (TAHMİN) ve tembel kip onu kısaltmaz. Hedef üç parçaya bölündü (§6).
9. Bu turda ölçülen yeni bulgu: pahalı "çapraz başvuru" adımının fonksiyon başına çıktısı, Katman 1'in iki dosyasından Ghidra'sız türetilebiliyor (Ollama: 13 559 / 13 559 fonksiyonda aynı). Bu hem süreyi düşürür hem kısmi analizde ad kurallarını bozulmaktan korur.
10. İş 10 alt pakete bölündü; ilk üçü (seçim modülü, Ghidra'sız kesit deneyi, köprü kesit ölçümü) bugün yazılabilir, köprü değişikliği `headless.py` zincirinin sonunu bekler.

## Karar listesi (Berke / ana oturum)

| No | Karar | Kimin | Öneri | Gerekçe (tek satır) |
|---|---|---|---|---|
| K-1 | T100 kabul hedefi "ilk rapor ≤ 60 dk" üç parçaya bölünsün (§6.1) | ana oturum (ön kayıt değişikliği) | evet | Katman 1 TAHMİN [38; 72] dk, 60 dakikayı içeriyor; tembel kip Katman 1'i kısaltmıyor |
| K-2 | Seçilen kümede "ad eşitliği %100" yerine "tam kipte olmayan ad 0, farklı ad 0; eksik ad sayılır" | ana oturum | evet | ad hattının teklik / susturma / çakışma kuralları nüfusa bağlı (§3.3); eşitlik yapı gereği garanti değil, yanlış ad üretmemek garanti edilebilir |
| K-3 | Tembel kipte biten koşunun durumu `kismi`, çıkış kodu 3 (yeni kod yok) | ana oturum | evet | "decompile edilmedi" başarı gibi görünmemeli; var olan `partial_reasons` yolu yeter (`karadul/core/pipeline.py:81-86`) |
| K-4 | Tembel kipte BSim ertelenir (koşmaz; `bsim_status: "ertelendi"`) | ana oturum ("kapsam küçültülmez" ile ilişkisi) | evet | gölge kipte, ad haritasına girmiyor; T100'de TAHMİN 6,6 saatten fazla; ertelenen iş sayılıyor ve istenince koşuyor |
| K-5 | Kitaplık / çalışma zamanı sınıfı (Go `runtime`, standart kitaplık) kendiliğinden hiç seçilmez; yalnız istekle | Berke (ürün davranışı) | evet | Ollama'da kodun %58,5'i bu sınıf; adları üst veriden %99,99 kesinlikle biliniyor, kaynağı açık |
| K-6 | KaradulLM decompile'ı kendisi başlatmaz; "decompile isteği" önerisi açar, analist onaylar | Berke (ürün davranışı) | evet | var olan sözleşme süreç başlatan aracı yasaklıyor (`karadul/lm/tools/__init__.py:50-55`) |
| K-7 | İki yeni ayar alanı: `buyuk_ikili.decompile_butcesi_sn`, `buyuk_ikili.secim_ust_sinir` (yama ile; A-19) | ana oturum | evet | seçim sayısı sabit N değil süre bütçesinden türemeli (A-9: donanımdan bağımsız) |
| K-8 | Öntanım: kip kapalı kalır (`buyuk_ikili.tembel = False`, `esik_mb = 0`); açılış eşiği OL10-J ölçümünden sonra | ana oturum | evet; aday eşik 16 MiB kod | A-14 mantığı: ölçülmeden öntanım değişmez; 16 MiB = gösteri kodunun (5,25 MiB) 3 katı, TAHMİN |
| K-9 | Ghidra projesi tembel kipte silinmez (çalışma alanında kalır) | ana oturum (disk) | evet | sonradan decompile ve sürdürme için şart; T100'de TAHMİN [0,3; 0,9] GB |
| K-10 | Katman 1'i kısaltacak "bölgesel çözümleme" (yalnız seçilecek adres aralıklarını çözümlemek) bu planda yok; OL10-C ölçümünden sonra ayrı Ar-Ge | ana oturum | evet | çıktıyı tam kipten farklılaştırır (çağıran listeleri eksilir); önce Katman 1'in gerçek süresi ölçülmeli |
| K-11 | Boş makine gecesi (A-26) gelince OL10-C'nin süre kolu aynı geceye eklensin (T100; `--tek`) | Berke (gece izni) | evet | tasarımın en büyük iki bilinmeyeni (Katman 1 süresi, kayıtlı projeyi yeniden açma süresi) yalnız böyle kesinleşir |

## 0. Künye, yöntem, terimler

- **Taban:** main `f2b0db5` (2026-11-23 08:11; worktree `git merge --ff-only main`). Bütün dosya:satır atıfları bu commit'te `grep` / `sed -n` ile doğrulandı (liste Ek A). P16e (`karadul/ghidra/headless.py`) ve PUV6a (`karadul/stages.py`, `karadul/pipeline/steps/_feedback_naming_*.py`, `karadul/core/naming_labels.py`) bugün yazılıyor; main'e girince satır numaraları kayar. Her atfın yanında işlev adı var: uygulayan ajan `grep -n "def <ad>"` ile yeniden bulur, satır numarasına güvenmez.
- **Sayıların kaynağı:** belge yolu ya da komut her sayının yanında. Bu turda üretilen sayılar salt okur üç komuttan gelir (Ek B; komut metinleri ve çıktıları depo dışında, `~/karadul_olcum/runs/dalga1-2026-11-23/OL10/`). Yeni Ghidra / `karadul analyze` koşusu yok. Süre içeren iki küçük ölçüm (üst veri okuma) "yük altında" etiketlidir.
- **TAHMİN** etiketli her sayı dış değerlemedir; aralığıyla ve kaynağıyla yazıldı. 119 küçük ikiliden kurulan ölçek modeli gösteride 10 öngörünün 7'sinde tutmadı (`olcek/OLC0.md`); bu yüzden büyük ikili TAHMİN'leri karar için değil, bütçe ve ön kayıt aralığı için kullanılır.
- **Terimler:**
  - *Katman 0 (K0):* Ghidra'sız okuma (ikilinin baytları).
  - *Katman 1 (K1):* Ghidra içe aktarma + otomatik analiz + fonksiyon listesi + dizgiler + çağrı grafiği (decompile yok).
  - *Katman 2 (K2):* seçilen fonksiyonların decompile'ı + onlara bağlı döküm (CFG, P-code) + ad hattı.
  - *Seçili küme (S):* K2'ye giren fonksiyonlar. *Ertelenen:* K2'ye girmeyen program fonksiyonu.
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
- Başarı hükmü `_judge_outcome` (`:833-861`): en az bir fonksiyon decompile edilmiş olmalı. Seçili küme boş olamaz (B1 basamağı en az giriş fonksiyonunu içerir; §2.3).

Köprünün dışı:
- Statik aşama köprüyü `MachOAnalyzer._run_ghidra_legacy` içinden çağırır (`karadul/analyzers/macho.py:1254-1307`; çağrı `:1281-1287`) ve **Ghidra projesini her koşunun sonunda siler** (`:1293-1307`; `GhidraProject.cleanup`, `karadul/ghidra/project.py:47-66`). Sonradan decompile için proje kalmalı (K-9).
- Köprü dönünce her çıktı ikinci kez `static/ghidra_<ad>.json` olarak yazılır (`macho.py:434-438`); ad hattı bu kopyaları okur (`karadul/pipeline/steps/ghidra_metadata.py:94-133`).
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
| `TASLAK` | Ghidra'da `is_thunk` ya da `is_external` | hayır (yalnız istekle) |
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

- **E (giriş kümesi):** ikilinin giriş adresini içeren Ghidra fonksiyonu (sınıfı `STANDART` olsa da seçilir; ELF'te `main` kurtarma bu fonksiyonun `.c`'sini okur: `karadul/stages.py:1816-1875`); üst veride adı `main.main` olan Go fonksiyonu; Ghidra'nın `entry` adını verdiği fonksiyon. Dışa aktarılan fonksiyonlar (dylib) E'ye girmez (sayıları binleri bulabilir); onlar B2–B4'te kanıtlarıyla sıralanır.
- **kanıt(f)** = f'nin başvurduğu farklı dizgi adresi sayısı + f'nin çağırdığı farklı `TASLAK` fonksiyon (içe aktarım) sayısı. İkisi de küme boyutudur.
- Bir fonksiyon ilk girdiği basamakta sayılır.
- Adres karşılaştırması tam sayıyladır (onaltılık dizgi olarak değil).
- Sabitler (`GIRIS_DERINLIGI = 2`, `GIRIS_UST_SINIR = 256`, `KURAL_SURUMU = 1`) tek yerde, seçim modülünde tanımlanır (`karadul/core/tembel_secim.py`, yeni); başka dosya bu sayıları yazmaz, içe aktarır.

Gerekçe (neden bu sıra):
- Decompile'ın iki ayrı değeri var: analistin okuyacağı gövde ve ad kanallarına girdi. Adı üst veriden bilinen fonksiyonda ikinci değer sıfıra yakın (ad zaten %99,99 kesinlikle var: docker-compose 90 077 / 90 077, `DURUM.md` PUV1); geriye birinci değer kalır ve o yalnız programın kendi kodunda yüksektir. Bu yüzden `KENDI` en önce, `STANDART` hiç.
- `BILINMIYOR` sınıfı ad kanallarının iş yapabildiği tek yerdir (gösterinin 17 adının 17'si bu sınıfta: Ek B-1); kanıtı olan önce gelir çünkü analistin ve KaradulLM'in tutunacağı dizgi / içe aktarım orada.
- `c_namer` adlarının bağımsız nüfustaki kesinliği %79,8 (A-29), ad eşiğinin (0,909; A-13) altında. Sıra "c_namer daha çok ad üretsin" diye kurulmadı; ölçüt okunacak koddur.

### 2.4 Bütçe ve kesim

- Sıralı liste L = B0 ‖ B1 ‖ … ‖ B5. İki sınır:
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
| seçilmeyen (`STANDART`) | 8 541 | 3 168 916 | — | (%58,5) |

- Gösterinin ad verdiği 17 fonksiyon: B3'te 10, B4a'da 5, B4b'de 2; en geç sıra 3 831. B4 sonuna kadar (4 028 fonksiyon) seçilirse 17'sinin de gövdesi var. Adların aynı çıkıp çıkmadığı OL10-B'de ölçülür.
- Giriş adresi (`0x100081fb0`) Ghidra'da bir program fonksiyonunun başlangıcı değil (Ek B-1); E'ye yalnız `main.main` girdi. Kural "içeren fonksiyon" dediği için ürün aracı bu adresi içeren fonksiyonu arar (kuru sayımda aranmadı).
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
| Ön ad: gnulib parmak izi | `karadul/stages.py:1877-2212` (`.c` taraması ve "bütün dizgi değişmezleri" `:1938-1944`; çağrı grafiği `:1973-1976`) | C + J | **kanıt satırı** (ad yazmaz): adayın tekliği ve varlık kanıtı yalnız S'nin `.c`'lerinden hesaplanabiliyor (S-3) | hayır | aday `static/gnulib_candidates.json`'a "kısmi nüfus" nedeniyle (var olan yol: `:1902`, `:2211`); OL10-B ölçer, sonuca göre gevşetilir |
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
3. **`c_namer`'ın çözümleme aşaması.** Ad seçimi fonksiyon başına yalıtık değil: çakışma eki (`used_new_names`, `c_namer.py:2394`), kebap dizgi dizini (`KebabIndex(self._func_bodies)`, `:4154`), parametre mirası (`_propagate_passthrough_params`, `:2381`), alt kanal susturma sayımları ve geri besleme döngüsünün turları (bir turda verilen ad sonrakinin girdisi) nüfusun tamamına bakar. Kısmi nüfusta aynı fonksiyon farklı ek alabilir ya da tam kipte susturulan bir ad yazılabilir. Önlem yapı değil ölçüm: OL10-B, S üstünde tembel ↔ tam farkını kanal kanal sayar (aynı / eksik / fazla / farklı). Kabul kuralı K-2'dir: fazla = 0 ve farklı = 0 beklenir; tutmazsa farkı üreten kural bulunur ve o kural tembel kipte "kanıt satırı"na indirilir (yeni yanlış ad üretilmez), eksik ad sayısı raporlanır.

`c_namer` için ayrıca iki yapısal kural (OL10-F):
- Strateji döngüsü yalnız gövdesi olan fonksiyonlarda döner (bugün `ghidra_functions.json`'daki her fonksiyon için süreç havuzuna iş gönderiliyor: `c_namer.py:2245`, `:2285-2295`; toplam süre sınırı 1 200 sn `:2295`). T100'de bu 163 141 iş ve gövdesiz fonksiyonlarda JSON koluyla ad demektir.
- Var olan adla çakışma denetimi tam nüfusla kalır (fonksiyon dizini `self._func_by_name` bütün fonksiyonlardan kurulur; süzülmüş bir `functions.json` verilmez).

### 3.4 Köken kaydına eklenenler

Köken kaydı (`naming_provenance.json`, `karadul/core/naming_labels.py:24`) ve temiz çıktının ad kayıtları iki alan kazanır; yalnız tembel kipte yazılır (kip kapalıyken dosya bayt bayt aynı kalsın: S-5):

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
    "decompile_edildi": 5000, "decompile_basarisiz": 3,
    "ertelendi": {"secilmedi": 150000, "butce": 8138, "istek_bekliyor": 0},
    "sinif": {"KENDI": 0, "BILINMIYOR": 163141, "BAGIMLILIK": 0, "STANDART": 0},
    "basamak": {"B0": 0, "B1": 212, "B2": 0, "B3": 9100, "B4a": 0, "B4b": 0, "B5": 0}
  },
  "secim_sha256": "…",                               // sıralı listenin özeti
  "sira_dosyasi": "tembel_sira.jsonl",               // satır: {"a": adres, "b": basamak, "s": sınıf, "d": durum}
  "proje": {"yol": "static/ghidra_project", "saklandi": true},
  "dilimler": [ {"no": 1, "kaynak": "ilk", "istenen": 5000, "biten": 4997, "basladi": "…", "bitti": "…"} ]
}
```
(Sayılar örnek biçimdir, ölçüm değil.) `durum` değerleri: `decompile_edildi`, `basarisiz`, `ertelendi:secilmedi`, `ertelendi:butce`, `ertelendi:istek_bekliyor`. Değişmez kural (testle kilitli): `program = decompile_edildi + decompile_basarisiz + Σ ertelendi`. Sıra dosyası JSON Lines'tır (746 814 fonksiyonda tek JSON belgesi bellekte gereksiz yer tutar); dilim bitince atomik yeniden yazılır (`os.replace`).

### 4.2 Köprü ve durum dosyaları

- `decompiled.json` ve `ghidra_status.json` `decompile` bölümü (`macho.py:1137-1143`) yeni alan kazanır: `deferred` (ertelenen sayısı) ve `selection` (kural sürümü, sınırlar, basamak sayımı). `total_attempted` yalnız S'yi sayar; `functions_total` (bugün "sonuç kaydı sayısı", `headless.py:1533`) tembel kipte de BÜTÜN fonksiyonları sayar.
- Ertelenen fonksiyon `skipped` DEĞİLDİR. `skipped` / `losses.decompile_skipped` bugünkü anlamını korur: seçilmiş ama toplam decompile süresi dolduğu için yapılamamış (`headless.py:1355-1361`). Kayıp sayacı (`losses`) yalnız kayıpları sayar: başarısız, süreyle atlanmış, kesilmiş. Ertelenen ayrı alandadır. Böylece kip kapalıyken `losses` bugünküyle aynı kalır ve "kayıp 0" cümlesi tembel kipte de doğru anlam taşır: seçilenlerin hiçbiri kaybolmadı.
- `ghidra_status.json` `project` alanı (`macho.py:1146`; bugün `kept: false`) tembel kipte `kept: true` ve yolu taşır.

### 4.3 Rapor, CLI, çıkış kodu

- **Durum:** statik aşama `stats["partial"] = True` ve `partial_reasons = ["tembel derinlik: E / T fonksiyon decompile edilmedi (büyük ikili kipi; kural sürümü 1)"]` yazar. `analysis_outcome` (`karadul/core/pipeline.py:55-95`) bunu `kismi` sayar; çıkış kodu 3 (`EXIT_ANALYSIS_PARTIAL`, `:52`). Yeni çıkış kodu yok (K-3). Ertelenen fonksiyon varken hiçbir yol "tam" / çıkış 0 üretmez.
- **Ayırt edilebilirlik:** `pipeline_result.json` ve raporda `depth` nesnesi (`tembel_durum.json`'ın `kip`, `katman`, `sayim` alanları). Ölçüm araçları "kısmi, yalnız tembel erteleme" ile "kısmi, hata" durumunu buradan ayırır: `partial_reasons`'ın her öğesi `tembel derinlik:` ile başlıyorsa ve `losses` sıfırsa birincisidir.
- **CLI:** koşu sonunda `--quiet` olmayan her kipte stderr'e tek satır: `TEMBEL KİP: 5 000 / 163 141 fonksiyon decompile edildi; 158 141 ertelendi (150 000 seçilmedi, 8 138 bütçe); sürdürmek için: karadul decompile <ws> --sonraki`.
- **Rapor ("Derinlik" bölümü; `karadul/reporting/report_data.py`, fonksiyon sayacı `:734`):** dört gözlü tablo, yüzde yanında her zaman sayı:

  | | gövde var | gövde yok |
  |---|---|---|
  | adı var | … | … (kanal kırılımıyla: üst veri, ELF önyükü, FunctionID …) |
  | adı yok | … | … |

  "Adlandırılan fonksiyon oranı" tek sayı olarak verilmez; "programın kendi kodu" (`KENDI`) ayrı satırdır (`ustveri/PLAN.md` §risk 6: Go adlarının %72–94'ü kitaplık).
- **Sahte başarı denetimi (kabul ölçütü olarak yazılır):** (a) özet satırlarında "decompile edilen" sayısı `decompiled/` altındaki `.c` sayısına eşit; (b) `program = edildi + başarısız + ertelenen`; (c) ertelenen > 0 iken çıkış ≠ 0; (d) hiçbir çıktıda ertelenen fonksiyon için boş ya da yer tutucu `.c` yok.

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
karadul decompile <çalışma alanı> --komsu <adres> [--derinlik 1]   # fonksiyon + çağırdıkları (STANDART / TASLAK hariç)
karadul decompile <çalışma alanı> --sonraki [N]           # kural sırasındaki sonraki N (öntanım secim_ust_sinir)
karadul decompile <çalışma alanı> --devam                 # yarıda kalmış dilimi sürdür
        [--adlandir | --adlandirma-yok]                   # ad hattını şimdi yeniden koş / koşma
```
`karadul/cli.py`'de `decompile` adlı komut bugün yok (komutlar: `version`, `analyze` `:634`, `run` `:1127`, `list` `:1318`, `rtti` `:2315` …); ad çakışması yok.

### 5.2 Akış: K2 her zaman kayıtlı projeden koşar

İlk koşunun K2'si, sürdürme ve isteğe bağlı decompile **aynı kod yolunu** kullanır:

1. K1, `pyghidra.open_program` bağlamında koşar ve bağlam kapanırken program kaydedilir (bağlam çıkışı = programın kaydı ve projenin kapanışı: `headless.py:712-714` `ADIM_KAPATMA`).
2. Seçim JVM bağlamının DIŞINDA, K1'in diske yazdığı JSON'lardan yapılır (saf Python).
3. K2: proje `analyze=False` ile yeniden açılır (`open_program` var olan programı projeden açar; `_run_auto_analysis` `shouldAskToAnalyze` yanlış dönünce `already_analyzed` ile çıkar: `headless.py:802-804`), verilen fonksiyon listesi decompile edilir, S için CFG çıkarılır, bağlam kapanır.

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
- **Toplu (`--adlandir`; ya da bekleyen fonksiyon sayısı `--sonraki` dilimi kadar olunca kendiliğinden):** yeniden kurma aşaması birikmiş S üstünde BAŞTAN koşar. Artımlı ad hattı yok: `c_namer`'ın çözümlemesi nüfusa bağlı olduğu için (§3.3) yalnız yeni fonksiyonu adlandırmak, aynı kümeyi baştan seçmiş bir koşudan farklı ad verebilir. Baştan koşmak yol bağımsızlığını korur; maliyeti S ile sınırlıdır (TAHMİN: 5 000 fonksiyon ≈ 14,5 dk yük altında; HZ-7 paketleriyle düşer).
- Hangi kanal yeniden koşar: gövde isteyen kanallar (tablo §3.2'de "yalnız S") baştan; B / J girdili kanallar (üst veri, ELF önyükü, FunctionID, K-4) aynı girdiyle aynı sonucu verir, yeniden koşmaları zararsızdır (ayrı önbellek yazılmaz).
- Analistin elle verdiği adlar korunur (var olan yol: `force_manual_names`, `_feedback_naming_merger.py:187`).

### 5.5 Arayüzden ve KaradulLM'den tetikleme

- **Arayüz:** gövdesiz düğümdeki "Decompile et" düğmesi sunucuda `karadul decompile <ws> <adres>` işini başlatır (var olan iş kuyruğu; ilerleme `_job_progress`, `ui/server.py:2477`). Aynı çalışma alanında aynı anda tek decompile işi (proje kilidi); ikinci istek kuyruğa girer. İş bitince düğüm gövdeli olur; sayfa yenilenmeden yalnız o düğüm güncellenir.
- **KaradulLM:** model süreç başlatamaz ("süreç başlatan araç hiçbir kipte yoktur": `karadul/lm/tools/__init__.py:50-55`). Yeni "Ö" sınıfı araç `request_decompile(addr, neden)`: bir **öneri kaydı** açar (`ACTION_PROPOSE`, `:54-55`); analist onaylarsa arayüz yukarıdaki işi başlatır. Model sonucu aynı turda göremez; bir sonraki turda `get_decompiled` çalışır. Oturum başına öneri sayısı sınırlıdır (öneri: 20; sabit araç kaydında tek yerde). Öneri kayıtları P22e'nin öneri altyapısına bağlıdır; P22e main'de değilse araç kayıt defterine girmez (`arac_kapali`) ve model yalnız "bu fonksiyon decompile edilmedi; analist isteyebilir" bilgisini verir.

### 5.6 Sürdürme (kaldığı yerden)

| Kesinti anı | Diskte ne var | Sürdürme |
|---|---|---|
| K0 sırasında | hiçbir şey ya da `static/k0_ozet.json` | baştan (saniyeler) |
| K1 sırasında (otomatik analiz) | adım adım yazılmış K1 JSON'ları olabilir; proje kaydedilmemiş | K1 baştan (bağlam kapanmadığı için kayıt yok). Otomatik analizin ortasından sürdürme bu tasarımda YOK; ÖL-1 bekçisi ve ÖL-2 bütçeleri K1'i sınırlar |
| K1 bitti, K2 başlamadı | K1 JSON'ları + kayıtlı proje + `tembel_durum.json` (`k2: "yok"`) | `karadul decompile <ws> --devam`: seçim yeniden hesaplanır (belirlenimci), K2 baştan |
| K2 decompile sırasında | biten partilerin `.c`'leri + `tembel_gunluk.jsonl` (parti bitince eklenen satırlar) | `--devam`: günlükte bitmiş görünen fonksiyon yeniden decompile edilmez; kalan aynı sırayla |
| ad hattı sırasında | `static/` tam; `reconstructed/` yarım | ad hattı baştan (S ile sınırlı) |

Parti günlüğü (`static/tembel_gunluk.jsonl`): her parti bitince tek satır (parti no, adresler, başarı / hata sayısı) `flush` + `fsync` ile eklenir. Dilim bitince `tembel_sira.jsonl` yeniden yazılır ve günlük boşaltılır. Sürdürmenin kabul ölçütü ön kayıtlıdır (H-I2): kesilip sürdürülen koşunun `static/` içeriği kesintisiz koşununkiyle aynı; yeniden decompile edilen bitmiş fonksiyon 0.

Paket hedefinde sürdürme ÖL-5b'dir (bileşen kuyruğu); ÖL-10 bileşenin İÇİNDEKİ sürdürmeyi verir. İkisi birleşince: paket kesilir → bitmiş bileşenler atlanır (ÖL-5b), yarım bileşen K1 bittiyse K2'den sürer (ÖL-10).

## 6. Kabul ve ön kayıt

YAZILMADI

## 7. Uygulama planı

YAZILMADI

## 8. Riskler ve açık sorular

YAZILMADI

## Ek A — atıf doğrulama

YAZILMADI

## Ek B — bu turda koşulan komutlar

YAZILMADI
