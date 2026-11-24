# BA2 — BA-2: kalan üstel düzenli ifadeler ve tam takımda kalıp denetimi kapısı (ilerleme)

- Gönderim: `docs/arge/2026-11-23_dalga1/gonderim/BA2.md`
- Dal: `worktree-agent-ae5cddf8fcd57b762`; taban main `cfe93cef` (ff-only, 13:13; ürün kodu `534e252b` ile aynı)
- Koşu kökü: `~/karadul_olcum/runs/dalga1-2026-11-23/BA2/`
- Sert son: 14:55

## Durum

- 13:13 başladı; belgeler okundu (ORTAK_D1 §5 + §6, ORTAK_D0, ONARIM_BRIF, KARARLAR A-35 / A-36, gönderim BA1 + BA1 ilerleme, `kalip_tara.py`, `kalip_sure.py`).
- 13:20 ön kayıt: `docs/arge/2026-11-23_dalga1/on_kayit_BA2.md`, commit `17b415a3`.
- Bütün süreler **yük altında** (load 8 → 34; aynı anda üç ajan + ana oturumun S8 / Ollama koşuları). Kusurlu kalıbı deneyen her komut ayrı çocuk süreçte, zaman aşımı / bekçiyle (SIGKILL). Koşu betikleri ve ham çıktılar koşu kökünde (`h1.py`, `ozet/h2_esdeger.py`, `ozet/h2_buyuk.py`, `kos1.sh`, `s8_kos.sh`, `ozet/polinom_gercek.py`, `ozet/calisma_ani.py`, `eski_mutasyon.sh`); depoya yalnız sayı.

## Kalem 2 — iki bilinen üstel kalıbın onarımı (H1, H2, H3) (13:16)

| dosya:satır (onarımdan sonra) | eski | yeni | çağıranın okuduğu |
|---|---|---|---|
| `karadul/reconstruction/c_namer.py:3445` (`CVariableNamer._try_demangle_cpp`) | `_ZN(\d+\w+)+E` | `_ZN(\d\w+)E` | yalnız eşleşmenin varlığı (`if match:`); grup okunmaz, ad `mangled[3:]`'ten elle ayrıştırılır |
| `karadul/reconstruction/recovery_layers/constraint_solver.py:275` (`_LINKED_LIST_RE`) | `(?P<type>[a-zA-Z_](?:\w+\s*)*\*{0,2})` | `(?P<type>[a-zA-Z_](?>(?:\w+\s*)*)\*{0,2})` | `finditer` dizisi (span'lar sonraki aramanın başlangıcını belirler), `var`, `type` (`.strip()`), `offset` |

**Gerekçe.**
- `_ZN`: `\d ⊂ \w` olduğu için `(\d+\w+)+` ile `\d\w+` aynı dili tanır (rakamla başlayan, en az iki karakterlik `\w` dizisi; tek parça her bölünüşü kapsar). Eski kalıbın geri izleme sırası: ilk yinelemenin `\w+`'ı en uzundan geri verilir, her konumda önce ikinci yineleme (rakam ister; `E` rakam değil) sonra `E` denenir; ilk başarı en sağdaki uygun `E`'dir (konum ≥ 5) ve o anda tek yineleme vardır. Yeni kalıp aynı `E`'de biter: span ve grup 1 (`mangled[3:q]`) aynı. Grup okunmadığı için grup eşitliği zorunlu değildi; yine de eşit. `\d+\w+` yazımı karesel kalırdı (`\d+` ile `\w+` örtüşür); `\d\w+` doğrusal.
- `_LINKED_LIST_RE`: döngünün tükettiği karakterler `\w` ve `\s`; ardındaki `\*{0,2}\s*\*?\s*\)` bir `\w` karakterini tüketemez, geri verilen boşluğu ise dıştaki `\s*` zaten yutar. Bu yüzden döngünün geri vermesi hiçbir başlangıçta yeni bir eşleşme üretemez; atomik grup yalnız sonuçsuz denemeleri keser, span ve bütün grupları korur (döngünün içinde yakalama grubu yok). Kalıbın yanındaki v1.7.6 yorumu ("her adımda en az 1 \w tüketir, backtracking sınırlar") ölçümle çelişiyordu: düzeltildi; `_detect_linked_lists` içindeki "O(n) safe (negated char class)" yorumu da yanlıştı, düzeltildi.

**H1 (ayrı süreçte, `ozet/H1.json`; 13:18, load 8,3):**

| kalıp | girdi | eski | yeni |
|---|---|---:|---:|
| `_ZN` | `"_ZN" + "0a" * n + "!"`, n = 20 / 24 / 28 / 32 | 54 ms / 0,98 sn / **> 5 sn** / > 5 sn | 1,8 / 3,4 / **3,6** / 3,8 µs |
| `_ZN` | n = 64 / 1 000 / 10 000 | ölçülmedi | 5 µs / 14 µs / 0,13 ms |
| `_LINKED_LIST_RE` | `"a=*(a" + "a" * n + "!"`, n = 20 / 24 / 28 / 32 | 0,10 sn / **1,60 sn** / > 5 sn / > 5 sn | 5,9 / **6,5** / 9,2 / 9,0 µs |
| `_LINKED_LIST_RE` | n = 64 / 1 000 / 10 000 | ölçülmedi | 28 µs / 5,2 ms / 0,52 sn |

Eşik ≤ 0,1 sn → **TUTTU** (BA-1'in iki girdisi: 3,6 µs ve 6,5 µs). Not: `_LINKED_LIST_RE`'nin 10 000 karakterlik tek `\w` koşusunda 0,52 sn'si üstel değil, `var` grubunun `\w+`'ının her arama başlangıcında geri izlemesi (karesel; 1 000 → 10 000'de ~100 kat). Bu kalıbın onarımın dışındaki parçası; polinom listesinde.

**H2 (eşdeğerlik, gerçek girdi; `ozet/h2_esdeger.py`, ham `h2/H2_ozet.json`):** girdiler geliştirme setinin 119 çalışma alanı (`urun-onarim-a62f15e`) + Ollama.
- `_LINKED_LIST_RE`: her çalışma alanının `deobfuscated/decompiled/*.c` dosyasının tam içeriği (`_detect_linked_lists`'in birimi), **80 537 dosya**; eski ve yeni ayrı çocuk süreçlerde, dosya başına `finditer` dizisinin (span + adlı gruplar) özeti karşılaştırıldı. **Farklı 0**, zaman aşımı 0 / 0 (5 sn bekçi); eşleşen dosya 1 517, toplam eşleşme 2 841; en kötü dosya eski 0,37 sn / yeni 0,39 sn (251 812 karakter). İlk koşuda 3 sn bekçi eski ve yenide birer dosyada (farklı dosyalar) kesti; ağır yükte (load 34) dosya okuması sırasında; 5 sn bekçiyle yinelenince ikisi de bitti. En büyük dört dosya ayrıca tek başına (90 sn sınır): 697 KB'lık Ollama dosyası eski 93 ms / yeni 41 ms, dördünde de aynı özet (`ozet/H2_buyuk.jsonl`).
- `_ZN`: çağıranın koşulunu (`_is_ghidra_auto_name` değil ve `^_Z[A-Z]`) geçen işlev adı **0** (120 çalışma alanının `ghidra_functions.json`'ında `_Z` ile başlayan ad 0; adın içinde `_ZN` geçen ad da 0). **Bu kalıp gerçek veride 0 kez denendi** (Ghidra C++ adlarını çözülmüş biçimde veriyor). Eşdeğerlik bu yüzden yalnız sentetik girdide: `tests/test_ba2_kalip_onarimi.py` 40 000 rastgele girdi (eşleşen > 1 000), farklı 0.
- **H2 → TUTTU** (`_LINKED_LIST_RE` 80 537 gerçek girdi, farklı 0; `_ZN` gerçek veride 0 kez denendi, ön kaydın izin verdiği biçim).

**H3 (ad haritası, S8'in 8 ikilisi; OK1 / P12d'nin Ghidra'sız yeniden oynatması):** kaynak `urun-onarim-a62f15e/<ikili>/ws/workspaces/*/*`; önce kolu `~/karadul_olcum/urun-534e252b` (ürün kodu main `cfe93cef` ile aynı), sonra kolu `BA2/agac_sonra` (= `urun-534e252b`'nin kopyası + bu dalın iki dosyası; `diff -rq` bu dalın `karadul/`'u ile aynı; worktree izolasyonu `git worktree add`'i engellediği için kopya). Her kolun günlüğü yüklenen `karadul/__init__.py` yolunu doğruluyor. Sürücü `s8_kos.sh`, iki kol paralel; 8 / 8 `basari True`.

| ikili | naming_map.json | önce ↔ sonra | süre (sn, iki kolda) |
|---|---:|---|---:|
| debian/coreutils/cat | 11 003 B | bayt eşit | 32 / 32 |
| debian/coreutils/sort | 32 612 B | bayt eşit | 51 / 52 |
| debian/tree/tree | 15 507 B | bayt eşit | 29 / 29 |
| debian/sqlite3/sqlite3 | 72 500 B | bayt eşit | 97 / 97 |
| debian/htop/htop | 89 585 B | bayt eşit | 149 / 149 |
| debian/tmux/tmux | 293 953 B | bayt eşit | 200 / 200 |
| debian/zstd/zstd | 287 955 B | bayt eşit | 268 / 268 |
| mac/tmux | 407 589 B | bayt eşit | 191 / 191 |

**H3: 8 / 8 bayt eşit → TUTTU** (`ozet/H3_bayt.txt`, `ozet/H3_harita_esit.json`).

**Testler:** `tests/test_ba2_kalip_onarimi.py`, 11 sınama: iki kalıbın düşmanca girdileri (BA-1'inkiler ve 20 000 karaktere kadar) ayrı süreçte ≤ 0,1 sn; geçerli adlar / satırlarda beklenen çıktı; eski ↔ yeni eşdeğerlik (2 × 40 000 rastgele girdi, eski kalıp ayrı süreçte); eski kalıpların gerçekten yavaş olduğu (sınamanın körleşmediği). Commit `8bdf7f5c`.

## Kalem 5 — kalıcı araç + kapı testi (H6) (13:24)

- Tarama mantığı `scripts/measurement/kalip_denetimi.py`'ye taşındı; `scripts/arge/ba1/kalip_tara.py` yalnız onu içe aktarır, `kalip_sure.py`'nin ayrı süreçte ölçüm işlevi (`ayri_surecte_ara`) de oradan gelir: iki kopya yok. Komut satırı aynı (`tara`, `gercek`) + yeni `guclu`.
- **Hızlandırma (kapsam daraltmadan, önbelleksiz):** BA-1'de her düşmanca ölçüm ayrı süreçti (aday başına ≤ 42 süreç). Şimdi bütün adaylar tek bir çocuk süreçte ölçülür; çocuk her ölçümden önce satır yazar, ebeveyn 2 sn ilerleme görmezse SIGKILL ile öldürür, takılan adayı üstel sayar, sonraki adaydan yeni çocuk açar. Durağan sınıflamada karakter sınıfı kümeleri (`IN` düğümü) süreç içinde ezberlenir.
- `tests/test_kalip_denetimi.py`, 8 sınama: (a) `karadul/` + `ui/server.py`'nin **1 509 sabit kalıbında** (1 479 dizgi + 30 bytes; bytes kalıpları `fbe382a4`'ten beri latin-1 ile açılıp ASCII bayrağıyla taranıyor) üstel 0 (kapsam körleşmesin diye: `ui/server.py`, `constraint_solver.py`, `block_annotator.py` ve `reconstruction/` dışından en az bir dosya toplanmalı, kalıp sayısı ≥ 1 400, iç içe aday ≥ 30); (b) bilinen kusurlu beş eski kalıp (BA-1'in `memcpy` / `memset` / `memmove`'u, bu paketin `_ZN` ve `_LINKED_LIST_RE`'si) üstel bulunur; (c) istisna listesi (`ISTISNALAR`) boş ve sayılı (`BEKLENEN_ISTISNA_SAYISI = 0`), kayıt alanları (`dosya`, `kalip`, `gerekce`, `olculen_sure`); istisna yalnız kendi kalıbını geçirir; bekçi takılan çocuğu öldürüp üstel sayar; onarılmış iki kalıp üstel değil; şablon toplama yerleştirmeyi ayırır.
- **H6: kapı testi 5,2 sn (load 8; aynı test ağır yükte 20,5 sn), istisna listesi boş → TUTTU** (≤ 60 sn).
- **Mutasyon** `scripts/measurement/mutation_specs_ba2.json`: **9 / 9 öldü (75 sn)** — eski `_ZN` (süre sınaması zaman aşımıyla kırmızı), `_ZN` dili genişler (`\w*`; eşdeğerlik kırmızı), eski `_LINKED_LIST_RE`, `_LINKED_LIST_RE` dili daralır (eşdeğerlik kırmızı), kapının istisna denetimi kalkar, durağan sınıflayıcı iç içe yinelemeyi kaydetmez, bekçinin öldürdüğü aday üstel sayılmaz, kapı `ui/server.py`'yi taramaz, istisna listesine gerekçesiz kayıt girer. Ayrıca kapı sınamasının (a) kendisi eski iki kalıbı geri koyan mutantları öldürüyor (2 / 2; yani üstel bir kalıp eklenince tam takım kırmızı). Commit `2269eb9c`; güçlü düşmanca girdi ve kaçış izleme `fd69a297`; bytes kalıpları `fbe382a4` (ardından `mutation_specs_ba2.json` yeniden 9 / 9, ilgili takım 39 / 39).
- Eski mutasyon tanımları (ORTAK_D1 §6; `grep -l` ile `c_namer.py` / `constraint_solver.py`'ye bakan 8 dosyanın bu iki dosyaya bakan tanımları, `--id` ile): `ad_gecerliligi` 33 / 33, `adim3_c_namer` 21 / 21, `ok1` 7 / 7, `on_ad_onarimi` 3 / 3, `p12a` 13 / 13, `p12b` 3 / 3, `p12c` 14 / 14, `p12d` 10 / 10 → **104 / 104 öldü, hata 0, bayat `find` 0** (koşudan önce her `find` metninin dosyada geçtiği ayrıca denetlendi; toplam 152 sn; sonra `git diff` yalnız bu paketin dosyaları). `scripts/arge/ba1/*.py`'ye bakan tanım yok.

## Kalem 3 — 39 aday (hüküm 2) ve dinamik kalıplar (hüküm 3) (13:31 – 13:43)

**Yöntem (`kalip_denetimi.py guclu`):** her aday için dış yinelemenin gövdesinden pompa adayları: gövdenin tanığı, tanığın iki katı, gövdenin tüketebildiği tek karakterler (en çok 8) ve bunların ikilileri (`ab`: hem tek hem iki yinelemeyle tüketilebilen, yani iki farklı bölünüşü olan girdi); sonek: 13 sabit bozucu + gövdenin tüketemediği karakterler (en çok 6). Bileşim sayısı aday başına 90 – 818. Her bileşim 20 / 40 / 80 karakterde ölçülür; en kötü bileşim (80'de en uzun) 200 / 400 / 800'de yeniden ölçülür, derece d = log2(t800 / t400). Sınıf: 20–80 evresinde zaman aşımı ya da 80'de ≥ 1 sn ya da 40 → 80 ≥ 64 kat → üstel; d ≥ 1,5 ve t800 ≥ 0,1 ms ya da büyüme evresinde zaman aşımı (3 sn bekçi) → polinom; değilse güvenli. Bütün ölçümler tek çocuk süreçte, bekçili. Ham: `ozet/guclu.json` (üçüncü koşu, 13:40); yük altında.

**H4: 39 adaydan üstel 0** (ilk ölçüm). Dağılım: **üstel 0 / polinom 17 / güvenli 22 / doğrulanamadı 0.** Kararsızlık: üç koşuda iki aday sınır üstünde gidip geldi (`semantic_namer.py:389` polinom / güvenli / polinom; `analyzers/dotnet_binary.py:874` polinom / güvenli / güvenli; ikincisi 39'un dışında). Tablo üçüncü koşudur. "Güvenli" ölçümdür, kanıt değil: en kötü bileşimde süre uzunlukla doğrusal.

| aday (`r/` = `karadul/reconstruction/`) | sınıf | d | 800 karakterde | bileşim |
|---|---|---:|---:|---:|
| `r/binary_name_extractor.py:185` | polinom | 1,97 | 5,2 ms | 306 |
| `r/binary_name_extractor.py:2745` | polinom (kübik) | 2,93 | **2,2 sn** | 396 |
| `r/binary_name_extractor.py:2752` | polinom (≥ kübik) | — | **> 3 sn** (bekçi) | — |
| `r/binary_name_extractor.py:2759` | polinom (≥ kübik) | — | **> 3 sn** (bekçi) | — |
| `r/c_flow_simplifier.py:147` | polinom | 2,05 | 12,4 ms | 378 |
| `r/c_namer.py:1503` | polinom | 2,06 | 25,5 ms | 342 |
| `r/c_namer.py:934` | güvenli | 0,96 | 0,016 ms | 323 |
| `r/c_type_recoverer.py:440` | polinom | 1,92 | 11,9 ms | 818 |
| `r/c_type_recoverer.py:543` | güvenli | 0,38 | 0,013 ms | 286 |
| `r/c_type_recoverer.py:129` | güvenli | 0,97 | 0,021 ms | 209 |
| `r/c_type_recoverer.py:239` | güvenli | 0,82 | 0,029 ms | 323 |
| `r/engineering/semantic_namer.py:332` | güvenli | 0,95 | 0,072 ms | 495 |
| `r/engineering/semantic_namer.py:369` | güvenli | 0,67 | 0,030 ms | 615 |
| `r/engineering/semantic_namer.py:384` | güvenli | 1,01 | 0,035 ms | 286 |
| `r/engineering/semantic_namer.py:389` | polinom (sınırda) | 1,91 | 12,2 ms | 286 |
| `r/engineering/semantic_namer.py:1777` | güvenli | −0,15 | 0,023 ms | 286 |
| `r/engineering/struct_recovery.py:713` | polinom | 1,92 | 1,1 ms | 323 |
| `r/engineering/struct_recovery.py:724` | polinom | 1,92 | 1,1 ms | 323 |
| `r/engineering/struct_recovery.py:737` | polinom | 1,92 | 1,1 ms | 323 |
| `r/engineering/struct_recovery.py:748` | polinom | 1,83 | 1,1 ms | 323 |
| `r/engineering/struct_recovery.py:777` | polinom | 2,04 | 13,8 ms | 532 |
| `r/recovery_layers/formula_extractor.py:2430` | polinom | 1,99 | 3,3 ms | 286 |
| `r/reference_differ.py:139` | güvenli | 1,13 | 0,023 ms | 90 |
| `r/string_intelligence.py:102` | polinom | 1,95 | 1,4 ms | 340 |
| `r/string_intelligence.py:110` | polinom | 2,02 | 1,6 ms | 340 |
| `r/string_intelligence.py:115` | güvenli | (1,93; süre gürültü düzeyinde) | 0,014 ms | 340 |
| `r/string_intelligence.py:121` | güvenli | (2,23; süre gürültü düzeyinde) | 0,020 ms | 340 |
| `r/string_intelligence.py:128` | güvenli | 0,99 | 0,036 ms | 340 |
| `r/string_intelligence.py:142` | güvenli | 0,99 | 0,008 ms | 340 |
| `r/string_intelligence.py:216` | güvenli | 0,91 | 0,026 ms | 323 |
| `r/string_intelligence.py:242` | güvenli | 0,96 | 0,020 ms | 323 |
| `r/string_intelligence.py:291` | güvenli | 0,95 | 0,010 ms | 324 |
| `r/string_intelligence.py:300` | güvenli | −0,29 | 0,021 ms | 306 |
| `r/string_intelligence.py:306` | güvenli | 0,85 | 0,024 ms | 324 |
| `r/string_intelligence.py:317` | güvenli | 0,92 | 0,014 ms | 306 |
| `r/string_intelligence.py:1061` | güvenli | 0,96 | 0,015 ms | 180 |
| `r/tarif/alt_kanal.py:142` | güvenli | 0,93 | 0,015 ms | 306 |
| `r/tarif/alt_kanal.py:442` | güvenli | 0,83 | 0,013 ms | 306 |
| `r/xtride_typer.py:633` | polinom | 2,04 | 37,7 ms | 646 |

(BA-1'deki satır numaraları: `alt_kanal.py:140` / `:439` OK1'den sonra `:142` / `:442`; öbürleri aynı.)

Güvenlilerin yapısal nedeni (elle, ölçümle uyumlu):
- **Ayırıcılı yineleme** `X(?:s X)*`, ayırıcı `s` X'in karakter kümesinde değil (`::`, `.`, `_`, `-`, `:`): her yinelemenin sınırı ayırıcıyla belirlenir, bölünüş tek → `string_intelligence.py` 115 / 121 / 128 / 142 / 216 / 242 / 291 / 300 / 306 / 317 / 1061, `alt_kanal.py` 142 / 442, `reference_differ.py:139`, `c_namer.py:934`.
- **Açılmış döngü** (`[^x]*(?:x[^x]*)*`, `(?:\[[^\]]*\]\s*)+`): seçenekler ilk karakterde ayrışır → `c_type_recoverer.py:543`, `semantic_namer.py` 384 / 1777.
- **Anahtar sözcük önekleri** `(?:(?:const|unsigned|…)\s+)*` ardından tek ad: her sözcük `\s+` ile biter, ardındaki ad tek sözcük alabilir → `c_type_recoverer.py` 129 / 239, `semantic_namer.py` 332 / 369 (aynı biçimin `\s*\*+` vb. ile birleşen sürümleri polinom çıktı: `c_type_recoverer.py:440`, `struct_recovery.py:777`, `c_namer.py:1503`).

**Dinamik kalıplar (hüküm 3; `kalip_denetimi.py tara`, ham `ozet/tara_genis.json` → `sablon`):** `karadul/` + `ui/server.py`'de sabit olmayan kalıplı **146** `re.` çağrısı (bytes sabitleri sabit sayılmadan önce 176; BA-1 kapsamında 113).
- **Taranan şablon 118:** modül sabitine bağlı ad 7, şablon 111 (f-dizgi, `+`, `"|".join(…)`, `.format`, `%`; yerleştirilen parça tek harf). Şablonlarda iç içe / örtüşen seçenek adayı **0 → üstel 0**; zincir (polinom adayı) 6: `c_algorithm_id.py` 606 / 620 / 699, `engineering/data_flow.py:1698`, `engineering/semantic_namer.py:1845`, `tarif/rules.py:227`.
- **Taranamayan 28** (kalıp bir değişkenden ya da nesne alanından): `binary_intelligence.py` 1682 / 1891 / 1905, `packer_fingerprint.py:796`, `rust_binary.py:327`, `yara_scanner.py` 372 / 1591, `lm/` altında 6, `c_comment_generator.py:430`, `c_namer.py` 1628 / 2461 ve dört `pattern.pattern.replace('PARAM', re.escape(…))` (taban kalıp sabit olarak taranıyor, yerleştirme kaçışlı), `c_type_recoverer.py:663`, `engineering/` altında 5, `name_validity.py:198`, `naming/npm_fingerprinter.py:585` (kaçışlı).
- **Ek tarama, içe aktarma anı (`ozet/calisma_ani.py`, ham `ozet/calisma_ani.json`):** 351 modül ayrı süreçlerde içe aktarıldı (10'u `karadul/ghidra/scripts/*`, Ghidra dışında içe aktarılamıyor); modül / sınıf / nesne düzeyindeki derlenmiş `re.Pattern`'ler toplandı: AST'nin sabit saymadığı **4 195** kalıp (imza ve kural tabloları), iç içe aday 17, **üstel 0**; güçlü girdiyle polinom 8 / güvenli 9 (hepsi `engineering/analyzer.py`'nin döngü gövdesi kalıpları `(?:[^{}]|\{[^{}]*\})*…`). İşlev içinde çağrı anında kurulan kalıplar bu yolla görülmez.
- **`re.escape`'ten geçmeyen yerleştirme (ayrı bulgu; 8):**

| yer | yerleştirilen | değerlendirme (elle) |
|---|---|---|
| `analyzers/assembly_analyzer.py:239` | `reg` (`AAPCS64_PARAMS` / `WIN64_PARAMS` / `SYSV_AMD64_PARAMS`) | modül sabiti yazmaç adları, düzenli ifade karakteri yok; kaçışsız ama zararsız |
| `analyzers/assembly_analyzer.py:299`, `:308`, `:330` | `instr` (`SSE_` / `AVX_` / `CRYPTO_INSTRUCTIONS`) | modül sabiti komut adları; aynı |
| `analyzers/anti_debug_detector.py:1994` | `min_run` (`%d`) | tamsayı; zararsız |
| `analyzers/packer_fingerprint.py:287` | `parts` (`b"".join`) | işlev içinde kurulan bayt kalıbı; içeriğe bakılmadı |
| `analyzers/binary_intelligence.py:1683` | `f"(?:{s})"`, `s` = gösterge kaynakları (`_indicator_source`) | bilerek düzenli ifade parçası (kural tablosundan); tek tek de derleniyor (taranamayan 1682); içe aktarma anında derlenmediği için ek taramaya da girmedi → **taranmadı** |
| `reconstruction/engineering/semantic_namer.py:1575` | `t` (`[A-Za-z_]\w*(?:\s+[A-Za-z_]\w*)*` ya da kaçışlı tip listesi) | bilerek düzenli ifade parçası; ayırıcılı yineleme (`\s+`), güvenli sınıfta |

Dış girdiden kalıp derleyen yer (not): `yara_scanner.py:372` / `:1591` YARA kuralının düzenli ifadesini Python `re` ile derliyor; kural dosyası üçüncü taraftan gelirse üstel kalıp taşıyabilir, statik kapı bunu göremez.

## Kalem 4 — genişletilmiş tarama (hüküm 4, H5) (13:24 – 13:43)

- Kapsam `karadul/` tamamı + `ui/server.py` (BA-1: `reconstruction/` + `pipeline/steps/`). Sabit kalıp **1 509** (BA-1 kapsamında 1 073), derlenemeyen 0; durağan aday 61 kalıp (iç içe 61, örtüşen seçenek 8, kesişimli), zincir 138.
- **H5: yeni üstel kalıp 0** (ilk ölçüm). Kapının hızlı doğrulaması da güçlü girdiyle sınıflama da 0 üstel; şablonlar ve içe aktarma anı taraması da 0. Onarılacak ya da yama bırakılacak dosya çıkmadı: **yama 0**. "Dokunma" listesindeki dosyalar (`block_annotator.py` dahil) tarandı, bulgu yok.
- BA-1 kapsamı dışından gelen 22 aday: polinom 8 (`analyzers/bindiff.py:98`, `analyzers/go_demangler.py:125`, `analyzers/java_binary.py:760`, `analyzers/python_binary.py:117`, `analyzers/signature_db.py:426`, `quality/metrics/local_vars.py:95`, `quality/metrics/type_quality.py:86`, `:94`); güvenli 14 (`go_binary.py` 73 / 82 / 547, `go_demangler.py` 87 / 111, `java_binary.py` 83 / 88, `dotnet_binary.py:874` (sınırda), `signature_db.py:3397`, `swift_binary.py` 84 / 87 / 102, `deobfuscators/string_decryptor.py:105`, `anti_debug_detector.py:389` (bytes)).

## Polinom listesi — gerçek veride en kötü süre (hüküm 2 / 7) (13:34 – 13:47)

Araç `ozet/polinom_gercek.py` (her kalıp ayrı çocuk süreçte, 20 sn ilerleme bekçisi; hiçbiri kesilmedi). Derlem: S8'in 8 çalışma alanı (`urun-onarim-a62f15e`) + Ollama (`ANA/ollama_ustveri`); dört birim: `deobfuscated/decompiled/*.c` satırları (`strip`), aynı dosyaların tam içeriği, `ghidra_strings.json` dizgileri, işlev adları. Kalıbın üründe hangi birime uygulandığına bakılmadı, dördü de denendi: **üst sınır**. Yük altında (load 17–34). Ham `ozet/polinom_gercek.json` (+ `_ek`: `semantic_namer.py:389`, üçüncü sınıflama koşusunda polinoma geçtiği için ayrıca).

| kalıp | satır | dosya | dizgi | ad |
|---|---:|---:|---:|---:|
| `analyzers/bindiff.py:98` | 0,40 ms | 3,1 ms | 6,0 ms | 0,02 ms |
| `analyzers/go_demangler.py:125` | 0,30 ms | 0,02 ms | 0,01 ms | 0,01 ms |
| `analyzers/java_binary.py:760` | 1,2 ms | 16 ms | 14 ms | 0,01 ms |
| `analyzers/python_binary.py:117` | 48 ms | **1,04 sn** | **10,3 sn** | 9,5 ms |
| `analyzers/signature_db.py:426` | 1,5 ms | 16 ms | 37 ms | 0,04 ms |
| `quality/metrics/local_vars.py:95` | 1,8 ms | 0,2 ms | 7,4 ms | 0,12 ms |
| `quality/metrics/type_quality.py:86` | 0,8 ms | 0,2 ms | 3,1 ms | 0,03 ms |
| `quality/metrics/type_quality.py:94` | 1,5 ms | 1,4 ms | 6,9 ms | 0,02 ms |
| `reconstruction/binary_name_extractor.py:185` | 3,4 ms | 3,1 ms | 14 ms | 0,06 ms |
| `reconstruction/binary_name_extractor.py:2745` | 0,22 ms | 52 ms | 6,8 ms | < 0,01 ms |
| `reconstruction/binary_name_extractor.py:2752` | 0,10 ms | 78 ms | 6,4 ms | 0,02 ms |
| `reconstruction/binary_name_extractor.py:2759` | 0,65 ms | 77 ms | 2,6 ms | < 0,01 ms |
| `reconstruction/c_flow_simplifier.py:147` | 9,6 ms | 5,1 ms | 30 ms | 0,02 ms |
| `reconstruction/c_namer.py:1503` | 0,12 ms | 3,0 ms | 5,5 ms | < 0,01 ms |
| `reconstruction/c_type_recoverer.py:440` | 0,24 ms | 0,01 ms | 0,02 ms | 0,01 ms |
| `reconstruction/engineering/semantic_namer.py:389` | 42 ms | 0,94 sn | **10,8 sn** | 0,04 ms |
| `reconstruction/engineering/struct_recovery.py:713` | 0,36 ms | 0,19 ms | 0,39 ms | < 0,01 ms |
| `reconstruction/engineering/struct_recovery.py:724` | 0,11 ms | 1,3 ms | 0,39 ms | < 0,01 ms |
| `reconstruction/engineering/struct_recovery.py:737` | 0,49 ms | 1,9 ms | 0,38 ms | < 0,01 ms |
| `reconstruction/engineering/struct_recovery.py:748` | 0,26 ms | 0,64 ms | 0,41 ms | 0,01 ms |
| `reconstruction/engineering/struct_recovery.py:777` | 0,23 ms | 0,10 ms | 6,0 ms | 0,01 ms |
| `reconstruction/recovery_layers/formula_extractor.py:2430` | 15 ms | 0,33 sn | **4,05 sn** | 0,04 ms |
| `reconstruction/string_intelligence.py:102` | 4,3 ms | 0,17 sn | **5,2 sn** | 0,01 ms |
| `reconstruction/string_intelligence.py:110` | 0,07 ms | 2,5 ms | 1,1 ms | 0,01 ms |
| `reconstruction/xtride_typer.py:633` | 0,57 ms | 1,2 ms | 5,8 ms | 0,01 ms |

**> 1 sn olanlar (ayrıca işaret; onarım bu paketin kapsamı dışında):** dördü de aynı girdide: Ollama'nın `ghidra_strings.json`'ındaki **1 352 968 karakterlik tek dizgi**.
- `analyzers/python_binary.py:117` (`_PYC_MODULE_PATTERN`) — dizgide 10,3 sn, en büyük C dosyasında 1,04 sn. Üründe `_extract_embedded_modules` bu kalıbı **ikilinin tamamının** `ascii` çözülmüş metnine `finditer` ile uyguluyor: gerçek girdi bu derlemdeki her birimden büyük. Bu yolun Python ikilisi olmayan bir hedefte çağrılıp çağrılmadığı ölçülmedi.
- `reconstruction/string_intelligence.py:102` (C++ assert biçimi) — dizgide 5,2 sn. Bu modülün birimi zaten ikili dizgileri: **gerçek kullanımda erişilebilir** (çağrı yolu ölçülmedi).
- `reconstruction/engineering/semantic_namer.py:389` — dizgide 10,8 sn, tam C dosyasında 0,94 sn; üründeki birim C bildirimi (satır: 42 ms).
- `reconstruction/recovery_layers/formula_extractor.py:2430` (Horner) — dizgide 4,05 sn, tam C dosyasında 0,33 sn; üründeki birim C kodu.

Ayrıca yüksek dereceli (düşmanca girdide kübik ve üstü): `binary_name_extractor.py` 2745 (800 karakterde 2,2 sn), 2752 / 2759 (800 karakterde > 3 sn); gerçek veride en kötü 52 / 78 / 77 ms (Ollama'nın 212 KB'lık C dosyası).

## Hipotezler (ön kayıt `17b415a3`; eşikler değişmedi)

| H | ön kayıt | ölçülen | sonuç |
|---|---|---|---|
| H1 | iki kalıbın BA-1 düşmanca girdileri ≤ 0,1 sn | `_ZN` 3,6 µs (eski: 28 tekrarda 5 sn'de bitmedi), `_LINKED_LIST_RE` 6,5 µs (eski: 30 karakterde 1,60 sn) | **TUTTU** |
| H2 | gerçek girdide eski ↔ yeni farklı 0; her kalıp ≥ 200 girdi ya da "N kez denendi" | `_LINKED_LIST_RE`: 80 537 dosya, farklı 0; `_ZN`: gerçek veride 0 kez denendi (çağıranın koşulunu geçen ad 0) | **TUTTU** |
| H3 | S8 8 ikili ad haritası önce ↔ sonra bayt eşit 8 / 8 | 8 / 8 | **TUTTU** |
| H4 | 39 adaydan üstel (ilk ölçüm) | 0 (polinom 17, güvenli 22, doğrulanamadı 0) | ilk ölçüm |
| H5 | genişletilmiş taramada yeni üstel (ilk ölçüm) | 0 (1 509 sabit + 118 şablon + 4 195 içe aktarma anı kalıbı) | ilk ölçüm |
| H6 | kapı testi ≤ 60 sn; istisna listesi boş | 5,2 sn (ağır yükte 20,5 sn); istisna 0 | **TUTTU** |

## Ana oturumun bilmesi gerekenler

- **GS-1 için:** statik kapı yalnız `re.` ile derlenen ve AST'de ya da içe aktarma anında görülen kalıpları kapsar. Görmediği üç sınıf: (1) çalışma anında dış girdiden derlenen kalıp (`yara_scanner.py:372` / `:1591`, `lm/protocol.py:324` şema `pattern`'i); (2) işlev içinde kurulup değişkenle geçirilen kalıp (taranamayan 28, özellikle `binary_intelligence.py` gösterge kaynakları); (3) polinom kalıbın çok büyük girdide uzun sürmesi (yukarıdaki dört > 1 sn; 1,35 MB'lık tek dizgi). Bu üçü için tek koruma süreç dışı kesme (A-36 katman 3). SIGTERM davranışı bu pakette ölçülmedi (bu paketin bütün kesmeleri SIGKILL). GS-1'in kesme ölçümü için hazır, Ghidra'sız bir uzun eşleşme girdisi: Ollama'nın 1,35 MB'lık dizgisi + `python_binary.py:117` (≈ 10 sn, yük altında).
- **HZ-7a için:** `c_namer.py`'de bu paket yalnız `_try_demangle_cpp`'deki kalıp satırına dokundu (3441 → 3445, dört satır yorum); `_strategy_dataflow` / `_strategy_local_var_naming`'e dokunulmadı. `c_namer.py:1503` (yerel bildirim kalıbı; polinom, gerçek veride en kötü 5,5 ms) HZ-7a'nın değiştirebileceği bölgeye yakınsa kapı (`tests/test_kalip_denetimi.py`) yeni yazımı denetler.
- `_ZN` kalıbı gerçek veride hiç denenmedi (Ghidra C++ adlarını çözülmüş veriyor; 120 çalışma alanında `_Z` ile başlayan işlev adı 0). Onarım yine de doğru (eşdeğerlik ve süre sınamalarıyla), ama `_try_demangle_cpp` bugün ölü yol olabilir: ölçülmedi.
- Kapıya yeni üstel kalıp eklenirse tam takım kırmızı olur; yanlış alarmda kalıp `ISTISNALAR`'a gerekçe ve ölçülen süreyle girer, `tests/test_kalip_denetimi.py`'deki `BEKLENEN_ISTISNA_SAYISI` birlikte artar.
- Kapı Python'un iç modüllerini (`re._parser`, `re._constants`) kullanıyor: Python iç değişikliğinde test kırılabilir (ürün değil).
- Sınıflama ölçüme dayalı ve yük altında: üç koşuda iki aday sınırda gidip geldi (`semantic_namer.py:389`, `dotnet_binary.py:874`). Kapının üstel ölçütü (40 → 80'de 64 kat ya da 1 sn ya da bekçi) ile polinom arasındaki boşluk geniş; kapı kararı bu kararsızlıktan etkilenmedi (beş bilinen kusurlu kalıp her koşuda üstel, onarılmışlar her koşuda değil).
- H3 için "sonra" kolu `git worktree add` yerine `urun-534e252b`'nin kopyası + bu dalın iki dosyasıyla kuruldu (`BA2/agac_sonra`; ajan izolasyonu dış yola git işlemini reddetti); `diff -rq` ile bu dalın `karadul/`'u ile aynı olduğu denetlendi.
- Takım tartışma dosyasına (`~/.claude/team-state/discussion.md`) yazılmadı: gönderim yalnız listelenen dosyalara yazma izni veriyor.
