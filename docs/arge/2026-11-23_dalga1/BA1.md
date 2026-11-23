# BA1 — BA-1: blok açıklama kalıplarında üstel geri izleme (ilerleme)

- Gönderim: `docs/arge/2026-11-23_dalga1/gonderim/BA1.md`
- Dal: `worktree-agent-a6cebf741f6009eac`; taban main `0b4d948` (ff-only, 19:35)
- Koşu kökü: `~/karadul_olcum/runs/dalga1-2026-11-23/BA1/`
- Sert son: 21:05

## Durum

- 19:36 başladı; belgeler okundu (ORTAK_D1 §5 dahil, ORTAK_D0, ONARIM_BRIF, KARARLAR A-17 / A-27 / A-35, DURUM "Ollama uçtan uca koşusu", ANA OZET).

## Kalem 1 — kusurun yeniden üretimi (19:40)

- Adımın girdisi: `capa_annotation_decompiled_dir` = `comment_generation`'ın çıktısı `reconstructed/commented/` (CAPA kod beslemesi K-1 gereği kapalı, dizin değişmeden geçer). Kusurlu dosya `…/ws/workspaces/Ollama/20261123_063359/reconstructed/commented/FUN_100295d40.c`, satır 211, `strip()` sonrası 89 karakter: `runtime_memmove(field_ptr_3,iVar14,status_2 << 3,ctx,i,status,accumulator,pbVar13,iVar14,` (çağrı satıra bölünmüş, kapanan ayraç yok). Dosya sıralı listede 7 311. sırada: eski koşunun yazdığı 7 310 dosyanın hemen ardından.
- Araç: `scripts/arge/ba1/kalip_sure.py satir <dosya> 211 --zaman-asimi 20` (her kalıp ayrı çocuk süreçte; `subprocess.run(timeout=…)` süre dolunca SIGKILL).
- Sonuç (eski kalıplar, main `0b4d948`; yük altında): `memcpy` 0,001 ms (eşleşme yok), `memset` 0,001 ms (eşleşme yok), **`memmove` 20 sn'de bitmedi (zaman aşımı, çocuk öldürüldü)**. Ham çıktı `~/karadul_olcum/runs/dalga1-2026-11-23/BA1/ozet/yeniden_uretim_eski.json`. Asılı süreç kalmadı (`pgrep` boş).
- Ön kayıt: `docs/arge/2026-11-23_dalga1/on_kayit_BA1.md`, commit `de86d08` (yeniden üretim `8ecd3d8`).

## Kalem 2 — onarım, birim testleri, mutasyon (19:46)

**Seçilen yazım: atomik grup.** `block_annotator.py` `MEMORY_PATTERNS` içindeki üç kalıpta üçüncü argümanın döngüsü `((?:[^()]+|\([^)]*\))+)` → `((?>(?:[^()]+|\([^)]*\))+))`. Başka hiçbir karakter değişmedi.

Gerekçe:
- Döngünün dili belirlenimli: ayraç dışındayken `(` ve `)` olmayan karakter tüketilir, `(` bir ayraç açar, açık ayraç ilk `)`'de kapanır (`[^)]*` `)` atlayamaz). Bir `)` tüketilmiş bölgede yalnız bir ayraç kapatıcısı olarak bulunabilir; döngü o `)`'nin hemen önünde duramaz (açan `(` kapatıcısı olmadan tüketilemez). Bu yüzden eski kalıbın geri izlemeyle bulabileceği tek başarılı eşleşme, döngünün açgözlü en uzun eşleşmesidir (ayraç dışındaki ilk `)`'ye kadar; sondaki boşluklar grupta kalır). Eski kalıptaki geri izleme yalnız `[^()]+` koşusunun 2^(n−1) bölünüşünü sonuçsuz deniyordu.
- Atomik grup tam bu sonuçsuz denemeleri keser, eşleşme kümesini değiştirmez: aynı başlangıçta aynı span, aynı üç grup. Döngünün dışındaki `\s*` geri izlemesi (örn. `memcpy(a,b, )` → üçüncü grup `" "`) atomik grubun dışında kaldığı için aynen korunur.
- Seçenekleri örtüşmeyecek biçimde yeniden yazmak (`(?:[^()]|\([^)]*\))+`, tek karakterlik yineleme) de üstelliği kaldırırdı ama her karakter için bir yineleme çerçevesi açar (yavaş) ve başarısızlıkta yine doğrusal geri izler; atomik grup en küçük değişiklik ve eşdeğerliği kanıtı en kısa olan. Proje `requires-python >= 3.11` (`pyproject.toml:10`), çalışma ortamı 3.12.7.
- Karmaşıklık: bir başlangıç konumunda döngü en çok bir kez açgözlü tarar (O(n)); başarısız `(` seçeneği `[^)]*` için O(n) geri döner, döngü o noktada biter. Arama yalnız `memcpy` / `memset` / `memmove` geçen konumlarda ilerler: toplam O(k·n) ≤ O(n²).

**H1 (ölçüldü, yük altında; 19:41, load 5,95):** gerçek satır (89 karakter) yeni kalıplarla: `memcpy` 0,002 ms, `memset` 0,002 ms, `memmove` **0,004 ms** (eşleşme yok; çocuk süreç duvar süresi 0,028 sn). Eşik ≤ 0,1 sn → **TUTTU**. Ham: `…/BA1/ozet/H1_yeni.json`.

**Büyüme (hüküm 2; `kalip_sure.py buyume`, her ölçüm ayrı süreç, yük altında):** kapanan ayraçsız satırlar; `tek` = gerçek satırın biçimi (tek çağrı, uzun argüman), `ic_ayrac` = içinde kapanmamış `(`, `yinelenen` = `memcpy(a,b,c ` tekrarı (her başlangıç satır sonuna kadar tarar; en kötü durum).

| n (karakter) | tek / memmove | ic_ayrac / memmove | yinelenen / memcpy |
|---:|---:|---:|---:|
| 100 | 0,003 ms | 0,004 ms | 0,005 ms |
| 1 000 | 0,006 ms | 0,004 ms | 0,053 ms |
| 10 000 | 0,027 ms | 0,013 ms | 2,841 ms |
| 100 000 | 0,246 ms | 0,102 ms | 283,6 ms |

`tek` / `ic_ayrac` doğrusal; `yinelenen` 10× uzunlukta ~100× (karesel, beklenen üst sınır). Üstel yok. (`yinelenen` girdisi yalnız `memcpy` adını taşıdığı için öbür iki kalıpta eşleşme başlangıcı yok; o satırlar 0,05 ms.) Ham: `…/BA1/ozet/buyume_yeni.json`.

**Testler:** `tests/test_ba1_blok_kalip_suresi.py`, 20 sınama (9 işlev; parametreli): gerçek satır + devam satırı ayrı süreçte; kapanan ayraçsız 1 000 / 10 000 / 100 000 karakter (üç ad, ayrı süreçte); ana oturumun 32 karakter eşiği (ayrı süreçte); iç içe ayraçlı geçerli çağrılar ve kenar durumlar eski kalıpla aynı span + grup (10 durum; önekli ad dahil, kural değişmedi); rastgele kısa satırlarda eski = yeni (3 × 1 500); `_detect_memory_ops` açıklama metni eski kalıplarla aynı; yapı denetimi (atomik grup dışında iç içe sınırsız yineleme yok, `re._parser` ağacı). Süre sınamaları `subprocess.run(timeout=15)`; eski kalıpla asılı kalmaz, kırmızı olur. İlgili takım: `test_ba1_blok_kalip_suresi.py` + `test_p04a_blok_yorumu.py` + `test_step_engineering_annotation.py` → 30 geçti / 0 kaldı.

Commit: `09060ad`.

**Mutasyon:** `scripts/measurement/mutation_specs_ba1.json`, 7 mutant (üçü eski kalıbın geri konması: memmove / memcpy / memset; ayraç içi daralma; ayraçlı seçeneğin düşmesi; boş üçüncü argüman; atomik grubun kalkması) → **7 / 7 öldü**, toplam süre **54 sn** (üç zaman aşımı × 15 sn dahil). Sonra `git diff` yalnız onarım.

## Kalem 4a — Ghidra'sız yeniden oynatma, Ollama (H2, H3) (19:47)

**Girdi / çıktı (`karadul/pipeline/steps/engineering_annotation.py`'den çıkarıldı):** `CodeBlockAnnotator(config).annotate(decompiled_dir=capa_annotation_decompiled_dir, functions_json=functions_json_path, call_graph_json=call_graph_json_path, output_dir=reconstructed/annotated, algorithm_matches=_collect_all_algorithms(algo_result, eng_result))`.
- `capa_annotation_decompiled_dir` = `reconstructed/commented/` (`capa_annotation` dizini değiştirmeden geçirir; CAPA kod beslemesi K-1 gereği kapalı).
- `functions_json_path` / `call_graph_json_path` = `ghidra_metadata._resolve_json_paths`: önce `deobfuscated/`, yoksa `static/` (`ghidra_functions.json`, `ghidra_call_graph.json`).
- `algo_result` / `eng_result`: `reconstructed/algorithms.json` (yalnız `success` iken yazılır) + `reconstructed/engineering_algorithms.json` (`success` alanı). `algorithms.json` `detection_method` / `address` taşımaz; bu iki alan yalnız başlık kutusu kategorilerinde (`_ALGORITHM_HEADER_CATEGORIES`) çıktıya girer. Ollama'da 2 algoritma (`hash`), başlık kategorisinde 0 → kayıp yok.
- `config` adımda yalnız `CodeBlockAnnotator.__init__`'te saklanıyor, hiçbir dedektörde okunmuyor; yeniden oynatmada `None`.
- Çıktı: her `*.c` (açıklamalı ya da değişmeden kopya) + `block_annotations.json`. Çıktıda zaman, rastgelelik, süreç kimliği yok (`block_annotator.py`'de `time` / `random` / `datetime` kullanımı yok; dosya sırası `sorted(rglob)`): karşılaştırmada ayrılan alan yok, tam bayt karşılaştırması.
- Araçlar: `scripts/arge/ba1/yeniden_oynat.py` (ayrı çocuk süreç + zaman aşımı; her dosyaya başlarken `ilerleme.txt`; dosya başına süre `_extract_functions` çağrı damgalarından), `scripts/arge/ba1/cikti_karsilastir.py`. Çıktı `~/karadul_olcum/runs/dalga1-2026-11-23/BA1/ollama_yeni/` (çalışma alanına yazılmadı).

**H2 (yük altında; başta load 5,48, sonda 6,13):** 13 554 / 13 554 dosya işlendi ve yazıldı, toplam **61,9 sn** (çocuk süreç duvarı 62,5 sn), en uzun tek dosya **0,70 sn** (`FUN_1002c6eb0`; sonraki 0,29 / 0,28 / 0,27 / 0,25 sn). Eşikler ≤ 300 sn ve ≤ 5 sn → **TUTTU**. 8 981 açıklama (`loop_purpose` 8 585, `memory_op` 396); hata 0. Ham: `…/BA1/ollama_yeni/zamanlama.json`.

**H3:** eski koşunun yazdığı 7 310 dosyanın (`ANA/ollama_ustveri/ws/…/reconstructed/annotated/`, ürün ağacı `urun-d2134d5`; `block_annotator.py` `d2134d5` ile `0b4d948` arasında değişmemiş) **7 310 / 7 310**'u yeni çıktıyla bayt eşit, farklı 0, eksik 0 → **TUTTU**. Ayrılan alan yok (yukarıda). Yeni çıktının tamamı 13 555 dosya (13 554 `.c` + `block_annotations.json`), dizin özeti sha256 `ba1fb761e227…`. Ham: `…/BA1/ozet/H3_karsilastirma.json`.

## Kalem 4b — Ghidra'sız yeniden oynatma, S8 (H4) (19:49)

S8'in 8 çalışma alanı (`P16e/s8_sonra_3`, ürün ağacı `urun-00b8a9c`; `block_annotator.py` `00b8a9c` ile `0b4d948` arasında değişmemiş), her birinde adım iki kez yeniden oynatıldı: eski kod (`git show 0b4d948:…/block_annotator.py` kopyası, `…/BA1/eski_kod/block_annotator_eski.py`) ve yeni kod; ayrıca yeni çıktı çalışma alanının kendi `reconstructed/annotated/`'ı ile karşılaştırıldı (yeniden oynatmanın ürün yoluna sadakati). Sürücü `…/BA1/s8_kos.sh`; ham `…/BA1/s8/<ad>/{eski_yeni,ws_yeni}.json`, `…/zamanlama.json`. Yük altında (load 5,27 → 5,62).

| çalışma alanı | dosya (`.c` + rapor) | eski ↔ yeni bayt eşit | ws ↔ yeni bayt eşit | açıklama (eski / yeni) | süre eski / yeni (sn) |
|---|---:|---:|---:|---:|---:|
| debian/coreutils/cat | 297 | 297 / 297 | 297 / 297 | 54 / 54 | 0,34 / 0,12 |
| debian/coreutils/sort | 626 | 626 / 626 | 626 / 626 | 213 / 213 | 0,85 / 0,35 |
| debian/htop | 1 149 | 1 149 / 1 149 | 1 149 / 1 149 | 374 / 374 | 1,64 / 0,76 |
| debian/sqlite3 | 1 145 | 1 145 / 1 145 | 1 145 / 1 145 | 554 / 554 | 1,55 / 0,67 |
| debian/tmux | 2 589 | 2 589 / 2 589 | 2 589 / 2 589 | 1 720 / 1 720 | 4,31 / 2,21 |
| debian/tree | 251 | 251 / 251 | 251 / 251 | 148 / 148 | 0,28 / 0,17 |
| debian/zstd | 1 445 | 1 445 / 1 445 | 1 445 / 1 445 | 1 161 / 1 161 | 3,75 / 2,16 |
| mac/tmux | 2 822 | 2 822 / 2 822 | 2 822 / 2 822 | 1 938 / 1 938 | 4,86 / 2,49 |

**H4: 8 / 8 bayt eşit → TUTTU** (`block_annotations.json` dahil; ayrılan alan yok). Yeni çıktı çalışma alanının kendi çıktısıyla da 8 / 8 eşit: yeniden oynatma ürün yolunu birebir veriyor (algoritma girdisi: sqlite3'te 7, zstd'de 2 algoritma, başlık kategorisinde 0). Yan gözlem (yük altında, tek koşu): yeni kod adımı eskisinden ~1,7–2,8 kat hızlı bitirdi; eski kalıp eşleşmeyen sıradan satırlarda da bölünüş deniyordu.

## Kalem 2 eki — eşdeğerlik, gerçek satırlarda (19:52)

Araç `scripts/arge/ba1/esdeger_ve_onek.py` (eski ve yeni kalıp ayrı çocuk süreçlerde; çocuk her sonucu bir satır yazar, ebeveyn 2 sn ilerleme görmezse SIGKILL ile öldürür, satırı `zaman aşımı` diye işaretler, sonrakinden sürdürür) + `scripts/arge/ba1/esdeger_tablo.py`. Girdi: Ollama ve S8'in 8 çalışma alanında adımın girdisi `reconstructed/commented/*.c`; `memcpy` / `memset` / `memmove` geçen ve `strip()` sonrası `//` ya da `/*` ile başlamayan her satır (adımın atladığı satırlar atlandı), her (satır, ad) çifti için o adın kalıbı. Satır metni depoya girmez (üçüncü taraf kodundan çıkarılmış adlar); tam döküm `…/BA1/esdeger/esdeger_dokum.json`.

**Bütün çiftler:** 2 855 (satır, ad) çifti (Ollama 1 643; S8: cat 34, sort 70, htop 79, sqlite3 154, debian tmux 198, tree 24, zstd 464, mac tmux 189). Eski kalıbın 2 sn içinde bittiği 2 854 çiftin **2 854'ünde yeni sonuç eskiyle aynı** (span + üç grup; 794'ünde eşleşme var, Ollama 453). Eski kalıp yalnız 1 çiftte zaman aşımına uğradı: Ollama `FUN_100295d40.c:211` (kusurlu satır); yeni kalıp orada eşleşme bulmadı (0,001 ms). Farklı sonuç 0. Toplam duvar süresi: yeni 0,8 sn, eski 2,1 sn (1 zaman aşımı dahil). Ham özet `…/BA1/esdeger/esdeger_ozet.json`.

Not (sayım kapsamı): ana oturumun "1 262 dosya / 3 631 satır" sayısı `grep -E '(memcpy|memset|memmove)\('` ile, yorum satırları dahil (bu dizinde 1 272 dosya, 3 631 satır; bunların 2 144'ü `/* INLINE: memcpy() — … */` yorumu, adım bunları atlar). Adımın gerçekten kalıba verdiği kod satırı 1 641 (çift 1 643).

**Eşdeğerlik tablosu (44 gerçek satır; seçim belirlenimli, ölçüt `esdeger_tablo.py` başlığında):**

| # | çalışma alanı | dosya:satır | ad | uzunluk | eski sonuç | yeni = eski | eski süre | yeni süre |
|---:|---|---|---|---:|---|---|---:|---:|
| 1 | ollama | FUN_10000bd60.c:102 | memmove | 60 | eşleşti (grup uzunlukları 5/5/30) | evet | 0.002 ms | 0.002 ms |
| 2 | ollama | FUN_100015a80.c:79 | memmove | 37 | eşleşti (grup uzunlukları 11/3/3) | evet | 0.001 ms | 0.001 ms |
| 3 | ollama | FUN_100015a80.c:112 | memmove | 39 | eşleşti (grup uzunlukları 9/5/5) | evet | 0.001 ms | 0.001 ms |
| 4 | ollama | FUN_1000179b0.c:72 | memmove | 47 | eşleşti (grup uzunlukları 9/7/11) | evet | 0.001 ms | 0.001 ms |
| 5 | ollama | FUN_100017c70.c:216 | memmove | 37 | eşleşti (grup uzunlukları 1/11/5) | evet | 0.001 ms | 0.001 ms |
| 6 | ollama | FUN_10001b390.c:281 | memmove | 46 | eşleşti (grup uzunlukları 8/5/13) | evet | 0.001 ms | 0.001 ms |
| 7 | ollama | FUN_10001d7e0.c:51 | memmove | 35 | eşleşti (grup uzunlukları 5/7/3) | evet | 0.000 ms | 0.001 ms |
| 8 | ollama | FUN_1000361d0.c:107 | memmove | 48 | eşleşti (grup uzunlukları 5/7/16) | evet | 0.001 ms | 0.001 ms |
| 9 | ollama | FUN_1000410a0.c:150 | memmove | 50 | eşleşti (grup uzunlukları 6/11/13) | evet | 0.001 ms | 0.001 ms |
| 10 | ollama | FUN_1000410a0.c:168 | memmove | 47 | eşleşti (grup uzunlukları 6/11/10) | evet | 0.001 ms | 0.001 ms |
| 11 | ollama | FUN_100001a90.c:131 | memmove | 56 | eşleşme yok | evet | 0.002 ms | 0.004 ms |
| 12 | ollama | FUN_100001a90.c:146 | memmove | 70 | eşleşme yok | evet | 0.001 ms | 0.002 ms |
| 13 | ollama | FUN_100001a90.c:175 | memmove | 50 | eşleşme yok | evet | 0.001 ms | 0.001 ms |
| 14 | ollama | FUN_100001a90.c:192 | memmove | 96 | eşleşme yok | evet | 0.001 ms | 0.001 ms |
| 15 | ollama | FUN_1000033b0.c:63 | memmove | 62 | eşleşme yok | evet | 0.001 ms | 0.000 ms |
| 16 | ollama | FUN_1000033b0.c:77 | memmove | 94 | eşleşme yok | evet | 0.000 ms | 0.000 ms |
| 17 | ollama | FUN_100295d40.c:211 | memmove | 89 | zaman aşımı | — | > 2 sn | 0.001 ms |
| 18 | ollama | _sqlite3_serialize.c:22 | memcpy | 146 | eşleşme yok | evet | 0.000 ms | 0.000 ms |
| 19 | ollama | FUN_1004f5b00.c:18 | memcpy | 144 | eşleşme yok | evet | 0.000 ms | 0.000 ms |
| 20 | ollama | FUN_1004f7154.c:18 | memcpy | 127 | eşleşme yok | evet | 0.000 ms | 0.000 ms |
| 21 | cat | FUN_001025e0.c:566 | memmove | 24 | eşleşti (grup uzunlukları 4/5/3) | evet | 0.002 ms | 0.000 ms |
| 22 | cat | FUN_00107664.c:29 | memcpy | 24 | eşleşti (grup uzunlukları 6/3/4) | evet | 0.001 ms | 0.000 ms |
| 23 | cat | FUN_00105b70.c:22 | memset | 106 | eşleşme yok | evet | 0.001 ms | 0.000 ms |
| 24 | sort | FUN_00108cd0.c:52 | memcpy | 23 | eşleşti (grup uzunlukları 6/3/3) | evet | 0.001 ms | 0.001 ms |
| 25 | sort | FUN_0010ac40.c:110 | memmove | 46 | eşleşti (grup uzunlukları 10/13/11) | evet | 0.001 ms | 0.001 ms |
| 26 | sort | FUN_00104020.c:801 | memcpy | 42 | eşleşme yok | evet | 0.000 ms | 0.001 ms |
| 27 | htop | FUN_00118564.c:91 | memcpy | 32 | eşleşti (grup uzunlukları 13/5/3) | evet | 0.000 ms | 0.000 ms |
| 28 | htop | FUN_00128f50.c:40 | memcpy | 44 | eşleşti (grup uzunlukları 11/5/17) | evet | 0.001 ms | 0.001 ms |
| 29 | htop | CommandLine_run.c:20 | memcpy | 121 | eşleşme yok | evet | 0.000 ms | 0.000 ms |
| 30 | sqlite3 | FUN_0010da00.c:40 | memset | 19 | eşleşti (grup uzunlukları 1/1/6) | evet | 0.001 ms | 0.000 ms |
| 31 | sqlite3 | FUN_0010ecec.c:47 | memset | 78 | eşleşti (grup uzunlukları 3/1/29) | evet | 0.001 ms | 0.001 ms |
| 32 | sqlite3 | FUN_001097c0.c:163 | memset | 30 | eşleşme yok | evet | 0.000 ms | 0.000 ms |
| 33 | tmux_debian | FUN_001253e0.c:253 | memcpy | 23 | eşleşti (grup uzunlukları 6/5/1) | evet | 0.000 ms | 0.000 ms |
| 34 | tmux_debian | FUN_0012da48.c:48 | memcpy | 25 | eşleşti (grup uzunlukları 6/5/3) | evet | 0.000 ms | 0.000 ms |
| 35 | tmux_debian | FUN_001230e0.c:18 | memcpy | 43 | eşleşme yok | evet | 0.000 ms | 0.000 ms |
| 36 | tree | FUN_00104100.c:108 | memset | 32 | eşleşti (grup uzunlukları 3/1/17) | evet | 0.001 ms | 0.000 ms |
| 37 | tree | FUN_00104100.c:237 | memcpy | 40 | eşleşti (grup uzunlukları 5/7/9) | evet | 0.001 ms | 0.001 ms |
| 38 | tree | FUN_00104100.c:20 | memset | 112 | eşleşme yok | evet | 0.000 ms | 0.000 ms |
| 39 | zstd | FUN_0010a480.c:63 | memset | 35 | eşleşti (grup uzunlukları 1/1/22) | evet | 0.001 ms | 0.001 ms |
| 40 | zstd | FUN_0010c180.c:72 | memset | 16 | eşleşti (grup uzunlukları 3/1/1) | evet | 0.000 ms | 0.000 ms |
| 41 | zstd | FUN_0010a480.c:23 | memcpy | 56 | eşleşme yok | evet | 0.000 ms | 0.000 ms |
| 42 | tmux_mac | FUN_100007450.c:458 | memcpy | 21 | eşleşti (grup uzunlukları 3/5/1) | evet | 0.001 ms | 0.000 ms |
| 43 | tmux_mac | FUN_10000ff88.c:37 | memcpy | 23 | eşleşti (grup uzunlukları 3/7/1) | evet | 0.001 ms | 0.000 ms |
| 44 | tmux_mac | FUN_10000672c.c:18 | memcpy | 46 | eşleşme yok | evet | 0.000 ms | 0.000 ms |

44 satır.

Süreler tek eşleşmenin çocuk süreç içi süresi (yük altında); 17. satırda eski kalıp 2 sn bekçisiyle öldürüldü.

## Kalem 5a — önekli ad sayımı (hüküm 5; kod değişmedi) (19:52)

Yöntem: yeni kalıbın eşleştiği her kod satırında (satır başına bir kez, `MEMORY_PATTERNS` sırasıyla memcpy → memset → memmove) eşleşmenin başladığı adın önünde aynı tanımlayıcıya ait `\w` karakterleri: boş = çıplak, `_` = tek alt çizgi, başka = önekli. Kaynak `esdeger_ozet.json` → `onekli_ad`.

| çalışma alanı | eşleşen satır | çıplak | tek alt çizgi (`_memcpy(`) | başka önekli | en sık önekler | ad dağılımı (memcpy / memset / memmove) |
|---|---:|---:|---:|---:|---|---|
| **Ollama** | **453** | **0** | **236** | **217** | `runtime_` 217 (tek önek) | 227 / 6 / 220 |
| debian cat | 13 | 13 | 0 | 0 | — | 8 / 2 / 3 |
| debian sort | 14 | 14 | 0 | 0 | — | 9 / 2 / 3 |
| debian htop | 20 | 20 | 0 | 0 | — | 7 / 11 / 2 |
| debian sqlite3 | 49 | 49 | 0 | 0 | — | 17 / 29 / 3 |
| debian tmux | 50 | 50 | 0 | 0 | — | 29 / 18 / 3 |
| debian tree | 11 | 11 | 0 | 0 | — | 8 / 3 / 0 |
| debian zstd | 149 | 149 | 0 | 0 | — | 62 / 52 / 35 |
| mac tmux | 35 | 0 | 35 | 0 | — | 24 / 10 / 1 |

Okuma: Mach-O'da libc adı Ghidra'da `_memcpy` biçiminde (Ollama 236, mac tmux 35); Ollama'da öbür 217 eşleşme Go çalışma zamanının kendi işlevi `runtime_memmove` (libc çağrısı değil; açıklama "Move memory" diyor, anlam olarak yakın ama çağrılan işlev farklı). `__memcpy_chk` gibi `_chk` sonekli adlar `memcpy\s*\(` ile eşleşmez (ad `memcpy`'den sonra `_chk` sürdüğü için). Karar ana oturumda; kod değişmedi.

## Kalem 5b — envanter: `karadul/reconstruction/` + `karadul/pipeline/steps/` (hüküm 6b; onarım YOK) (19:53)

Araç `scripts/arge/ba1/kalip_tara.py tara` (yöntem dosyanın başında; özet):
1. **Toplama (AST):** `re.compile / search / match / fullmatch / findall / finditer / sub / subn / split` çağrılarının sabit (ya da sabitlerin `+` birleşimi) kalıp dizgisi + `re.X` bayrakları. Sabit olmayan kalıp "dinamik" sayılır, taranmaz.
2. **Durağan sınıflama (`re._parser` ağacı):** `ic_ice` = atomik grup / sahiplenici niceleyici dışında sınırsız yineleme gövdesinde sınırsız yineleme; `ortusen_secenek` = sınırsız yineleme gövdesinde ilk karakter kümeleri kesişen iki seçenek; `zincir` = aynı dizide kümeleri kesişen ve aradaki düğümleri ilkinin yutabildiği iki ya da daha çok sınırsız yineleme (polinom adayı).
3. **Devingen doğrulama** (yalnız `ic_ice` / `ortusen_secenek` adayları; her ölçüm ayrı çocuk süreç, 5 sn zaman aşımı): önek = dış yinelemeye götüren alt kalıbın en kısa tanığı; pompa = dış yineleme gövdesinin tanığı / iç yinelemenin tek karakteri / kesişen seçeneklerin ortak karakteri; sonek = küçük n'de eşleşmeyi bozan ilk karakter (`!`, satır sonu, boş, `(`, `)`, `\x00` …). Pompa 8, 12, …, 32 kez. **Üstel** = zaman aşımı ya da ≥ 1 sn ya da +4 pompada ≥ 8 kat (≥ 10 ms).
4. **Duyarlılık denetimi:** aynı araç BA-1 öncesi `block_annotator.py` kopyasında üç eski bellek kalıbını üstel buldu (pozitif kontrol), onarılmış dosyada 0.

Sınır: pompa üreteci sezgisel; üretemediği düşmanca girdi biçimleri olabilir (aşağıda "kurulamadı" ve "doğrulanmadı" listesi). Dinamik (sabit olmayan) 113 kalıp taranmadı.

**Sayım (H6):** 1 073 sabit kalıp (dinamik 113, derlenemeyen 0); `ic_ice` adayı 41, `ortusen_secenek` adayı 5 (kesişimli; toplam 41 kalıp), `zincir` 111. **Devingen doğrulanan üstel: 2.** Hepsi `karadul/reconstruction/` altında; `karadul/pipeline/steps/`'te aday çıkmadı. Ham `…/BA1/ozet/envanter.json`.

**Üstel kalıplar (sonraki paketin girdisi):**

| dosya:satır | kalıp | en kısa düşmanca girdi (bulunan) | ölçülen süre (ayrı süreç, yük altında) | not |
|---|---|---|---|---|
| `karadul/reconstruction/c_namer.py:3436` | `_ZN(\d+\w+)+E` (`re.match`) | `"_ZN" + "0a" * 28 + "!"` (60 karakter) | n = 8 / 12 / 16 / 20 / 24 / 28 pompa: 0,02 ms / 0,21 ms / 3,4 ms / 53 ms / 0,83 sn / **> 5 sn (zaman aşımı)** | `\d+` ⊂ `\w+` (rakam ikisinde de); her 4 pompada ~16 kat. C++ ad çözücü sezgisi; `E` içermeyen uzun `_ZN…` girdisinde. Gerçek girdide erişilebilirliği ölçülmedi |
| `karadul/reconstruction/recovery_layers/constraint_solver.py:271` (`_LINKED_LIST_RE`) | `…(?P<type>[a-zA-Z_](?:\w+\s*)*\*{0,2})…` | `"a=*(a" + "a" * 24 + "!"` (30 karakter) | n = 8 / 12 / 16 / 20 / 24: 0,03 ms / 0,29 ms / 4,6 ms / 73 ms / **1,13 sn** | `(?:\w+\s*)*`: `\s*` boş olabildiği için `\w+` koşusu her bölünüşle denenir. Satırdaki yorum (v1.7.6) bu yazımı "geri izlemeyi sınırlar" diye tanıtıyor; ölçüm tersini gösteriyor. Gerçek girdide erişilebilirliği ölçülmedi |

Doğrulanamayan adaylar (39; pompayla n = 32'de süre < 1 ms, ya da girdi kurulamadı — üstel olmadıkları KANITLANMADI, yalnız bu yöntemle bulunamadı): `r/` = `karadul/reconstruction/`: `r/binary_name_extractor.py:185`, `:2745`, `:2752`, `:2759`; `r/c_flow_simplifier.py:147`; `r/c_namer.py:1503`, `:934`; `r/c_type_recoverer.py:440`, `:543`, `:129`, `:239`; `r/engineering/semantic_namer.py:332`, `:369`, `:384`, `:389`, `:1777`; `r/engineering/struct_recovery.py:713`, `:724`, `:737`, `:748`, `:777`; `r/recovery_layers/formula_extractor.py:2430`; `r/reference_differ.py:139` (girdi kurulamadı); `r/string_intelligence.py:102`, `:110`, `:115` (kurulamadı), `:121` (kurulamadı), `:128`, `:142` (kurulamadı), `:216`, `:242`, `:291`, `:300`, `:306`, `:317`, `:1061`; `r/tarif/alt_kanal.py:140`, `:439`; `r/xtride_typer.py:633`. Elle bakış (ölçüm değil): kurulamayan dördü ayırıcılı yineleme (`\w+(?:::\w+)*`, `\d+(?:\.\d+)*`), belirsizlik görünmüyor.

Kapsam dışı notlar (yapılmadı): (a) Ghidra sonrası adımlar için takılma bekçisi / SIGTERM'e yanıt ayrı paket (ÖL-4 / ÖL-2 notu); bu paketin süre testi yalnız kendi kalıplarını ayrı süreçte sınar. (b) Yukarıdaki iki üstel kalıbın onarımı sonraki paket.

## Kalem 3 — `block_annotator.py`'nin bütün kalıpları (hüküm 4) (20:04)

**Yöntem:** Kalem 5b'deki araç (`kalip_tara.py tara`; AST ile toplama → `re._parser` ağacında durağan sınıflama → üstel adaylarda ayrı süreçte düşmanca girdiyle süre ölçümü) onarılmış `block_annotator.py`'ye ve BA-1 öncesi kopyasına koşuldu; ardından `kalip_tara.py gercek` ile dosyanın 52 kalıbının hepsi Ollama + S8'in 8 çalışma alanındaki gerçek girdide (adımın girdisi `reconstructed/commented/*.c`; 23 870 dosya, 4 533 866 satır) zamanlandı: her kalıp her `strip()` edilmiş satırda (adımın satır kalıplarına verdiği birim) ve ayrıca her dosyanın tam içeriğinde (yalnız `_FUNC_RE` ve gövde kalıbı için gerçek kullanım; öbürleri için üst sınır). Tek çocuk süreç, 1 500 sn zaman aşımı; **yük altında** (aynı anda tam takım koşuyordu, load ~10–13).

**Durağan sonuç:** 52 sabit kalıp (dinamik 0). `ic_ice`: onarılmış dosyada **0** (eski kopyada 3: memcpy / memset / memmove, devingen olarak üstel doğrulandı — aracın pozitif kontrolü). `ortusen_secenek`: 0. `zincir` (polinom adayı, derece ≈ 2 + aramanın başlangıç konumu): 27 kalıp — satır 204 (`0\.0+\d+` + `.*break`), 275 (`ASSEMBLY_BODY_PATTERNS`, DOTALL), 293 / 301 / 309 (`malloc` / `calloc` / `realloc`: `\(?.*\)?\s*` … `(.+?)\s*\)`), ve 22 döngü amacı kalıbı `for\s*\([^)]*=\s*0\s*;[^)]*<\s*\w*(…)` (satır 387 … 512). Bunlara ek olarak durağan kuralın yakalamadığı ama arama başlangıç konumuyla karesel olan satır içi kalıplar (`(\w+)\s*\[…`, `\w+\s*\(` vb.) gerçek veri ölçümünde ayrıca görülüyor.

**H5: `block_annotator.py`'de üç onarılan dışında üstel sınıfa giren kalıp: 0** (ilk ölçüm; yön bildirilmemişti). Onarım gerekmedi.

**Gerçek veride en kötü süre (satır birimi; en kötü 12; ham `…/BA1/ozet/gercek_en_kotu.json`):**

| block_annotator.py satırı | kalıp (özet) | sınıf | en kötü satır | nerede | toplam (4,5 M satır) | tam dosya üst sınırı |
|---|---|---|---:|---|---:|---:|
| 293 | `malloc` (`\(?.*\)?\s*malloc\s*\(\s*(.+?)\s*\)`) | zincir | 67,4 ms | Ollama `FUN_100346360.c:33` | 19,4 sn | 481 ms |
| 301 | `calloc` | zincir | 36,1 ms | Ollama `FUN_1000b7680.c:2386` | 18,8 sn | 566 ms |
| 309 | `realloc` | zincir | 32,2 ms | Ollama `FUN_100368b50.c:59` | 19,1 sn | 446 ms |
| 253 | row-major `(\w+)\s*\[\s*(\w+)\s*\*…` | arama-karesel | 31,0 ms | Ollama `FUN_100346360.c:33` | 12,9 sn | 387 ms |
| 512 | ML döngüsü `for\s*\([^)]*=\s*0\s*;[^)]*<\s*\w*(n_layer…)` | zincir | 29,5 ms | mac tmux `FUN_1000357a0.c:112` | 0,5 sn | 0,3 ms |
| 1428 | satır içi `\w+\s*\(` | arama-karesel | 27,1 ms | Ollama `FUN_1000bee20.c:34` | 8,4 sn | 1,7 ms |
| 204 | `if\s*\(…(1e-\d+\|0\.0+\d+)\s*\).*break` | zincir | 25,7 ms | mac tmux `FUN_100082b98.c:8` | 0,6 sn | 0,5 ms |
| 1426 | satır içi `\w+\s*\[\s*\w+\s*\*` | arama-karesel | 21,6 ms | Ollama `FUN_100346360.c:33` | 12,5 sn | 366 ms |
| 261 | dot product `(\w+)\s*\+=\s*(\w+)\s*\[[^]]+\]…` | arama-karesel | 20,3 ms | Ollama `FUN_100056090.c:59` | 12,2 sn | 420 ms |
| 238 | scatter `(\w+)\s*\[([^]]*)\]\s*\+=…` | arama-karesel | 19,4 ms | Ollama `FUN_100158cc0.c:18` | 13,4 sn | 378 ms |
| 474 | DSP döngüsü | zincir | 10,1 ms | mac tmux `FUN_100090f14.c:15` | 0,5 sn | 0,3 ms |
| 53 | `_FUNC_RE` (MULTILINE, `finditer` tam içerikte) | — | 8,0 ms | mac tmux `FUN_100059c6c.c:338` | 1,8 sn | 1,9 ms |

Sınıf sütunu: `zincir` durağan kuralın sonucu; `arama-karesel` elle sınıflama (her arama başlangıcında `\w+` koşusunun geri izlenmesi), büyüme eğrisi ölçülmedi. Öbür 40 kalıbın en kötü satır süresi ≤ 6,1 ms. Gövde kalıbı 275 (`ASSEMBLY_BODY_PATTERNS`, gerçek kullanımı ≤ 10 000 karakterlik gövde): satırda 2,8 ms, tam dosyada 0,3 ms. Sonuç: gerçek veride hiçbir kalıp tek satırda 0,1 sn'ye yaklaşmıyor; adımın tamamı Ollama'da 62 sn (H2). Karesel / zincir kalıplar uzun satırda büyür (ör. 1 537 karakterlik satırda `\w+\s*\(` 16–27 ms), ama üstel değil; onarım bu paketin kapsamında değil (hüküm 4: "yalnız listelenir"). Not: `tmux` adı iki çalışma alanında ortak (`FUN_001…` debian, `FUN_1000…` mac).
