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
