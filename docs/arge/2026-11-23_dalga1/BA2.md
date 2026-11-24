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
- `tests/test_kalip_denetimi.py`, 8 sınama: (a) `karadul/` + `ui/server.py`'nin **1 479 sabit kalıbında** üstel 0 (kapsam körleşmesin diye: `ui/server.py`, `constraint_solver.py`, `block_annotator.py` ve `reconstruction/` dışından en az bir dosya toplanmalı, kalıp sayısı ≥ 1 400, iç içe aday ≥ 30); (b) bilinen kusurlu beş eski kalıp (BA-1'in `memcpy` / `memset` / `memmove`'u, bu paketin `_ZN` ve `_LINKED_LIST_RE`'si) üstel bulunur; (c) istisna listesi (`ISTISNALAR`) boş ve sayılı (`BEKLENEN_ISTISNA_SAYISI = 0`), kayıt alanları (`dosya`, `kalip`, `gerekce`, `olculen_sure`); istisna yalnız kendi kalıbını geçirir; bekçi takılan çocuğu öldürüp üstel sayar; onarılmış iki kalıp üstel değil; şablon toplama yerleştirmeyi ayırır.
- **H6: kapı testi 5,2 sn (load 8; aynı test ağır yükte 20,5 sn), istisna listesi boş → TUTTU** (≤ 60 sn).
- **Mutasyon** `scripts/measurement/mutation_specs_ba2.json`: **9 / 9 öldü (75 sn)** — eski `_ZN` (süre sınaması zaman aşımıyla kırmızı), `_ZN` dili genişler (`\w*`; eşdeğerlik kırmızı), eski `_LINKED_LIST_RE`, `_LINKED_LIST_RE` dili daralır (eşdeğerlik kırmızı), kapının istisna denetimi kalkar, durağan sınıflayıcı iç içe yinelemeyi kaydetmez, bekçinin öldürdüğü aday üstel sayılmaz, kapı `ui/server.py`'yi taramaz, istisna listesine gerekçesiz kayıt girer. Ayrıca kapı sınamasının (a) kendisi eski iki kalıbı geri koyan mutantları öldürüyor (2 / 2; yani üstel bir kalıp eklenince tam takım kırmızı). Commit `2269eb9c`; güçlü düşmanca girdi ve kaçış izleme `fd69a297`.
