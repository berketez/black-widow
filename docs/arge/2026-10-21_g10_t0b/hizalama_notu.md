# G10 / T0b: Ghidra parametreleri ↔ DWARF parametreleri hizalaması — sonuç notu

- **Tarih:** 2026-10-21
- **Plan:** v2.2 §4 T0 (b) ve (c); §5 K1. Önceki adım: T0a (`2026-10-21_g9_t0/dwarf_tip_notu.md`, 6cf0ae3).
- **Araçlar** (commit'siz; sha256'ları `kosu.json`'da):
  - `scripts/measurement/ghidra_parametre.py` (yeni): Ghidra tarafı, Karadul'un ayarlarıyla.
  - `scripts/measurement/dwarf_tip.py` (genişletildi): parametrenin girişteki konumu.
  - `scripts/measurement/parametre_hizala.py` (yeni): yükleme tabanı, fonksiyon ve parametre hizalaması, sınıflar, özet, denetim paketi.
- **HEAD:** Görev 1acba60'ta başladı; koşular sırasında HEAD 1f69b35'e ilerledi. Aradaki `karadul/` farkı yalnız `c_namer.py` (b7faeac); Ghidra yolunu etkilemiyor. Künyelerdeki `git_head` bu yüzden dosyadan dosyaya farklı.
- **Testler:** `tests/test_parametre_hizala.py` (24 test, yeni), `tests/test_dwarf_tip.py` (41 → 64 test). Hepsi yeşil.
- **Mutantlar:** `mutation_specs_parametre_hizala.json` 8/8 öldü; `mutation_specs_dwarf_tip.json` 15/15 öldü (T0a'nın 8'i + T0b'nin 7 konum mutantı).
- **Kapsam:** Debian 13 geliştirme setinin 8 programı, 22 ikili. coreutils'in 106 ikilisinden 12'si tohumla seçildi (§1.4). Doğrulama setine, ağa ve `karadul/`'a dokunulmadı.
- **Veri:** `~/karadul_olcum/runs/t0b-1acba60/`. Alt dizinler: `dwarf/`, `ghidra/` (ilk koşu), `ghidra_2/` (son koşu), `hizalama/` (fonksiyon başına eşleme JSON'ları, 21 MB), `ozet.json`.

## 1. Yöntem

### 1.1 Ghidra tarafı (`ghidra_parametre.py`)

İkili, Karadul'un `GhidraHeadless._analyze_pyghidra` yolunun aynısıyla analiz edilir (§2). Her fonksiyon için iki parametre kümesi yazılır. İkisinde de sıra, ad, tip, boyut ve depolama vardır:

1. **Liste imzası** (`Function.getParameters()`). Karadul'un `ghidra_functions.json`'ı buradan okur. Depolama `VariableStorage`'ın parçalarıdır: yazmaç adı (`w0`, `d1`…) ya da yığın ofseti.
2. **Decompiler parametreleri** (`HighFunction.getLocalSymbolMap().getParamSymbol(i)`). C'deki `param_N`'ler bunlardır. Yanlarında prototip modeli, değişken argüman bayrağı, C imzası ve C metni de yazılır.

Fonksiyon kaydında ayrıca şunlar var: giriş adresi, gövde aralıkları, girişteki ilk 16 bayt (yükleme tabanı denetimi için), thunk bayrağı ve imza kaynağı.

### 1.2 DWARF tarafı (`dwarf_tip.py`, alan `giris`)

- **Kaynak.** Konum `DW_AT_location`'dan okunur:
  - `exprloc` ise ifadenin kendisi;
  - konum listesiyse `low_pc`'yi kapsayan girdi (`bas <= low_pc < son`).

  Konum listeleri pyelftools ile okunur ve mutlak adrese çevrilir: `DW_LLE_base_addressx` ve birim tabanı uygulanır; sıfır uzunluklu (görünüm) girdiler kapsamaz.
- **Yazmaçlar.** İfade AArch64 DWARF numaralarıyla çözülür: 0-30 `x0`-`x30`, 31 `sp`, 64-95 `v0`-`v31`.
- **Türler:**
  - `yazmac`;
  - `yigin`: `DW_OP_fbreg N` (çerçeve tabanı `DW_OP_call_frame_cfa` iken) ya da `DW_OP_breg31 N`. Girişte CFA = SP olduğu için N, Ghidra'nın `Stack[N]`'ine denk gelir;
  - `yerel_yuva`: N < 0, çağrılanın kendi yuvası;
  - `dolayli`: `DW_OP_bregN 0`, değer `xN`'in gösterdiği bellekte;
  - `parcali`: `DW_OP_piece`;
  - `sabit`, `deger` (ör. `DW_OP_GNU_parameter_ref`), `bellek`, `konumsuz`.

  `DW_OP_entry_value(<yazmaç>), DW_OP_stack_value` da girişteki yazmaç sayılır. `arguman` bayrağı, yazmacın AAPCS64 argüman yazmacı olup olmadığını (`x0`-`x7`, `v0`-`v7`) gösterir.
- Fonksiyon kaydına `cerceve_tabani` ve `dil` (`DW_AT_language`), parametreye `yapay` (C++ `this`) eklendi.
- 22 ikilinin 29 987 parametresinin girişteki konumu:

  | Tür | Sayı |
  |---|---|
  | `yazmac` | 29 153 |
  | `yigin` | 312 |
  | `deger` | 163 |
  | `dolayli` | 125 |
  | `konumsuz` | 116 |
  | `sabit` | 66 |
  | `parcali` | 40 |
  | `yerel_yuva` | 12 |
  | `cozulemedi` | 0 |

### 1.3 Hizalama (`parametre_hizala.py`)

1. **Eşleme.** DWARF belgesi ile Ghidra belgesi build-id ile eşlenir.
2. **Yükleme tabanı.** Fark üç bağımsız yoldan ölçülür, ayrıca bayt düzeyinde doğrulanır (§3).
3. **Fonksiyon.** `low_pc + fark` adresinde girişi olan Ghidra fonksiyonu aranır. Bulunmazsa `govde_icinde` ya da `yok` yazılır.
4. **Parametre: depolamayla.**
   - DWARF tarafında anahtar girişteki konumdan çıkar. Ghidra tarafında ad normalleştirilir: `w/x` → GPR, `b/h/s/d/q/v` → SIMD, `Stack[N]` → yığın N.
   - Eşleşme anahtar eşitliğidir. Parçalı konum, Ghidra'da birden çok parametreye düşüyorsa `yapi_bolunmesi` sayılır.
   - **Anahtar vermeyen DWARF konumları:** girişte yer yok (`konumsuz`, `sabit`, `deger`); argüman dışı yazmaç; `yerel_yuva`; `exprloc` ile yazılmış `dolayli` (§4.4).
   - Bu durumlarda, fonksiyon klon değilse ikinci kaynak **AAPCS64 beklentisi**dir (`aapcs64`, Linux). Beklenti bildirim sırası ve tiplerden hesaplanır: GPR ve SIMD sayaçları ayrı, HFA, 16 bayttan büyük yapı dolaylı, 16 bayt hizalı çift yazmaç, yığına taşma. Bu eşleşmeler `abi` diye ayrı sayılır.
5. **Parametre: sırayla** (yalnız karşılaştırma için). DWARF bildirim sırası k olan parametre `param_k` ile eşlenseydi sonuç `uyumlu`, `celiski`, `yalniz_sira` ya da `ortaksiz` olurdu.
6. **Klon** (T0 (c)). Ölçütler:
   - `.isra`/`.constprop`/`.part`/`.cold` soneki;
   - `sira ≠ somut_sira`;
   - tekrar DIE;
   - bildirimden düşen parametre.

   `abstract_origin` tek başına klon sayılmaz (T0a §4).

### 1.4 coreutils seçimi

- Tohum `karadul-g10-t0b-coreutils-secimi-2026-10-21` (SHA-256'nın ilk 16 hex basamağı: 1617656031144111583).
- Evren: `x_coreutils_9.7-3_arm64` altındaki 106 ELF dosyasının adları, sıralı. Seçim `random.Random(tohum).sample`.
- Seçilenler: `arch`, `chgrp`, `dir`, `du`, `env`, `ln`, `logname`, `md5sum`, `nproc`, `sha224sum`, `tr`, `unlink` (`secim.json`).
- Öbür 7 programın ikilileri:
  - tmux, htop, tree, sqlite3, openssl;
  - zstd ve pzstd;
  - redis-cli, redis-benchmark ve redis-check-aof. redis-check-rdb aynı build-id'li kopyadır, bir kez sayıldı.

## 2. Karadul ayarlarının taklidi ve kalan farklar

**Taklit edilenler.** `karadul/ghidra/headless.py` (`GhidraHeadless.analyze` → `_analyze_pyghidra`) okundu; şunlar aynen uygulandı:

- **Kurulum.** `karadul.config.GHIDRA_PINNED_DIR` (Ghidra 12.1.2, `application.properties`'ten doğrulanıyor).
- **JVM.** `karadul.ghidra.headless._ensure_pyghidra_started`'ın kendisi çağrılıyor: `HeadlessPyGhidraLauncher`, `-Djava.awt.headless=true`, G1GC, iş parçacığı bayrakları ve `-Xmx14745m`.
- **Analiz.** `pyghidra.open_program(..., analyze=True)`: varsayılan analizörler, seçenek değişikliği yok, analize zaman aşımı yok.
  - Açık analizörler belgede listeli. `Decompiler Parameter ID` kapalı; liste imzaları bu yüzden boş kalıyor (§4.3).
- **GDT ve PDB.** GDT arşivleri `Config()`'ten okunuyor (varsayılan boş). PDB yalnız PE'de denendiği için ELF'te yok.
- **Decompile.** İş parçacığı başına `DecompInterface` + `DecompileOptions()` (varsayılan, `grabFromProgram` yok) + `openProgram`. `decompileFunction(f, 30, ConsoleTaskMonitor())`. `CPU_PERF_CORES` (9) iş parçacığı, parça boyu `max(1, n // 9)`, toplam zaman aşımı 7200 sn.
- **Sıra.** Liste imzası decompile'dan önce okunuyor (`_extract_functions` sırası).

**Doğrulama.** tree üstünde Karadul'un kendi `GhidraHeadless(Config()).analyze(...)`'ı da koşturuldu. 250/250 fonksiyonda üç şey aynı çıktı:
- ad;
- liste imzası (`functions.json`);
- decompile edilmiş C metni (`decompiled/*.c`, başlık ve disassembly dışında, bayt bayt).

**Belirlenimcilik.** Aynı betikle iki ayrı koşu yapıldı (`ghidra/`, `ghidra_2/`; aradaki fark yalnız belge dizgisi). 22/22 ikilide fonksiyon kümesi aynı. 25 380/25 380 fonksiyonda liste imzası, decompiler parametreleri ve C metni aynı.

**Kalan farklar:**

| Konu | Karadul | T0b | Etkisi |
|---|---|---|---|
| Kurulumun bulunması | Önce `GHIDRA_INSTALL_DIR`/`GHIDRA_HOME` ortam değişkeni, sonra sabitlenen dizin | Doğrudan sabitlenen dizin | Yok: bu ortamda değişken tanımlı değil, ikisi de 12.1.2 |
| Proje | Çalışma alanında, `karadul_<hedef>` | Geçici dizin, `karadul_t0b` | Yok |
| Ek çıkarımlar | Dizgiler, çağrı grafı, xref, disassembly, yığın çerçevesi, tipler, p-code, CFG, FunctionID | Yok | Salt okunur; decompile'ı etkilemiyor (tree'de C aynı) |
| BSim | Açık (`shadow_mode`), decompile'dan sonra; `~/.cache/karadul/bsim`'e yazıyor | Yok | Decompile'ı etkilemiyor |
| Çıktı biçimi | `decompiled/*.c` (başlık + disassembly), `functions.json` | Tek JSON: C metni, imza, iki parametre kümesi, depolama | Yalnız biçim |
| Süreç | İkili başına bir Karadul süreci | İkili başına bir süreç (`toplu`) | Yok |

**Not.** tree'deki karşılaştırma koşusu Karadul'un varsayılan BSim ayarıyla `~/.cache/karadul/bsim/karadul_bsim` veritabanına tree'nin 119 fonksiyonunu ekledi (11:48). Her Karadul koşusu bunu yapıyor, `shadow_mode` adlandırmayı etkilemiyor. Yine de bilinsin diye yazıldı. `ghidra_parametre.py` BSim çalıştırmaz.

**Süre.** 22 ikili toplam 361 sn sürdü: içe aktarma ve analiz 203 sn, decompile 105 sn, JVM 32 sn. En uzunu openssl (87 sn).

## 3. Yükleme tabanı (PIE) bulgusu

- **Ölçülen fark.** 22 ikilinin hepsi ET_DYN. En küçük `PT_LOAD` `p_vaddr` 0, Ghidra'nın `image_base`'i `0x100000`. Fark: **Ghidra adresi = DWARF adresi + 0x100000**.
- **Üç yol aynı farkı veriyor** (`hizalama_indeksi.json` → `pie_tabani`):
  1. `image_base − en küçük p_vaddr`;
  2. Ghidra `.text` bloğu − ELF `.text` `sh_addr`;
  3. tarama: tohumlu 200 DWARF adresi (küçük ikilide hepsi) × bütün Ghidra girişleri.
- **Tarama ayrımı net.** Örneklemin %100'ü 0x100000'da tutuyor. İkinci en sık fark 11-28 rastlantı eşleşmesinde kalıyor.
- **Öbür adayların eşleşme payı:** fark 0 → en çok %1,5, ±0x1000 → %1,8-%12,0 (rastlantı).
- **Bayt düzeyinde doğrulama.** Eşlenen 12 994 fonksiyonun 12 994'ünde ikili dosyanın DWARF adresindeki ilk 16 bayt (`PT_LOAD` ile dosya ofsetine çevrilmiş) Ghidra'nın o girişteki baytlarıyla aynı. Farklı ya da okunamayan yok.
- **Sınır.** 0x100000, Ghidra'nın 64 bit ELF PIE için seçtiği varsayılan taban. Betik bunu varsaymıyor, her ikilide yeniden ölçüyor. Mach-O'da (`__TEXT` 0x100000000) aynı yol geçerli ama orada sınanmadı.

## 4. Ölçüler

### 4.1 (a) Adresle eşlenen fonksiyon payı

| Program | İkili | DWARF fonk. | Adresle eşlenen | Pay | Ghidra fonk. | Thunk dışı | Klon fonk. | Gövde boyu farklı |
|---|---|---|---|---|---|---|---|---|
| tmux | 1 | 1 911 | 1 911 | %100 | 2 588 | 1 920 | 61 | 4 |
| htop | 1 | 608 | 608 | %100 | 1 148 | 609 | 13 | 2 |
| tree | 1 | 110 | 110 | %100 | 250 | 119 | 1 | 0 |
| zstd | 2 | 1 907 | 1 907 | %100 | 2 600 | 1 931 | 276 | 40 |
| sqlite3 | 1 | 418 | 418 | %100 | 1 144 | 429 | 31 | 4 |
| openssl | 1 | 596 | 596 | %100 | 5 672 | 592 | 21 | 13 |
| redis-tools | 3 | 5 794 | 5 794 | %100 | 7 700 | 5 821 | 120 | 22 |
| coreutils | 12 | 1 650 | 1 650 | %100 | 4 278 | 1 730 | 31 | 59 |
| **Toplam** | 22 | 12 994 | **12 994** | **%100** | 25 380 | 13 151 | 554 | 144 |

- Eşlenmeyen DWARF fonksiyonu yok; `govde_icinde` ve `yok` 0.
- Aynı adreste birden çok DWARF fonksiyonu yok.
- 178 DWARF fonksiyonunu Ghidra thunk sayıyor: tek sıçramalık gövde, ör. `setlocale_null_r`.
- DWARF karşılığı olmayan, thunk dışı Ghidra fonksiyonu 335 tane (crt başlangıcı vb.).
- "Gövde boyu farklı": DWARF `high_pc − low_pc` ≠ Ghidra gövdesi. İncelenmedi (§8).

### 4.2 (b) Parametre düzeyi

| Program | DWARF param. | Depolama (DWARF) | Depolama (ABI) | Pay (DWARF) | Pay (toplam) | Klonsuz pay | Sıra: uyumlu | Sıra: çelişki | Bunun yazmaç sınıfı farkı | Yalnız sırayla | Ortaksız |
|---|---|---|---|---|---|---|---|---|---|---|---|
| tmux | 4 211 | 3 958 | 4 | %94,0 | %94,1 | %94,8 | 3 916 | 34 | 0 | 36 | 225 |
| htop | 1 112 | 1 031 | 0 | %92,7 | %92,7 | %93,3 | 1 022 | 7 | 4 | 6 | 76 |
| tree | 208 | 182 | 4 | %87,5 | %89,4 | %90,3 | 181 | 5 | 0 | 0 | 22 |
| zstd | 6 514 | 5 712 | 94 | %87,7 | %89,1 | %89,8 | 5 639 | 162 | 12 | 14 | 699 |
| sqlite3 | 993 | 824 | 0 | %83,0 | %83,0 | %83,1 | 821 | 2 | 0 | 6 | 164 |
| openssl | 1 522 | 1 442 | 0 | %94,7 | %94,7 | %95,4 | 1 396 | 35 | 2 | 13 | 78 |
| redis-tools | 11 578 | 10 712 | 33 | %92,5 | %92,8 | %93,0 | 10 492 | 240 | 158 | 23 | 818 |
| coreutils | 3 849 | 3 213 | 0 | %83,5 | %83,5 | %83,6 | 3 193 | 13 | 4 | 11 | 632 |
| **Toplam** | **29 987** | **27 074** | **135** | **%90,3** | **%90,7** | **%91,2** | 26 660 | **498** | 180 | **109** | 2 714 |

Görevin üç sorusuna cevap:

1. **Depolamayla bir Ghidra parametresine eşlenen:** 27 209 (%90,7).
   - 27 074'ü DWARF konumuyla, 135'i AAPCS64 beklentisiyle eşlendi.
   - Eşleşme türü: 27 163 tam, 46 yapı bölünmesi.
2. **Yalnız sırayla eşlenebilecek:** 109. Depolama bilgisi yok, ama `param_k` var.
   - 108'i klon. Örnek: isra klonunda düşen `this`, `DW_OP_GNU_parameter_ref`.
3. **Sıra ile depolamanın çeliştiği:** 498.
   - Sırayla eşleme bu 498 parametreyi yanlış Ghidra parametresine bağlardı. Bu, sıra ortağı olan parametrelerin %1,8'i.
   - Çelişkiler 184 fonksiyonda toplanıyor: 84'ünde kayan noktalı parametre var, 39'unda x8 dönüş işaretçisi, 45'i klon, 16'sının nedeni başka.
   - Kayan nokta örneği: `Meter_humanUnit(char *buffer, double value, size_t size)` Ghidra'da `Meter_humanUnit(double param_1, undefined8 param_2, undefined8 param_3)` olarak çıkıyor; Ghidra SIMD parametrelerini başa alıyor.
   - x8 örneği: `listdir`, struct'ı değerle döndürüyor, `param_1` = x8. Bütün parametreler bir kayıyor.
   - 180 çelişkide sıra ortağının yazmaç sınıfı farklı (x ↔ v).

**DWARF konumu ile AAPCS64 beklentisinin bağımsız sınaması.** İkisinin de bulunduğu 27 934 parametrenin 27 934'ünde aynı yazmaç ya da yığın ofseti çıkıyor. Okuyucunun konum çözümü ile ABI hesabı birbirini doğruluyor. §4.4'teki kural konmadan önce 24 vaka farklıydı; hepsi `exprloc` ile yazılmış dolaylı konumdu.

**Tip sınıfına göre kapsam** (toplam 22 ikili; "klonsuz" klon fonksiyonları dışarıda bırakır):

| DWARF tip sınıfı | Parametre | Eşlenen | Pay | Klonsuz pay |
|---|---|---|---|---|
| `yapi*` | 10 537 | 9 985 | %94,8 | %95,5 |
| `skaler` | 9 122 | 8 016 | %87,9 | %88,9 |
| `char*` | 4 398 | 3 969 | %90,2 | %89,6 |
| `void*` | 2 643 | 2 319 | %87,7 | %87,7 |
| `skaler*` | 1 601 | 1 471 | %91,9 | %91,4 |
| `ptr**` | 1 078 | 952 | %88,3 | %88,3 |
| `fonk*` | 313 | 286 | %91,4 | %91,1 |
| `yapi_degerle` | 259 | 187 | %72,2 | %74,5 |
| `diger` | 36 | 24 | %66,7 | %66,7 |

Program başına `yapi*` (klonsuz pay):

| Program | Pay |
|---|---|
| openssl | %97,3 |
| tmux | %96,7 |
| redis | %96,1 |
| zstd | %94,2 |
| htop | %93,7 |
| sqlite3 | %93,6 |
| coreutils | %90,6 |
| tree | %90,0 |

### 4.3 Liste imzası (`ghidra_functions.json`) parametre taşımıyor

- **Liste imzası boş.** Thunk dışı 13 151 Ghidra fonksiyonunun 13 144'ünün imza kaynağı `DEFAULT`, liste parametresi 0. Parametreli 7 fonksiyonun hepsi redis-check-aof'taki demangle edilmiş C++ (fast_float; imza kaynağı `ANALYSIS`; 3'ü `__thiscall`).
- **Decompiler'da var.** Aynı fonksiyonlarda decompiler 11 611 fonksiyonda 28 201 parametre görüyor.
- **Neden.** `Decompiler Parameter ID` analizörü kapalı ve Karadul decompiler parametrelerini veritabanına geri yazmıyor.
- **Sonuç.** Karadul'un `ghidra_functions.json`'ındaki parametre bilgisi pratikte yalnız PLT thunk'larının (libc imzaları) bilgisi. K1 parametreyi `HighFunction`'dan, yani C'den almalı.
- **Ad ile yuva.** Thunk dışı fonksiyonların 28 201 parametre yuvasında C'deki ad her zaman yuvayı vermiyor:
  - 28 183 yuvada `param_N`'deki N yuva sırasına eşit; 3'ünde farklı (C++ `__thiscall`'da `this` yuvası).
  - 12 yuvanın adı `UNRECOVERED_JUMPTABLE` (dolaylı kuyruk çağrısı), 3'ünün `this`.
  - K1 yuvayı (`sira`/depolama) kullanmalı, adı değil.
- **Değişken argüman.** Decompiler, thunk dışı 13 151 fonksiyonun hiçbirinin prototipini değişken argümanlı işaretlemiyor (`isVarArg`).

### 4.4 `exprloc` ile yazılmış dolaylı konum güvenilmez

- **Ne oluyor.** 16 bayttan büyük değerle yapı (`va_list`, `ZSTD_customMem` …) AAPCS64'te kopyasının işaretçisiyle geçer. GCC bunun konumunu çoğu zaman tüm fonksiyon için tek bir `exprloc` olarak yazar: `DW_OP_bregN 0`. N prolog SONRASI yazmaçtır.
- **Ölçüm.** Argüman yazmacı taşıyan ve ABI beklentisi olan 49 vakanın 24'ünde N, ABI yazmacından farklı. Örnek: gnulib `error_tail`'in `va_list args`'ı `DW_OP_breg4 0`; ABI ve Ghidra'ya göre x3. Bu 24 vaka 12 coreutils ikilisinde, redis'te, tmux'ta ve zstd'de.
- **Kural.** Bu tür konum giriş anahtarı sayılmaz; klon değilse ABI beklentisi kullanılır.
- **Doğrulama.** Kural sonrası DWARF ile ABI 27 934/27 934 uyumlu. Zor vaka denetiminde 2 vaka (Z6, Z7) bu yoldan eşlendi, ikisi de doğru.
- **Argüman dışı yazmaç.** `exprloc`'ta argüman dışı yazmaç taşıyan 65 dolaylı konum (`DW_OP_breg22 0` …) baştan beri anahtar sayılmıyor.

## 5. Eşleşmeyenlerin sınıf dağılımı

**DWARF parametresi, Ghidra karşılığı yok:** toplam 2 778.

| Sınıf | Sayı | Anlamı |
|---|---|---|
| `ghidra_az` | 2 107 | Ghidra o sınıfta daha az parametre görüyor (sayı farkı) |
| `ghidra_thunk` | 342 | Ghidra fonksiyonu thunk sayıyor; 178 fonksiyonda |
| `klon` | 299 | Klon fonksiyonlarında |
| `yigin_eksik` | 16 | Yığın parametresi Ghidra'da yok |
| `kullanilmayan_ya_da_optimize` | 13 | DWARF girişte yer vermiyor (konumsuz, sabit, `parameter_ref`) ve ABI yuvasında da parametre yok |
| `diger` | 1 | — |
| `ghidra_atladi` | 0 | — |
| `decompile_yok` | 0 | — |

**Not.** Program başına dağılım `ozet_t0b.json`'da. coreutils'te `ghidra_az` ikili başına ~45 civarında; bunlar her ikilide tekrarlanan gnulib sarmalayıcıları (`error`, `version_etc_ar`, `xnrealloc`, `quote_n_mem` …).

- **`ghidra_az` iki mekanizmadan geliyor.** DWARF ikisini ayırmıyor; ikisinde de değer girişte yazmaçta.
  1. **Geçirme ya da kuyruk çağrısı:** argüman değiştirilmeden başka bir fonksiyona aktarılıyor. Çağrılanın prototipi bilinmediği için okuma görünmüyor. C imzası `void FUN(void)` oluyor. Örnekler: `hashTypeExists`, `RM_ZsetLastInScoreRange`, `quote_n_mem`.
  2. **Kullanılmayan parametre.** Örnek: sqlite `expertFilter`'ın `argv`'si.

  69'u C'de `in_x4` gibi bir girdi olarak görünüyor (`c_girdisi`): decompiler okumayı görmüş ama prototipe koymamış. Örnek: `version_etc_ar`.
- **Değerle geçen yapının bölünmesi:** 46. Bunlar eşlendi ama tek parça değil (`yapi_bolunmesi`). Örnek: 16 baytlık `struct timeval` x1+x2'de geliyor, Ghidra'da `param_2` ve `param_3` olarak çıkıyor.

**Ghidra parametresi, DWARF karşılığı yok:** toplam 750.

| Sınıf | Sayı | Anlamı |
|---|---|---|
| `degisken_arguman` | 575 | Değişken argümanlı fonksiyonun `va_start` kaydettiği x(n)-x7 yazmaçları |
| `klon` | 84 | IPA-SRA'nın parçaladığı alanlar |
| `fazla` | 50 | Bkz. aşağı |
| `x8_donus` | 41 | Dolaylı dönüş işaretçisi |

`fazla`'nın 36'sı zstd'de. Bu fonksiyonlarda decompiler gövdenin dışındaki koda da dallanıp onu C'ye katıyor; o kodun okuduğu yazmaçlar parametre görünüyor. Örnek: `HUF_minTableLog`'un gövdesi DWARF'la aynı (40 bayt), ama C'si 8 parametreli ve başka bir fonksiyonun (`HUF_optimalTableLog`) assert dizgisini içeriyor. Mekanizma ayrıca incelenmedi.

**Sırayla eşlemedeki yazmaç sınıfı farkı:** 180 çelişki (§4.2).

**Fonksiyon sınıfları** (12 994):

| Sınıf | Sayı |
|---|---|
| `tam_uyum` | 11 197 |
| `ghidra_eksik` | 888 |
| `klon` | 554 |
| `ghidra_thunk` | 178 |
| `sira_bozuk` | 117 (depolama tam, sıra yanlış) |
| `ghidra_fazla` | 56 |
| `eksik_ve_fazla` | 4 |

## 6. Elle denetim

### 6.1 Tohumlu 50 hizalama (`denetim_50.json`, kararlar `denetim_kararlari.json`)

- **Örneklem.** Tohum `karadul-g10-t0b-hizalama-denetimi-2026-10-21`. Evren: adresle eşlenen fonksiyonlardaki 29 987 DWARF parametresinin hepsi, ikili, adres ve DIE konumuna göre sıralı.
- **Bakılanlar.** Her örnekte decompile edilmiş C (ilk satırlar ve eşlenen `param_N`'in geçtiği satırlar), Ghidra imzası, DWARF parametre listesi ve tipler. Karar şu soruya göre verildi: `param_N`'in kullanımı DWARF parametresinin adı, tipi ve kaynaktaki rolüyle tutarlı mı? Eşleşmeyenlerde Ghidra'da o depolamada parametre gerçekten yok mu, sınıfı makul mü?
- **Bağımsız konum denetimi.** Parametrenin `low_pc`'deki ifadesi Apple `/usr/bin/dwarfdump -v -F --debug-info=<ofset>` çıktısından ayrıca okundu ve karşılaştırıldı. Bu yol pyelftools'u ve betiğin çözücüsünü kullanmıyor.

**Sonuç:**
- **50/50 doğru**: 45 tam eşleşme (sıra uyumlu), 1 tam eşleşme (sıra çelişkili), 4 `ghidra_az`.
  - Sıra çelişkili örnek: #9 `hnsw_update_worst_neighbor_on_add`. `node` → `param_3`; sırayla eşleme `index`'i verirdi.
  - `ghidra_az` örnekleri: `expertFilter` (kullanılmayan `argv`); `hashTypeExists`, `RM_ZsetLastInScoreRange`, `quote_n_mem` (geçirme ya da kuyruk çağrısı).
- **dwarfdump denetimi 50/50 tutarlı.**
- **Program dağılımı.** Örneklem düzgün olduğu için büyük programlara kayıyor: redis-check-aof 26, zstd 6, tmux 5, openssl 4, sqlite3 2, öbür 7 ikili 1'er.
- **Not.** #49 `lh_FUNCTION_doall_thunk`'ta eşleme doğru, ama 2. yuvanın C adı `UNRECOVERED_JUMPTABLE`.

### 6.2 Ek: tohumlu 15 zor vaka (`denetim_zor_15.json`, kararlar `denetim_zor_kararlari.json`)

- **Neden.** Düzgün örneklemin 45'i kolay vaka. Sıranın yanılttığı ya da tek parçalı veya DWARF konumlu olmayan eşleşmeler ayrıca denetlendi.
- **Evren.** 656 vaka: sıra çelişkisi, ABI ile eşleşme ya da yapı bölünmesi. Tohum `karadul-g10-t0b-zor-vaka-denetimi-2026-10-21`.
- **Sonuç: 15/15 doğru, dwarfdump 15/15 tutarlı.**
  - 12'si sıra çelişkisi; 12'sinin hepsinde sırayla eşleme yanlış olurdu. Nedenleri: kayan noktalı parametre başta, x8 dönüşü, isra/constprop klonunda düşen parametre ve yığında kayan sıra (`certify.constprop`: `default_op` Stack[120] → `param_24`, bildirim sırası 25).
  - 2'si ABI yedeği (`ZSTD_createCCtx_advanced`, `ZSTD_createCDict_advanced`).
  - 1'i yapı bölünmesi (`ZSTD_CCtx_setFParams`: 12 baytlık yapı x1 + w2).

**Sınır.** Kararlar bir LLM ajanınındır, insan değerlendirici değil (plan v2.2 §9: insan değerlendirici Faz 3'te). Kararlar örnek numarası ve kimlikle (`ikili|adres|DIE konumu`) bağlanır; kimlik uyuşmazsa paket `kimlik_uyusmuyor` yazar.

## 7. Testler ve mutantlar

**`tests/test_parametre_hizala.py`** (24 test). Saf mantık:
- yükleme tabanı: üç yolun uyumu ve uyuşmazlığın işaretlenmesi, `PT_LOAD` ofset çevirisi, gövde indeksi;
- yazmaç normalleştirme ve DWARF anahtarı: argüman dışı yazmaç ve `exprloc` dolaylı konum anahtar vermez;
- AAPCS64: ayrı sayaçlar, HFA (birlikte en büyük üye), dolaylı yapı, çift hizalı `__int128`, yığına taşma, belirsizlik;
- klon nedenleri;
- karışık int/double imza, x8, değişken argüman, yapı bölünmesi, ABI yedeği, `ghidra_az`/`atladi`/`yigin_eksik`, thunk, klon, decompile hatası;
- özet sayımları, zor vaka evreni, `in_<yazmaç>` girdisi;
- dwarfdump konum metninin ayrıştırılması ve normalleştirilmesi;
- tohumlu seçimin kararlılığı;
- `ghidra_parametre.py`'nin saf yardımcıları.

Tümleşik test: yerel T0b koşusu varsa tree'de taban 0x100000, 110/110 bayt, 110/110 fonksiyon, DWARF-ABI farkı 0, `listdir`'de x8.

**`tests/test_dwarf_tip.py`** (+23):
- DW_OP ayrıştırma ve işlenenler, AArch64 yazmaç adları;
- 16 konum türü (parametreli test), parçalar ve çerçeve tabanı;
- konum listesinin mutlak adrese çevrilmesi ve kapsayan girdi (açık son uç, sıfır uzunluk, varsayılan konum);
- sahte DIE dünyasında fonksiyon düzeyi konumlar;
- gerçek veride tree `main` (argc x0, argv x1, `dil` C11) ve htop `Meter_humanUnit` (`value` v0).

Önceki 41 test aynen geçiyor.

**Mutantlar.** Hepsi uzunluğu özgününden farklı mutant; `PYTHONDONTWRITEBYTECODE=1 python scripts/mutation_probe.py --spec …` ile koşuldu.

`parametre_hizala`, 8/8 öldü:
- yükleme tabanı 0;
- `w` yazmacı SIMD;
- her anahtar `param_1`'e;
- kayan noktalı parametre GPR'de;
- değişken argüman sınıfı yok;
- argüman dışı yazmaç anahtar;
- sıra değişimi klon değil;
- `exprloc` dolaylı anahtar.

`dwarf_tip` konum mutantları, 7/7 öldü:
- v tabanı 640;
- kapalı son uç;
- göreli tabanın eklenmemesi;
- `entry_value` yok sayılıyor;
- CFA altı yığın sayılıyor;
- x8-x30 argüman sayılıyor;
- ilk girdi seçiliyor.

T0a'nın 8 mutantı da yeniden öldü.

## 8. Bilinen sınırlar

- **Yalnız Debian 13 arm64.** Derleyici gcc `-O2`. Mac (dSYM, Apple clang, Apple arm64 ABI'si) bu adımda yok. Apple'da değişken argümanlar yığında ve yığın argümanları doğal boyutla paketli; ABI yedeği orada Linux kurallarıyla yanlış olur.
- **coreutils'ten 12 ikili.** Gnulib fonksiyonları her ikilide tekrarlanıyor; bu yüzden coreutils sayıları bağımsız değil.
- **AAPCS64 hesabı C içindir:**
  - C++'ın önemsiz olmayan sınıfları (görünmez başvuru) modellenmedi, `class` belirsiz sayıldı;
  - K&R yükseltmeleri modellenmedi;
  - hizalamada `long double`/`__int128` üye sezgisi var;
  - iç yapı yalnız yapı tablosundaysa açılıyor.

  Geliştirme setinde ABI ile DWARF arasında kural sonrası fark yok. ABI'nin tek başına eşlediği 135 parametre de ayrı sayıldı.
- **`ghidra_az` iki mekanizmayı ayırmıyor.** Kullanılmayan parametre ile geçirme/kuyruk çağrısı DWARF'tan ayrılamıyor; ayrım gövde analizi ister.
- **Sıra karşılaştırması bildirim sırasıyla yapıldı.** Somut DIE sırası kullanılsaydı yalnız klonlarda fark ederdi.
- **144 fonksiyonda gövde boyu farkı incelenmedi.** Olası nedenler `.cold` parçaları ve Ghidra'nın gövde birleştirmesi.
- **Desteklenmeyen biçimler.** `DW_FORM_loclistx` desteklenmiyor (pyelftools 0.32 dizini ofset sanıyor); verilerde görülmedi. `DW_OP_bit_piece` yalnız kaydediliyor.
- **Karadul eşdeğerliği tek ikilide.** Bayt düzeyinde yalnız tree'de denendi. Öbür ikililerde aynı kod yolu ve aynı ayarlar var; belirlenimcilik iki koşuyla gösterildi.
- **Elle denetim** LLM ajanınca yapıldı (§6).

## 9. K1 ön kaydı için öneriler

Taslakla karşılaştırma (`2026-10-21_k1_k2_onkayit_taslak.md`, 49efb28):
- **§1 "Birim".** T0b sonucu bunu destekliyor (madde 1-2).
- **§1 "Dil: araca eklenecek [T0c]".** T0b'de yapıldı: `dwarf_tip.py` fonksiyon kaydına `dil` (`DW_AT_language` kodu) yazıyor, `parametre_hizala.py` bunu C/C++'a çeviriyor. C++ olan: pzstd'nin kendi kodu ve redis-check-aof'taki fast_float, toplam 155 parametre.
- **§1 klon tanımı.** Taslak "sonek VEYA tekrar VEYA sıra farkı" diyor; T0b buna "bildirimden düşen parametre"yi ekliyor. Yalnız bu nedenle klon sayılan 20 fonksiyonun hepsi pzstd'de (C++), dolayısıyla K1 nüfusunu değiştirmiyor.
- **Klon nedenleri** (fonksiyon sayısı; bir fonksiyonun birden çok nedeni olabilir): sonek 543, sıra farkı 124, düşen parametre 20, tekrar DIE 5.
- **§4 "yerleşim imzası çıktısı".** T0b'de yapılmadı.


1. **Eşleme birimi.** Ghidra `HighFunction` parametre yuvası (C'deki `param_N`, yuva sırasıyla) ile DWARF parametresi **depolamayla** eşlenir; sıra ile eşleme yasaklanır.
   - Gerekçe (§4.2): sırayla eşleme 498 parametreyi yanlış bağlıyor.
   - Bunların 100'ü klon dışı fonksiyonlardaki `yapi*` parametreleri.
   - Çelişkiler kayan noktalı parametreli, x8 dönüşlü ve klon fonksiyonlarda toplanıyor.
2. **Kaynak.** Parametre `ghidra_functions.json`'dan değil decompiler'dan alınır (§4.3).
   - Ad kalıbına (`param_N`) güvenilmez: yuva kullanılır.
   - K1'in Ghidra koşusu Karadul'un C'siyle aynı olmalı. Öneri: `ghidra_parametre.py` çıktısı ya da Karadul `decompiled/*.c` + yuva eşlemesi.
3. **K1'e giren parametreler.** Fonksiyon düzeyinde şunlar dışarıda kalır:
   - adresle eşlenmemiş fonksiyon;
   - klon (§1.3 madde 6);
   - Ghidra thunk'ı (178 fonksiyon; C'si sıçrama). Taslakta yok, eklenmeli;
   - dili C olmayan birim (`dil` C ailesi değilse: pzstd'nin C++ kısmı, redis'in fast_float'u).

   Parametre düzeyinde girme şartları:
   - DWARF tip sınıfı `yapi*`;
   - eşleşme kaynağı `dwarf` (girişteki DWARF konumu);
   - eşleşme türü `tam`.

   Ek kurallar:
   - **ABI yedeğiyle eşlenenler karar ölçüsüne girmez**, ayrı raporlanır. Geliştirme setinde klonsuz `yapi*` içinde bu tür eşleşme yok. Taslağın "hizalanamayan parametreler" maddesinin altına yazılabilir.
   - **Bölünen ve kısmi eşleşmeler girmez.** Yalnız değerle yapılarda görülüyor.
   - **Değişken argümanlı fonksiyonların adlı parametreleri girer.** Fazla Ghidra yuvaları dışarıda.
4. **Nüfus (geliştirme seti, karar ölçüsüne giren `yapi*`).** Toplam 9 433:

   | Program | `yapi*` |
   |---|---|
   | redis | 4 486 (3 ikili) |
   | tmux | 2 066 |
   | zstd | 1 121 |
   | htop | 547 |
   | coreutils | 450 (12 ikili) |
   | openssl | 387 |
   | sqlite3 | 349 |
   | tree | 27 |

   Redis payı %47,6. T0a §5.9'daki öneri burada da geçerli: program başına makro ortalama ya da program başına örneklem üst sınırı ön kayda yazılmalı. Çiftler ikili içinde kurulur.
5. **Kapsamın paydası açık yazılır.** İki pay yan yana raporlanır:
   - DWARF'taki bütün `yapi*`;
   - uygun fonksiyonlardaki `yapi*` (klonsuz, C, thunk dışı: 9 821).

   Hizalamanın kendisi uygun fonksiyonlarda **%96,0** (9 433/9 821) ile bir **tavan** koyuyor. Kalan 388'in 387'si `ghidra_az` (Ghidra'nın C'sinde o parametre yok), 1'i `yigin_eksik`. K1'in kapsam alt sınırı (T0c) bu tavanın altında kalmak zorunda.
6. **`in_<yazmaç>` girdileri.** Ayrı raporlanır, karar ölçüsüne girmez: C'de parametre değiller.
7. **Kimlik ve sürüm kilidi.** Hizalama belgesi (`karadul-parametre-hizalama/1`) betik sha256'larını ve Ghidra ikilisinin sha256'sını taşıyor. K1 ön kaydı hangi `dwarf_tip`/`ghidra_parametre`/`parametre_hizala` sürümünün kullanılacağını sha256'yla kilitler.
8. **Mac dSYM (newlisp, nagios).**
   - Aynı depolama hizalaması kullanılır.
   - ABI yedeği Apple arm64 kurallarıyla yeniden yazılmadan kullanılmaz; öneri: Mac'te ABI yedeği kapalı.
   - Yükleme tabanı yine ölçülür.
   - Apple clang'ın soneksiz klonları (T0 (c)) ayrıca denetlenir.

## 10. Yeniden üretme

```sh
R=~/karadul_olcum/runs/t0b-<commit>; D=~/karadul_olcum/downloads/debian13; S=<geçici proje dizini>
python3 -I scripts/measurement/parametre_hizala.py secim -o $R/secim.json
python3 -I scripts/measurement/ghidra_parametre.py toplu $R/secim.json -o $R/ghidra --proje-kok $S   # ~6 dk, arka planda
python3 -I scripts/measurement/dwarf_tip.py toplu "$D/x_tmux-dbgsym_3.5a-3_arm64/usr/lib/debug" --ikili-kok "$D/x_tmux_3.5a-3_arm64" -o $R/dwarf/tmux   # öbür 7 paket aynı kalıpla
python3 -I scripts/measurement/parametre_hizala.py hizala --dwarf $R/dwarf --ghidra $R/ghidra -o $R/hizalama
python3 -I scripts/measurement/parametre_hizala.py ozet $R/hizalama --json $R/ozet.json
python3 -I scripts/measurement/parametre_hizala.py denetim $R/hizalama --dwarf $R/dwarf --ghidra $R/ghidra --kararlar denetim_kararlari.json -o denetim_50.json
python3 -I scripts/measurement/parametre_hizala.py denetim $R/hizalama --dwarf $R/dwarf --ghidra $R/ghidra --evren zor --kararlar denetim_zor_kararlari.json -o denetim_zor_15.json
PYTHONDONTWRITEBYTECODE=1 python scripts/mutation_probe.py --spec scripts/measurement/mutation_specs_parametre_hizala.json
PYTHONDONTWRITEBYTECODE=1 python scripts/mutation_probe.py --spec scripts/measurement/mutation_specs_dwarf_tip.json
```

## 11. Bu dizindeki kanıtlar

- `secim.json`: tohum ve 22 ikili.
- `hizalama_indeksi.json`: ikili başına yükleme tabanı (üç yol, aday payları), bayt doğrulaması, özet.
- `ozet_t0b.json`: program ve ikili başına (a), (b), sınıflar, tip sınıfı ve dil kapsamı.
- `denetim_50.json` + `denetim_kararlari.json`: 50 örnek, C satırları, dwarfdump denetimi, kararlar.
- `denetim_zor_15.json` + `denetim_zor_kararlari.json`: 15 zor vaka.
- `kosu.json`: betik sha256'ları, veri dizinleri, iki Ghidra koşusunun eşitliği, tree'de Karadul eşdeğerliği ve BSim yan etkisi.

## 12. Ana oturumun bağımsız denetimi (2026-10-21)

- **Testler ve mutantlar:** `test_parametre_hizala.py` + `test_dwarf_tip.py` 88/88 geçti. Mutantlar `parametre_hizala` 8/8, `dwarf_tip` 15/15 öldü (`PYTHONDONTWRITEBYTECODE=1`).
- **Tablonun yeniden toplanması:** §4.2'deki tablo, `hizalama/` altındaki 22 ikili dosyasından ajanın özet kodu kullanılmadan yeniden toplandı. Program başına ve toplamda bütün sütunlar aynı: 29 987 parametre, DWARF ile 27 074, ABI ile 135, sıra uyumlu 26 660, çelişkili 498, yalnız sırayla 109. Eşleşmeyen sınıflar da aynı (`ghidra_az` 2 107, `ghidra_thunk` 342, `klon` 299, `yigin_eksik` 16, `kullanilmayan_ya_da_optimize` 13, `diger` 1).
- **Yeni tohumla örneklem** (`bagimsiz_denetim.py`, tohum 7741, 12 örnek, havuz: DWARF konumuyla tam eşlenen 27 039 parametre). Ajanın ayrıştırıcıları yerine ham Ghidra JSON'u (`ghidra_2/`) ve Apple `dwarfdump` kullanıldı.
  - Yazmaç (DW_AT_location'ın ilk girdisi ↔ eşlenen Ghidra parametresinin depolaması): **12/12 aynı**.
  - Fonksiyon girişi (üst subprogram'ın low_pc + 0x100000 = Ghidra girişi): **12/12**.
  - Ad: denetlenebilen 8/8 aynı. Kalan 4'te ad dwz ek dosyasındaki dizgide (`DW_FORM_GNU_strp_alt`); Apple `dwarfdump` bunu `DW_AT_name ()` diye boş gösteriyor. Bu denetim aracının sınırı; `decl_file` ve `decl_line` doğru parametreyi gösteriyor (ör. `zstd_opt.c:82`, `ZSTD_setBasePrices`'ın 2. parametresi).
- **Karadul ile eşdeğerlik (bağımsız):** N1 için koşulan Karadul çıktısıyla karşılaştırıldı. Koşu a10fde3, `~/karadul_olcum/n1_debian13/tree/`.
  - Karadul'un `static/ghidra_output/decompiled/*.c` dosyalarından baştaki künye yorumu (`// Function:` … `// Stack:`) ve sondaki `// --- DISASSEMBLY` eki atıldı.
  - Dosyalar künyedeki `// Address:` alanıyla adrese eşlendi.
  - Sonuç: `ghidra_2/tree.json`'daki 250 fonksiyonun **250'sinde decompile gövdesi aynı**.
  - Ada göre eşleme yanıltır: aynı adlı PLT thunk'ı ile dış blok taslağı (ör. `strlen` 0x103d30 ve 0x135028) ayrı dosyalara yazılıyor.
