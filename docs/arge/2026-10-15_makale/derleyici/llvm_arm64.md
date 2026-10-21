# Clang/LLVM → Mach-O arm64: derleyici hattı, bıraktığı izler ve Karadul

**Kapsam.** Bu belge, C kaynağından Apple arm64 (Mach-O) yürütülebilir dosyasına giden yolu inceliyor. GCC/ELF, makine kodu deyim kataloğu ve teorik sınırlar başka ajanların alanında; onlara yalnız gerektiği kadar değinildi.

**Ortam (2026-10-15):**
- Derleyici: Apple clang 21.0.0 (clang-2100.3.34.2), hedef `arm64-apple-darwin25.6.0`.
- Bağlayıcı: `ld-27037.1`. Bu, yeni bağlayıcı ("ld-prime"). `ld -v` çıktısındaki LTO satırı "LLVM version 21.0.0" diyor.
- Sistem: macOS 26.7.1 (25G241). Yalnız CommandLineTools kurulu, Xcode yok.

**Sürüm eşlemesi (varsayım).** Upstream karşılaştırmaları `llvmorg-21.1.0` etiketine göre yapıldı. Apple, Apple clang'ın hangi upstream commit'ine dayandığını yayımlamıyor. "Apple clang 21 ≈ LLVM 21" eşlemesinin tek dayanağı bağlayıcının LTO satırı; bu yüzden bir **varsayım** olarak okunmalı.

**Bu makineye özgü tuzak.** PATH'te `/opt/anaconda3/bin` önde geliyor. `ld`, `nm`, `otool` ve `strip` komutları conda'nın cctools-port kopyalarına gidiyor (`arm64-apple-darwin20.0.0-*`, ld64-530, 2022). Bu yüzden bütün deneylerde Apple araçları mutlak yolla çağrıldı (`/Library/Developer/CommandLineTools/usr/bin/…`, `/usr/bin/dyld_info`). Bölüm 4.5'teki "sahte strip" bulgusunun anahtarı bu ayrıntı.

**Deney dosyaları:** `deney_llvm/` altında. Kaynaklar `src/` ve `lto/`, betikler `run1.sh`, `run2.sh` ve `parse_pipe.py`, çıktılar `out/` içinde.

---

## 1. Özet

1. **Apple clang upstream'den ayrılıyor: sıcak/soğuk bölme varsayılan açık.** -O1, -O2, -O3 ve -Os'ta açık (upstream'de kapalı); -Oz'de kapalı. Soğuk kod `foo.cold.N` adlı ayrı parçalara taşınıyor. Bu parçalar `minsize` olarak işaretlendiği için MachineOutliner -O2'de bile `OUTLINED_FUNCTION_N` üretiyor. Taranan 300 Homebrew arm64 yürütülebilirinin 194'ünde `.cold.`, 189'unda `OUTLINED_FUNCTION` var.
2. **İmzayı değiştiren geçişler ismi değiştirmiyor.** IPSCCP, DeadArgElim ve (-O3'te) ArgumentPromotion Apple clang 21'de isme sonek eklemiyor. Bu yüzden binary'deki parametre sayısı kaynaktakinden az olabilir. Function specialization `.specialized.N` üretiyor, ama varsayılan maliyet modeli küçük fonksiyonlarda tetiklenmedi.
3. **Bağlayıcı özdeş fonksiyonları katlıyor.** -O2, -Os ve -Oz bağlamalarında ld, dışa aktarılmayan (static ya da hidden) özdeş fonksiyonları tek adrese katlıyor. clang -O0 ve -O1'de `-no_deduplicate` geçiriyor. Sonuç: ölçümdeki gerçek isim (GT) listesinde bir adres bir isim kümesi demek.
4. **"Sahte strip"in iki kaynağı ölçüldü:**
   - `strip -x` türü soyma: codex'te 19.450 global isim kaldı.
   - Export trie'yi yeniden yazmayan eski cctools-port `strip`: bu makinede PATH'te Apple'ınkinin önünde.

   Güncel Apple `strip` ise trie'yi de temizliyor.
5. **Fonksiyon sınırları her zaman elde.** LC_FUNCTION_STARTS, `__unwind_info` ve export trie strip'ten sağ çıkıyor. Soğuk ve outline edilmiş parçalar da bu listede.
6. **LTO isimleri değiştiriyor:**
   - ThinLTO'nun `.llvm.<hash>` soneki ld-prime çıktısında görünmüyor; sembol `_helper` olarak kalıyor ve `nm -m` "was a private external" diyor.
   - Tam LTO, çakışan static isme `.1` ekliyor.
   - LTO, global fonksiyonları içe alıp export trie'den düşürüyor.
7. **Apple ABI izleri tip kurtarmaya yarıyor.** 32 bitten kısa argümanı çağıran taraf genişletiyor. Variadic argümanlar yığından geçiyor. Struct dönüşü x8 üzerinden. `__strcpy_chk` çağrısının 3. argümanı hedef tamponun boyutu.

---

## 2. Hat (pipeline)

### 2.1 Ön uç: kaynak → AST → LLVM IR

Clang sırasıyla önişlemciyi, ayrıştırıcıyı ve anlam denetimini (AST) çalıştırır, sonra CodeGen ile LLVM IR üretir. RE açısından önemli üç ön uç davranışı var.

**1. Ertelenmiş üretim.** İç (static) fonksiyonların IR'ı ancak kullanıldıklarında üretilir. Hiç çağrılmayan bir static fonksiyon -O0'da bile nesne dosyasına girmez (Deney E1, `s_unused`). `always_inline` fonksiyonlar -O0'da AlwaysInliner ile gömülür, sonra gövdeleri atılır (E1: `ai` hiçbir seviyede sembol olarak çıkmıyor). Ertelenmiş üretimin bir yan etkisi de dosya içi sırada görülür: static fonksiyonlar kaynak sırasına göre değil, ilk kullanıldıkları fonksiyondan sonra yerleşir (E5: `ssame1/2` `main`'den sonra geliyor).

**2. FORTIFY varsayılan açık.** macOS SDK'sı `_FORTIFY_SOURCE`'u varsayılan olarak 2 yapıyor (`usr/include/_types.h:64-70`; koşul: dağıtım hedefi macOS 10.5 veya üstü). Bu yüzden `strcpy`, `memcpy` gibi çağrılar `__*_chk` biçimine dönüşür ve hedefin derleme zamanında bilinen boyutunu argüman olarak taşır (E7).

**3. Öznitelikler.** Fonksiyonlara şu öznitelikler eklenir (deney):

| Seviye | Öznitelik |
|---|---|
| -O0 | `noinline optnone` |
| her seviye | `"frame-pointer"="non-leaf"` |
| her seviye | `ssp` (sürücü `-stack-protector 1` geçiriyor) |
| her seviye | `"stack-protector-buffer-size"="8"` |
| her seviye | `"probe-stack"="__chkstk_darwin"` |
| her seviye | `"target-cpu"="apple-m1"` |

### 2.2 Orta uç: yeni pass manager, seviye × geçiş

**Yöntem.** `clang -O<L> -c p.c -mllvm -print-pipeline-passes` çıktısı düzleştirildi (`parse_pipe.py`, `out/pipe_matrix.txt`). Toplam geçiş örneği / farklı geçiş sayıları:

| Seviye | Örnek | Farklı geçiş |
|---|---|---|
| -O0 | 9 | 9 |
| -O1 | 92 | 65 |
| -O2 | 110 | 77 |
| -O3 | 115 | 81 |
| -Os | 108 | 75 |
| -Oz | 107 | 74 |

**Tablo okuma kılavuzu:** hücredeki sayı, geçişin hatta kaç kez yer aldığını; `–` ise hiç yer almadığını gösterir.

| Geçiş | O0 | O1 | O2 | O3 | Os | Oz | Not |
|---|---|---|---|---|---|---|---|
| `always-inline` | 1 | 1 | 1 | 1 | 1 | 1 | -O0'da tek gömücü |
| `inline` (CGSCC) | – | 1 | 1 | 1 | 1 | 1 | eşikler §3 |
| `sroa` | – | 4 | 4 | 4 | 4 | 4 | |
| `mem2reg` | – | 1 | 1 | 1 | 1 | 1 | |
| `early-cse` | – | 3 | 3 | 4 | 3 | 3 | |
| `gvn` | – | – | 1 | 1 | 1 | 1 | -O1'de yok |
| `licm` | – | 3 | 4 | 4 | 4 | 4 | |
| `loop-unroll` | – | 1 | 1 | 1 | 1 | 1 | parametre: O1→`<O1>`, O3→`<O3>`, O2/Os/Oz→`<O2>` |
| `loop-unroll-full` | – | 1 | 1 | 1 | 1 | 1 | |
| `loop-vectorize` | – | 1 | 1 | 1 | 1 | 1 | O1: vektörleme ve iç içe geçirme yalnız pragma ile; Oz: vektörleme yalnız pragma ile |
| `slp-vectorizer` | – | – | 1 | 1 | 1 | 1 | |
| `tailcallelim` | – | 1 | 2 | 2 | 2 | 2 | |
| `ipsccp` | – | 1 | 1 | 1 | 1 | 1 | FuncSpec yalnız O1/O2/O3'te (upstream kaynağı, §3) |
| `deadargelim` | – | 1 | 1 | 1 | 1 | 1 | |
| `argpromotion` | – | – | – | 1 | – | – | yalnız O3 |
| `globalopt` | – | 2 | 2 | 2 | 2 | 2 | |
| `globaldce` | 1 | 2 | 2 | 2 | 2 | 2 | |
| `constmerge` | – | 1 | 1 | 1 | 1 | 1 | |
| `called-value-propagation` | – | 1 | 1 | 1 | 1 | 1 | |
| `jump-threading`, `correlated-propagation`, `dse`, `mldst-motion`, `speculative-execution`, `aggressive-instcombine`, `constraint-elimination` | – | – | ✓ | ✓ | ✓ | ✓ | O2'den itibaren |
| `chr`, `callsite-splitting`, `extra-vector-passes` | – | – | – | ✓ | – | – | yalnız O3 |
| `libcalls-shrinkwrap` | – | ✓ | ✓ | ✓ | – | – | boyut seviyelerinde yok |
| **`hotcoldsplit`** | – | ✓ | ✓ | ✓ | ✓ | – | **Apple'a özgü varsayılan**; upstream'de `hot-cold-split` varsayılan olarak kapalı |
| `cpa-optimizer` | – | ✓ | ✓ | ✓ | ✓ | ✓ | Apple'a özgü; upstream karşılığı ve işlevi **doğrulanamadı** |
| `mergefunc` | – | – | – | – | – | – | hiçbir seviyede yok; upstream'de `enable-merge-functions` varsayılan olarak `false` |
| `rel-lookup-table-converter` | – | ✓ | ✓ | ✓ | ✓ | ✓ | `switch` tabloları göreli ofset tablolarına dönüşür |

**-O2 sırası** (parametresiz, kısaltılmış; tam metin `pipe_O2.txt` içinde). Hat dört aşamada ilerliyor:

1. **Erken temizlik ve modül çapı yayılım:**
   `annotation2metadata, forceattrs, inferattrs, coro-early, function(lower-expect, simplifycfg, sroa, early-cse), openmp-opt, ipsccp, called-value-propagation, globalopt, function(mem2reg, instcombine, simplifycfg), always-inline`
2. **CGSCC turu: gömme ve fonksiyon içi sadeleştirme:**
   `cgscc(devirt(inline, function-attrs, …, function(sroa, early-cse, …, tailcallelim, …, loop-mssa(licm, loop-rotate, licm, simple-loop-unswitch), …, loop(loop-idiom, indvars, loop-deletion, loop-unroll-full), sroa, …, gvn, sccp, bdce, instcombine, …, adce, memcpyopt, dse, …)))`
3. **Modül çapı ölü kod temizliği:**
   `deadargelim, globalopt, globaldce, elim-avail-extern, rpo-function-attrs`
4. **Döngü ve vektör optimizasyonları, son temizlik:**
   `function(float2int, …, loop-distribute, loop-vectorize, loop-load-elim, instcombine, simplifycfg, slp-vectorizer, vector-combine, loop-unroll, …, loop-sink, instsimplify, div-rem-pairs, tailcallelim, simplifycfg), hotcoldsplit, globaldce, constmerge, cg-profile, rel-lookup-table-converter, function(cpa-optimizer)`

**Upstream kaynakla tutarlılık** (`llvmorg-21.1.0`, `PassBuilderPipelines.cpp`):
- `buildInlinerPipeline` içinde ArgumentPromotion yalnız `Level == OptimizationLevel::O3` koşulunda ekleniyor.
- `buildModuleSimplificationPipeline` içinde IPSCCP'ye function specialization izni veriliyor: `AllowFuncSpec = Level != Os && Level != Oz && !isLTOPreLink(Phase)`.
- `MergeFunctionsPass` yalnız `PTO.MergeFunctions` doğruysa ekleniyor.
- `HotColdSplittingPass` yalnız `EnableHotColdSplit && !LTOPreLink` koşulunda ekleniyor; `EnableHotColdSplit`'in açık bir başlangıç değeri yok, yani varsayılanı `false`.

**Apple'daki sıcak/soğuk bölme anahtarı.** Bölmeyi `-mllvm -hot-cold-split=false` kapatmadı. Kapatan, cc1 seçeneği `-Xclang -fno-split-cold-code` oldu (sürücü bu seçeneği "did you mean" önerisiyle gösterdi). Yani Apple bölmeyi cc1 düzeyinde açıyor (E4).

### 2.3 Arka uç: komut seçimi, register ataması, prolog/epilog

**Komut seçimi.** `-mllvm -debug-pass=Structure` çıktısına göre:

| Seviye | Komut seçici | Register ataması |
|---|---|---|
| -O0 | GlobalISel (`IRTranslator → Legalizer → RegBankSelect → InstructionSelect`), yedek olarak SelectionDAG | Fast |
| -O1, -O2, -Oz | SelectionDAG ("AArch64 Instruction Selection") | Greedy |

Fast ayırıcı her değeri yığına yazıp geri okur. -O0 kodunda bu `str`/`ldr [sp, #k]` çiftleri olarak görünür.

**-O2 makine hattından RE için önemli halkalar (sırasıyla):**
- `stack-protector` (IR düzeyi) → `aarch64-isel`
- `early-tailduplication`, `machine-combiner`, `aarch64-ccmp`, `early-ifcvt`
- `machinelicm`, `machine-cse`, `machine-sink`
- `greedy` → `shrink-wrap` → `prologepilog`
- `branch-folder`, `tailduplication` → `aarch64-ldst-opt` (ldp/stp birleştirme)
- `postmisched` → `block-placement` → `aarch64-collect-loh`
- **`machine-outliner`** → `aarch64-ptrauth` → `branch-relaxation` → `aarch64-jump-tables` (sıkıştırılmış atlama tabloları) → asm yazıcı

**Prolog ve epilog:**
- **Prolog:** `stp x29, x30, [sp, #-N]!` (ya da `sub sp` + `stp`), ardından callee-saved çiftleri (`stp x20, x19, …`) ve `add x29, sp, #…`.
- **Yaprak fonksiyonlar:** `non-leaf` politikası gereği çoğunlukla çerçevesiz (E2: `k_const` 3 komut).
- **Büyük çerçeveler:** `bl ___chkstk_darwin` ile yığın yoklanır. Deneyde çerçeve boyutu w9'a yükleniyor (8192 baytlık dizi için `mov w9, #0x2010`), ardından GOT üzerinden `blr x16` geliyor.
- **Unwind bilgisi:** Kaydedilen register çiftleri `__unwind_info` içinde compact-unwind kodlaması olarak durur ve strip'ten etkilenmez.

**Doğrulanmamış iki not:**
- `aarch64-collect-loh`, nesne dosyasına bağlayıcı ipuçları (LOH) yazar. Bağlayıcının bunlarla `adrp+add` dizisini gevşettiği bilinir, ama bu oturumda gözlenmedi.
- `global-merge` ve `aarch64-promote-const` geçişleri -O2 hattında var; etkileri test edilmedi.

### 2.4 Bağlayıcı: ld-prime

**Sürüm.** Kurulu bağlayıcı `ld-27037.1`. `-Wl,-ld_classic` artık destek görmüyor; bağlayıcı uyarı verip seçeneği yok sayıyor.

**clang sürücüsünün davranışı** (E5'teki `-###` çıktısı):

| Durum | `-no_deduplicate` geçiyor mu? |
|---|---|
| -O0 veya -O1 açıkça verildi | Evet |
| -O verilmedi, derleme ve bağlama birlikte | Evet |
| -O2, -Os, -Oz | Hayır |
| Yalnız bağlama | Hayır |

Bu davranış upstream kaynakla birebir uyuşuyor: `clang/lib/Driver/ToolChains/Darwin.cpp`, `shouldLinkerNotDedup`, koşul "ld64 ≥ 262". `-dead_strip` hiçbir seviyede varsayılan değil.

**Varsayılan çıktı biçimi (E9):**
- `LC_DYLD_CHAINED_FIXUPS` ve `LC_DYLD_EXPORTS_TRIE`. `LC_DYLD_INFO_ONLY` yok, tembel bağlama (lazy binding) yok.
- `LC_FUNCTION_STARTS` ve `LC_DATA_IN_CODE`.
- `LC_CODE_SIGNATURE`: arm64 için bağlayıcı ad-hoc imza atıyor.

---

## 3. Geçiş başına tablo

**Gömücü eşikleri** (upstream, `llvmorg-21.1.0`):

| Durum | Eşik | Kaynak |
|---|---|---|
| O1/O2 varsayılanı | 225 | `InlineCost.cpp`: `inline-threshold`, `inlinedefault-threshold` |
| -O3 | 250 | `InlineCost.h`: `OptAggressiveThreshold` |
| -Os | 50 | `InlineCost.h`: `OptSizeThreshold` |
| -Oz | 5 | `InlineCost.h`: `OptMinSizeThreshold` |
| `inlinehint` | 325 | `InlineCost.cpp` |
| soğuk callee | 45 | `InlineCost.cpp` |
| sıcak çağrı yeri | 3000 | `InlineCost.cpp` |

"Son çağrı static bonusu" artık hedefe özgü değer döndüren `TTI.getInliningLastCallToStaticBonus()` üzerinden geliyor. Bu değer bu oturumda **doğrulanmadı**.

| Geçiş (seviye) | Ne yapar | Kaynağa ait neyi siler / dönüştürür | Makine kodundaki iz | Karadul ne kazanır |
|---|---|---|---|---|
| **AlwaysInliner** (O0+) / **Inliner** (O1+) | Çağrıyı callee gövdesiyle değiştirir. | Fonksiyon sınırı, isim, çağrı kenarı. Tek çağrılan static fonksiyon tamamen kaybolur. E1: `once` O1'den Oz'ye kadar her seviyede gömüldü; iki kez çağrılan `twice` yalnız Oz'de (eşik 5) ayrı kaldı. | Çağıranda büyümüş gövde; aynı komut dizisi birden fazla çağıranda tekrar eder. | Gömülmüş static'in ismi bilgisel olarak yok; GT'de de yok, yani recall paydasını küçültür. Kazanç: tekrar eden gövde kalıbını tanıyıp "satıriçi X" diye açıklama vermek (klon tespiti). |
| **SROA / mem2reg** (O1+) | Yığın yuvalarını SSA register'lara çevirir; struct'ları alanlarına böler. | Değişken–bellek eşlemesi, struct sınırı, yerel değişken sayısı. | -O0: her değişken için `[sp/x29, #k]` yuvası. -O1+: adresi alınmayan değişkenler yalnız register'da yaşar. | -O0 binary'de yığın ofseti = değişken; yerel isim ve tip kurtarmak kolay. -O2'de yerel değişkenin varlığı bile kayıp; Karadul'un "yerel isim recall tavanı ≈ 0" bulgusuyla tutarlı. Yığında kalanlar (diziler, adresi alınanlar) tip ve boyut kanıtı verir. |
| **EarlyCSE / GVN (O2+) / LICM** | Ortak ifadeleri tekilleştirir; döngüde değişmeyen hesabı dışarı taşır. | İfade ile satır eşlemesi; tekrar eden hesaplar. | Bir register birden çok kaynak ifadeye hizmet eder; döngü öncesi blokta yüklemeler ve adres hesapları. | Decompile çıktısında kaynakta olmayan ara değişkenler doğaldır. "Bir değişken = bir kaynak ismi" varsayımı yanlıştır. |
| **LoopVectorize** (O2/O3/Os; O1 ve Oz'de yalnız pragma) / **SLP** (O2+) / **LoopUnroll** | Döngüyü NEON ile vektörler, iç içe geçirir, kalanı skaler işler. | Kaynaktaki tek döngü üç kopyaya bölünür. | E11 `sum`: O1'de 32 komut, O2'de 125 komut. 16 öğelik gövde (`ldp q4,q5` + 4×`add.4s`), ardından 4'lük ikinci vektör döngüsü, `addv.4s` indirgeme ve skaler kuyruk. Os'ta 29, Oz'de 28 komut. | **Tarif kuralı:** "n<4 → skaler; n<16 → 4'lük; değilse 16'lık gövde + `addv`" iskeletini tek `for` döngüsüne katla. İndirgeme işlemi (add/fmla/max) döngünün anlamını verir: toplam, iç çarpım, saxpy. |
| **TailCallElim** (IR, O1+) ve arka uç kuyruk çağrısı | Kendini çağırmayı döngüye çevirir; son konumdaki çağrıyı `b` yapar. | Çağrı/dönüş ilişkisi. | E2: `tail()` tek komut `b _k_const`. Epilog + `b hedef`. | Hedefi LC_FUNCTION_STARTS'ta bir başlangıç olan `b` komutunu **çağrı kenarı** say. Böylece çağrı grafiği eksik kalmaz ve iki fonksiyonun birleştirilmesi önlenir. |
| **IPSCCP** (O1+) + **FunctionSpecialization** (O1–O3; Os/Oz ve LTO ön bağlamada kapalı) | Modül çapında sabit yayar; sabit argümanlar için fonksiyonu klonlar. | Sabit parametreyi ve ona bağlı dalları siler. | E2: `k_const(x, 3)` → `k_const(x)`, gövde `x*7` (`lsl w8,w0,#3; sub w0,w8,w0`). FuncSpec: varsayılan maliyetle tetiklenmedi; `-funcspec-min-function-size=1` ile `apply.specialized.1` ve `apply.specialized.2` oluştu. | İmza veritabanı eşleşmesinde parametre sayısı esnek olmalı. `.specialized.N` normalize edilmeli. Aynı gövdenin sabitle özelleşmiş kopyaları tek isme bağlanmalı. |
| **DeadArgElim** (O1+) | İç fonksiyonların kullanılmayan argümanını ve dönüş değerini siler. | Parametre sayısı. Apple clang 21'de **isim değişmiyor**. | E2: `unused_arg(x, unused)` → tek parametre; `x1` hiç okunmuyor. | Static fonksiyonun binary ABI'si kaynaktan farklı. "x1 okunmuyor ⇒ tek parametre" çıkarımı makine düzeyinde doğru, kaynak düzeyinde yanlış olabilir. |
| **ArgumentPromotion** (yalnız O3) | Yalnız okunan işaretçi parametreyi değere çevirir. | İşaretçi tipi; dolaylı erişim. | E2: O2'de `by_ptr` içinde `ldr w8,[x0]` var. O3'te imza `by_ptr(i32)`, yükleme çağırana taşınmış. | O3 binary'de "değer parametresi" aslında işaretçi olabilir. Yükleme çağırana geçer; tip kurtarmada çağıranı da oku. |
| **GlobalOpt / GlobalDCE / ConstMerge** (O1+; GlobalDCE O0'da da) | Ölü globalleri siler, tek değer alan globali sabite çevirir, özdeş sabitleri birleştirir. | Global değişkenler ve isimleri; sabitlerin sahipliği. | Paylaşılan `__const` ve `__cstring` girdileri. | "Bu sabit bu fonksiyona ait" varsayımını gevşet; string kanıtı birden çok fonksiyona işaret edebilir. |
| **MergeFunctions** | IR düzeyinde özdeş fonksiyonları birleştirir. | — (varsayılan **kapalı**) | — | Apple'da ICF işini bağlayıcı yapıyor (§4.2). |
| **HotColdSplitting** (Apple: O1/O2/O3/Os) | Soğuk blokları `parent.cold.N` fonksiyonuna taşır ve onu `cold minsize noreturn` işaretler. Soğuk sayılanlar: `cold` bir fonksiyonu çağıran blok (macOS SDK `_abort.h:33`: `abort(void) __cold __dead2`), `unreachable` ile biten blok, EH blokları. | Fonksiyonun bir kısmı ayrı "fonksiyon" olur. | E4: `work.cold.1` ve `main.cold.1` (`main`'e gömülen `work`'ün soğuk yolu da ayrı parça). Parçalar TU'nun metin bölümünün sonunda; `ret` yok, `bl _abort` ile bitiyor. Ana gövdede `b.lt` ile parçaya dallanılıyor. | Parçayı ebeveyne bağla: tek çağıran + noreturn + bölüm sonu. İsmini `ebeveyn.cold.N` diye türet ve decompile'da ebeveyne geri ekle. GT'de ayrı sınıf olarak tut (§7). |
| **MachineOutliner** (MIR; O2/Os/Oz hattında var, varsayılan olarak yalnız `minsize` fonksiyonlarda çalışır) | Tekrar eden komut dizilerini `OUTLINED_FUNCTION_N` fonksiyonuna taşır. | Kaynağa ait olmayan yapay fonksiyon ekler; çağıranın gövdesini parçalar. | E10: O2/Os'te yok, Oz'de 4 parça. `-moutline` O2'de açıyor, `-mno-outline` Oz'de kapatıyor. Cold parçalar `minsize` olduğu için O2'de de çıkıyor (E4). Parçanın prologu yok, çağıranın callee-saved register'ını (x19) okuyor, `ret` ya da `b hedef` ile bitiyor. | Bu parçaların kaynak ismi yok: **isim verme**. Çağıranlara geri göm (de-outline), sonra decompile edip isimlendir. GT'den çıkar. |
| **SimplifyLibCalls** (InstCombine içinde) | libc çağrılarını eşdeğer, daha ucuz çağrılara çevirir. | Kaynaktaki çağrı biçimi. | E4: `fprintf(stderr, "abort ediliyor\n")` → `fwrite(s, 0xf, 1, stderr)` (`mov w1,#0xf; mov w2,#1; b _fwrite`). | `fwrite` + sabit uzunluk + `stderr` ⇒ kaynakta `fprintf`/`fputs`. İsimlendirme kanıtını bu tür eşdeğer çağrılarla da eşle. |
| **Stack protector** (`ssp`, seviye 1) + **FORTIFY** | 8 bayt ve üstü char dizisi (ya da alloca) içeren fonksiyona kanarya ekler; `str*`/`mem*` çağrılarını `_chk` biçimine çevirir. | — | E7 `buf`: GOT'tan `___stack_chk_guard` yükleme, sonda karşılaştırma ve `bl ___stack_chk_fail`; `__strcpy_chk(dst, src, 0x40)`. `int a[4]` içeren `nobuf` korunmuyor. | Kanarya ⇒ çerçevede 8 bayt veya daha büyük char dizisi var. `_chk` çağrısının 3. argümanı ⇒ hedef boyutu (`char b[64]`). Bu, yerel dizi tipini ve boyutunu kurtarır. |

---

## 4. Bağlayıcı ve strip

### 4.1 Ölü kod ayıklama (`-dead_strip`)

`man ld`'e göre `-dead_strip`, giriş noktasından ya da dışa aktarılan sembollerden ulaşılamayan fonksiyon ve verileri siler. clang bu seçeneği varsayılan olarak geçirmiyor.

E6'da `-Wl,-dead_strip` ile:
- `_g_unused` silindi.
- Export trie `__mh_execute_header, _main` ikilisine indi.
- LC_FUNCTION_STARTS 4'ten 2'ye indi.

Yani yürütülebilirde globaller tek başına kök sayılmadı. Kök sayılmaları için `-exported_symbol` ya da `-export_dynamic` gerekiyor.

### 4.2 Özdeş kod katlama (dedup / ICF)

**Varsayılan durum.** Dedup ld'de varsayılan açık. clang -O0 ve -O1'de `-no_deduplicate` ile kapatıyor (§2.4). İlgili `man ld` seçenekleri:

| Seçenek | İşlev |
|---|---|
| `-no_deduplicate` | katlamayı kapatır |
| `-keep_duplicates_list` | listedeki sembolleri katlamanın dışında tutar |
| `-verbose_deduplicate` | katlanan fonksiyonları raporlar |

**Neyin katlandığı (E5):**

| Fonksiyon çifti | Görünürlük | -O2'de katlandı mı? |
|---|---|---|
| `ssame1/ssame2` | static | **Evet**: ikisi de `0x5bc` adresinde, iki ayrı `t` sembolü |
| `same1/same2` | global, adresi alınmış | Hayır |
| `gsame1/gsame2` | global, adresi alınmamış | Hayır |
| `gsame1/gsame2` + `-fvisibility=hidden` | hidden | **Evet** |

Sonuç: katlama yalnız dışa aktarılmayan fonksiyonlara uygulanıyor. Dışa aktarılan globallerin adres kimliği korunuyor.

`-verbose_deduplicate` çıktısı: `code deduplicated functions 1 (size: 16) out of total 5 (size: 228)`.

**GT etkisi.** Strip edilmemiş binary'de bir adreste birden çok isim bulunur. Bu isimler bir **takma ad kümesi** oluşturur ve kümedeki her isim doğru sayılmalıdır. Strip sonrası tek bir gövde kalır.

### 4.3 Order file ve varsayılan yerleşim

`-order_file` verildiğinde, dosyada listelenen semboller kendi bölümlerinin başına, dosyadaki sırayla taşınır (`man ld`).

**Varsayılan yerleşim** (order file ve LTO yokken, deneylerde gözlendi):
- Nesne dosyaları komut satırı sırasıyla yerleşir.
- Bir TU'nun içinde global fonksiyonlar kaynak sırasıyla gelir.
- Static fonksiyonlar ilk kullanıldıkları fonksiyondan sonra gelir.
- `OUTLINED_FUNCTION_*` ve `*.cold.N` parçaları TU'nun sonunda yer alır (E4: `work, main, OUTLINED_0, OUTLINED_1, work.cold.1, main.cold.1`).

**Karadul açısından:** Order file, PGO ve LTO bu "TU komşuluğu" sinyalini bozar.

### 4.4 LTO / ThinLTO ve static fonksiyonlar (E8)

`lto/a.c` ve `lto/b.c` dosyalarının ikisinde de `static int helper` var; `a.c`'de ayrıca `api` ve `api_unused` tanımlı.

| Bağlama | Metin sembolleri (nm) | Export trie |
|---|---|---|
| LTO yok | `T _api`, `T _api_unused`, `T _main`, `t _helper` ×2 | `__mh_execute_header`, `_api`, `_api_unused`, `_main` |
| ThinLTO | `T _main`, `t _helper` (`nm -m`: "was a private external"), `t _helper` | `__mh_execute_header`, `_main` |
| Tam LTO | `T _main`, `t _helper`, **`t _helper.1`** | `__mh_execute_header`, `_main` |
| LTO + `-Wl,-export_dynamic` | yukarıdakilere ek olarak `T _api`, `T _api_unused` | (ölçülmedi) |

**ThinLTO ara nesnesi** (`-Wl,-object_path_lto` ile alındı). ThinLTO, başka modüle aktarılan static fonksiyonu `_helper.llvm.14500278487775878913` adıyla "private external" yapıyor. **Son binary'de bu sonek yok:** sembol `_helper` olarak duruyor ve `nm -m` "non-external (was a private external)" diyor; `strings` çıktısında `llvm.` geçmiyor. Bu, ld-27037.1 + libLTO ile ölçülen bir davranış. Mekanizması (sonekin bağlayıcıda mı, libLTO'da mı silindiği) **doğrulanmadı**.

**Sonuçlar:**
1. Mach-O'da LTO izi `.llvm.` soneki değil. İz şu üçlü:
   - static isim çakışmalarında `.1`, `.2` sonekleri (tam LTO),
   - "was a private external" işaretli yerel semboller,
   - export trie'nin yalnız `_main` ve `__mh_execute_header` kalacak kadar daralması.
2. LTO, `-export_dynamic` verilmedikçe global fonksiyonları içe alıyor (`man ld`'deki `-export_dynamic` açıklaması da bunu söylüyor). Dolayısıyla LTO'lu binary'de "sahte strip" sızıntısı çok daha küçük.
3. Aynı isimli iki static (`_helper` ×2) GT'de isim tekilliği varsayımını bozar. Karadul'un "unique-in-binary" sezgisi buna karşı kırılgan.

### 4.5 Strip türleri, export trie ve "sahte strip" (E6)

Kaynak `inline.c`, `-O2` ile derlendi.
- **Sembol tablosu** sütunu `nm` çıktısını gösteriyor; tüm satırlarda `U _printf` de var.
- **FS** sütunu LC_FUNCTION_STARTS girdi sayısı.
- **radr** sütunu Apple `strip`in eklediği `radr://5614542` OPT sembolünü gösteriyor.

| Varyant | Sembol tablosu | Export trie | FS | radr | İmza |
|---|---|---|---|---|---|
| düz | `__mh_execute_header`, `_g_api`, `_g_unused`, `_main` (T); `_ni` (t) | 4 isim | 4 | – | geçerli |
| `-g` (dSYM yok) | düz + 21 STAB girdisi (debug map) | 4 isim | 4 | – | geçerli |
| `-Wl,-x` | `_ni` (t) yok | 4 isim | 4 | – | geçerli |
| `-Wl,-S` | düzle aynı (zaten STAB yok) | 4 isim | 4 | – | geçerli |
| `-Wl,-dead_strip` | `_g_api`, `_g_unused` yok | 2 isim | 2 | – | geçerli |
| Apple `strip` | yalnız `__mh_execute_header` | **yalnız `__mh_execute_header`** | 4 | ✓ | geçerli |
| Apple `strip -x` | T'ler kalır, t gider | 4 isim | 4 | ✓ | geçerli |
| Apple `strip -S` | düzle aynı | 4 isim | 4 | – | geçerli |
| **conda `strip`** (cctools-port) | yalnız `__mh_execute_header` | **4 isim: `_g_api`, `_g_unused`, `_main` hâlâ trie'de** | 4 | – | **bozuk** ("code object is not signed at all") |

**Yorum:**
- `man strip`'e göre seçeneksiz `strip`, dinamik bağlanan bir yürütülebilir üzerinde `-u -r` ile aynı etkiyi yapar. Güncel Apple `strip` bu modda export trie'yi de yeniden yazıyor; trie'de `_main` bile kalmıyor.
- **"Sahte strip" görünümünün ölçülen iki kaynağı:**
  - (a) `strip -x` ya da eşdeğeri. Global semboller hem LC_SYMTAB'te hem trie'de kalır. Örnek: codex (§4.6).
  - (b) LC_DYLD_EXPORTS_TRIE'yi tanımayan ya da yeniden yazmayan eski cctools-port `strip`. Bu makinede PATH'te ilk sırada.
- Karadul'un eski "strip sonrası trie global isimleri tutuyor" bulgusu, ölçüm hattı PATH'teki `strip`'i çağırdıysa (b) ile açıklanabilir. Bu bir **hipotez**: eski harness'in hangi `strip`i çağırdığı bu oturumda doğrulanmadı.
- **Yürütülebilirde varsayılan:** hidden olmayan her global export trie'ye girer (düz binary'de 4 isim). Export trie yalnız global (`T`) fonksiyonlar için geçerli. Yerel `t` semboller yalnız LC_SYMTAB'te bulunur; `-Wl,-x` ya da `strip -x` onları siler.
- **Her durumda kalanlar:** LC_FUNCTION_STARTS (4 girdi; static `_ni` dahil), `__unwind_info`, LC_DATA_IN_CODE ve importlar (fixup'lardaki bağlama hedefleri).
- **`radr://5614542` işareti** Apple `strip`in parmak izi. Apple `strip` ve `strip -x`'te var, `strip -S`'te yok. Gerçek binary'lerde: codex'te var, htop ve bun'da yok.

### 4.6 Gerçek binary'ler (E12, E13)

| Binary | Dil / araç | Boyut | Metin sembolü | LC_FUNCTION_STARTS | Export trie | radr | Fixup biçimi |
|---|---|---|---|---|---|---|---|
| htop 3.5.3 (Homebrew) | C, clang | — | 221 `t` + 384 `T` = 605 | 605 | 477 | – | — |
| codex 0.162.1 (Cask) | Rust | 246,6 MB | 19.450 `T`, 0 `t` | 325.171 | 25.348 | ✓ | `LC_DYLD_INFO_ONLY` (minos 11.0) |
| bun (`~/.bun`) | Zig + C++ (JSC) | 59,9 MB | 0 | 87.479 | 555 | – | chained (minos 13.0) |

**Homebrew taraması (E13).** `/opt/homebrew/Cellar/*/*/bin/*` altındaki ilk 300 arm64 yürütülebilirde:
- 281'inde yerel `t` sembolü var,
- 194'ünde `.cold.N` var,
- 189'unda `OUTLINED_FUNCTION_N` var.

**Homebrew neden yerel sembol taşıyor?** Yerel Homebrew kaynağına bakıldı (commit `be45bb102a`, 2026-10-12):
- `shims/super/cc` içindeki `refurbish_arg` (satır 202), derleme sisteminin verdiği `-O*` ve `-g*` bayraklarını atıyor. Satır 324 yerine `-$HOMEBREW_OPTIMIZATION_LEVEL` ekliyor.
- Bu değişken clang için `Os` (`extend/ENV/super.rb:96`). Yani Homebrew şişeleri **-Os** ile derleniyor.
- `keg.rb:684-697` yalnız node-gyp eklentilerini `strip -S` ile soyuyor.
- Bağlayıcı `-x` almadıkça yerel sembolleri yazıyor (`man ld`, `-x`).

Sonuç: htop'ta 221 `t` + 384 `T` = 605 sembol, LC_FUNCTION_STARTS'taki 605 girdiyle birebir. **Homebrew binary'si fiilen sembollü bir GT kaynağı.** İstisna: kendi `strip`ini ya da `install -s` çağıran formüller.

---

## 5. Apple arm64 ABI

| Konu | AAPCS64 (Arm) | Apple arm64 | Bu oturumdaki kanıt | Karadul için |
|---|---|---|---|---|
| x18 | platform register | Ayrılmış; kullanılmaz (Apple belgesi) | — | x18 okuyan ya da yazan kod üçüncü taraf kodu değildir. |
| x29 | çerçeve kaydı isteğe bağlı | Her zaman geçerli bir çerçeve kaydını göstermeli (Apple belgesi); clang `-mframe-pointer=non-leaf` | E2: yaprak `k_const` çerçevesiz | x29 zinciri güvenilir; yığın geri izleme ve çerçeve analizi sağlam. |
| 32 bitten kısa argümanlar | callee genişletir | Çağıran genişletir; Apple belgesi çağıranı "responsible for signing or zero-extending" diye tanımlar | E7: `main` içinde `sxtb w0, w20` ve `and w1, w20, #0xffff`, ardından `bl _takes_char`; callee yalnız `add w0, w1, w0` | **Tip kurtarma:** çağrıdan hemen önce `sxtb`/`sxth` ⇒ `signed char`/`short`; `and #0xff`/`#0xffff` (ya da `uxtb`/`uxth`) ⇒ `unsigned char`/`unsigned short`. Callee tarafında bu kanıt yok; Ghidra AAPCS64 varsayımıyla `int` diyebilir. |
| Variadic argümanlar | adlandırılmış argümanlar gibi register'larda; `va_list` bir struct | Variadic argümanlar 8 baytlık yığın yuvalarında; `va_list` = `char*` (Apple belgesi) | E7: `printf` çağrısında `stp x22,x21,[sp]; stp x19,x0,[sp,#0x10]` ve yalnız x0 = format. `vsum(3,1,2,argc)` çağrısında `mov w0,#3; str x9,[sp]; stp x8,x20,[sp,#8]`. | **Tarif kuralı:** yalnız ilk k argüman register'da, gerisi `[sp]`'ye yazılıyorsa callee variadic'tir. printf ailesi sarmalayıcılarını ve format string'li logger'ları bu kuralla yakala. |
| Yığından geçen (variadic olmayan) argümanlar | 8 baytlık yuvalar | Doğal hizalamayla paketlenir; 8 bayt hizası dolgu ile korunur (Apple belgesi) | (test edilmedi) | Yığın argümanı ofsetlerini Apple kuralıyla hesapla. |
| Red zone | yok | SP'nin altındaki 128 bayt (Apple belgesi) | — | Yaprak fonksiyonlar `sub sp` yapmadan `[sp, #-k]` kullanabilir. |
| Temel tipler | `char` işaretsiz | `char` işaretli; `long double` = `double`; `wchar_t` 32 bit işaretli (Apple belgesi) | — | Tip çıkarımında platforma özgü tabloyu kullan. |
| Struct dönüşü | x8 = sonuç adresi | Aynı | E7: `main` içinde `add x8, sp, #0x20; bl _mk`; `_mk` içinde `str x0,[x8]`, `stur q0,[x8,#8]`, `str x9,[x8,#0x18]` | x8'e yazan callee ⇒ 16 bayttan büyük struct döndürüyor. `[x8, #off]` yazmaları alan düzenini ve boyutu verir (`struct Big`, 32 bayt). |
| Yığın koruyucu | — | Varsayılan seviye 1 (`ssp`, tampon eşiği 8) | E7 `buf` | §3 tablosu. |
| Yığın yoklama | — | Büyük çerçevede `___chkstk_darwin` | `big()`: `mov w9,#0x2010`, ardından `blr` | Çerçeve boyutu ⇒ büyük yerel dizi var. |
| PAC (arm64e) | — | `pacibsp`/`retab`; `__auth_stubs` içinde `braa x16, x17`; `__auth_got` | E7 arm64e: 3× `pacibsp` + 3× `retab`. Sistem binary'leri (`/bin/ls`, `/usr/bin/clang`) arm64e; Homebrew htop arm64. | arm64e dilimi ayrıca analiz edilmeli. PAC komutları anlamsal değil, kaldırılabilir. İmzalı işaretçi kodlamaları fixup'ta "auth" olarak geçer. |
| Import çağrıları | — | `__TEXT,__stubs`: 12 baytlık `adrp x16 / ldr x16,[x16,#off] / br x16`, hedef `__DATA_CONST,__got` | E9: `dyld_info -fixups` → `__got` girdileri `bind libSystem/_printf` vb. Lazy bind yok, `__stub_helper` yok. | Stub → import ismi eşlemesi kesin. Chained fixup **ve** eski `LC_DYLD_INFO_ONLY` biçiminin ikisi de desteklenmeli (codex eski biçimi kullanıyor). |

**PAC üzerine ek not.** Apple'ın ARM64 ABI sayfası (bu oturumda okunan sürümü) PAC'tan ya da arm64e'den söz etmiyor. arm64e satırındaki kanıtların hepsi deneyden geliyor.

---

## 6. Deney kayıtları

**Ortak tanımlar:**
- `B=/Library/Developer/CommandLineTools/usr/bin`
- `DI=/usr/bin/dyld_info`
- Çalışma dizini: `deney_llvm/`. Tam çıktılar `out/E*.txt` dosyalarında.

**E0. Ortam.**
```sh
clang --version; xcrun ld -v; which -a ld nm otool strip
```
- Apple clang 21.0.0 (clang-2100.3.34.2).
- `ld-27037.1` (LTO: LLVM 21.0.0).
- PATH'teki ilk `ld`, `nm`, `otool`, `strip` conda'ya ait (cctools-port, ld64-530).

**E-pipe. Orta uç hattı.**
```sh
clang -O$L -c p.c -o /dev/null -mllvm -print-pipeline-passes > pipe_O$L.txt
python3 -I parse_pipe.py
```
Sonuç §2.2'deki tablo. Arka uç için:
```sh
clang -O$L -c src/outline.c -o /dev/null -mllvm -debug-pass=Structure
```
- -O0: GlobalISel + Fast RA.
- -O1, -O2, -Oz: SelectionDAG + Greedy RA.
- "Machine Outliner" O2 ve Oz hattında var, O0'da yok.

**E1. Gömme ve static fonksiyonlar** (`src/inline.c`).
```sh
clang -O$L -c src/inline.c -o out/inline_O$L.o; $B/nm out/inline_O$L.o
```

| Sembol | O0 | O1 | O2 | O3 | Os | Oz |
|---|---|---|---|---|---|---|
| `once` (static, 1 çağrı, döngülü) | t | – | – | – | – | – |
| `twice` (static, 2 çağrı) | t | – | – | – | – | t |
| `ai` (always_inline) | – | – | – | – | – | – |
| `ni` (noinline static) | t | t | t | t | t | t |
| `g_api`, `g_unused` (global) | T | T | T | T | T | T |
| `s_unused` (static, çağrılmıyor) | – | – | – | – | – | – |

**E2. İmza değiştiren geçişler** (`src/ipo.c`).
```sh
clang -O2|-O3 -S -emit-llvm src/ipo.c -o - | grep ^define
```
IR imzaları:

| Fonksiyon | Kaynak imza | O2 | O3 |
|---|---|---|---|
| `k_const` | `(x, mode)` | `internal fastcc i32 @k_const(i32)` | aynı |
| `unused_arg` | `(x, unused)` | `@unused_arg(i32)` | aynı |
| `by_ptr` | `(const int *p)` | `@by_ptr(ptr … readonly)` | `@by_ptr(i32)` (ArgumentPromotion) |
| `ret_unused` | `(x)` | `noundef i32 … (i32 noundef returned %0)` | aynı |

- Nesne dosyasındaki isimler değişmedi; sonek yok.
- `otool -tV`: `_tail: b …` (kuyruk çağrısı), `_k_const: lsl w8,w0,#3; sub w0,w8,w0; ret`.

**E3. Function specialization** (`src/funcspec.c`).
```sh
clang -O3 -c src/funcspec.c -o /dev/null -mllvm -print-after=ipsccp [-mllvm -funcspec-min-function-size=1]
```
- Varsayılanla klon yok.
- Eşik düşürülünce `apply.specialized.1` ve `apply.specialized.2` oluştu.

**E4. Sıcak/soğuk bölme** (`src/coldsplit.c`; soğuk dal `fprintf` ve `abort` içeriyor).
```sh
clang -O$L src/coldsplit.c -o out/cold_O$L; $B/nm out/cold_O$L
```

| Seviye | Ek semboller |
|---|---|
| O0 | yok |
| O1, O2, O3 | `_work.cold.1`, `_main.cold.1`, `_OUTLINED_FUNCTION_0/1` |
| Os | `_work.cold.1` |
| Oz | yok |
| O2 + `-mllvm -hot-cold-split=false` | **değişmedi** (bölme sürdü) |
| O2 + `-Xclang -fno-split-cold-code` | bölme yok |

IR: `define internal void @work.cold.1(i64, i32) #4`; `#4 = { cold minsize nofree noreturn nounwind ssp … }`.

**E5. Bağlayıcı dedup** (`src/dedup.c`, `src/dedup2.c`).
```sh
clang -O0|-O2 src/dedup.c -o out/dedup_O$L; $B/nm -n …
```

| Bağlama | `_ssame1` | `_ssame2` | Katlandı mı? |
|---|---|---|---|
| -O2 | `0x5bc` | `0x5bc` | Evet |
| -O0 | `0x620` | `0x640` | Hayır |
| -O2 + `-Wl,-no_deduplicate` | `0x5bc` | `0x5cc` | Hayır |

- `same1/same2` (global): katlanmadı.
- `dedup2.c` global çift: katlanmadı. `-fvisibility=hidden` ile katlandı (`0x460`).
- `clang -### … | tail -1`: O0 ve O1'de `-no_deduplicate` var, O2, Os ve Oz'de yok.
- `-O2` + yalnız bağlama: yok. `-O` verilmeyen derleme+bağlama: var.
- `-Wl,-verbose_deduplicate` → `code deduplicated functions 1 (size: 16) out of total 5 (size: 228) (7.02% size reduction)`.
- `-Wl,-ld_classic` → "no longer supported and will be ignored".

**E6. Strip varyantları.**
```sh
clang -O2 [-g|-Wl,-x|-Wl,-S|-Wl,-dead_strip] src/inline.c -o out/s_*
cp s_plain s_strip; $B/strip s_strip    # ayrıca -x ve -S
$DI -exports …; $DI -function_starts …; codesign -v …
/opt/anaconda3/bin/strip s_strip_conda
```
- Sonuç §4.5'teki tablo.
- Conda `strip`in kendi çıktısı: "changes being made to the file will invalidate the code signature" ve "[cctools-port]: generating fake signature".

**E7. ABI** (`src/abi.c`).
```sh
clang -O2 src/abi.c -o out/abi_O2; $B/otool -tV …
clang -O2 -arch arm64e src/abi.c -o out/abi_O2_e
```
- Sonuç §5.
- arm64e bölümleri: `__auth_stubs`, `__auth_got`, `__got`. Stub: `adrp x17; add x17,…; ldr x16,[x17]; braa x16, x17`.

**E8. LTO.**
```sh
clang -O2 -flto=thin|-flto -c lto/a.c lto/b.c; clang -O2 -flto=… a.o b.o -o out/lto_*  [-Wl,-export_dynamic]
```
- Ara nesneler `-Wl,-object_path_lto,out/thin_tmp/obj` ile alındı.
- Sonuç §4.4.

**E9. Fixup ve stub'lar.**
```sh
$B/otool -l out/abi_O2 | grep cmd; $DI -fixups out/abi_O2; $B/otool -v -s __TEXT __stubs out/abi_O2
```
- Yük komutları: `LC_DYLD_CHAINED_FIXUPS`, `LC_DYLD_EXPORTS_TRIE`, `LC_FUNCTION_STARTS`, `LC_DATA_IN_CODE`, `LC_CODE_SIGNATURE`.
- `__got` bind hedefleri: `___stack_chk_fail`, `___stack_chk_guard`, `___strcpy_chk`, `_printf`, `_strlen`.

**E10. MachineOutliner** (`src/outline.c`).
```sh
clang -O2|-Os|-Oz [-moutline|-mno-outline] -c src/outline.c; $B/nm …
```

| Derleme | OUTLINED parça |
|---|---|
| O2, Os | 0 |
| Oz | 4 (`_OUTLINED_FUNCTION_0..3`, `t`) |
| O2 + `-moutline` | 4 |
| Oz + `-mno-outline` | 0 |

Örnek parça: `_OUTLINED_FUNCTION_0: mov w0,#4; mov w1,#5; mov w2,#6; mov x3,x19; b <sink>`.

**E11. Vektörleme** (`src/vec.c`).

| Seviye | NEON benzeri satır | Toplam komut |
|---|---|---|
| O1 | 0 | 32 |
| O2 | 7 | 125 |
| O3 | 7 | 125 |
| Os | 1 | 29 |
| Oz | 0 | 28 |

O2 `sum` iskeleti §3'te.

**E12. Gerçek binary'ler.**
```sh
$B/nm -m <bin>; $DI -function_starts|-exports <bin>; strings -a <bin> | grep '\.rs$'
```
- Sonuç §4.6 ve §6b.
- codex mangling sayımı: 23.648 legacy `__ZN…17h<hash>E`, 571 v0 `__R…`.
- codex string'leri: 6.183 `.rs` yolu (ör. `core/src/connectors.rs`) ve 90 `/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/...` yolu.
- bun export'ları: 315 `uv_*`, 145 `napi_*`, 12 `node_*`, V8 C++ API (`v8::HandleScope…`).

**E13. Homebrew taraması.** 300 arm64 yürütülebilir tarandı; sonuç §4.6.

**E14. FORTIFY ve chkstk.**
- `printf '#include <string.h>' | clang -O0|-O2 -dM -E -x c -` → her iki seviyede `_FORTIFY_SOURCE 2` ve `_USE_FORTIFY_LEVEL 2`.
- Kaynağı `SDK/usr/include/_types.h:64-70`.
- `src/chkstk.c` (`char b[8192]`): `mov w9,#0x2010` ve `ARM64_RELOC_GOT_LOAD_PAGE21 ___chkstk_darwin`.

### 6b. Rust ve Zig (soru 6, kısa)

**Rust (codex 0.162.1)**

*Hat:* rustc → LLVM IR → aynı AArch64 arka ucu. Bağlama sistem `cc` üzerinden ld-prime ile yapılıyor; yani §2.3 ve §4 aynen geçerli.

*Mangling:*
- Legacy biçim `_ZN…17h<16 hex>E`: Itanium benzeri, sonunda hash var; genel tip parametreleri hash'e gizlenir.
- v0 biçimi `_R…`: genel parametreleri açıkça kodlar.
- v0, nightly'de 2025-11-21'den, kararlı sürümde Rust 1.97'den (2026-07-09) beri varsayılan (resmî blog yazıları).
- codex'te iki biçim karışık: kalan sembollerin çoğu legacy, `std` kökenli bir kısmı v0. Bunun nedeni (araç zinciri sürümü ya da önceden derlenmiş `std`) **doğrulanmadı**.

*Monomorfizasyon:* Her genel örnek ayrı bir fonksiyon olur. Aynı yol farklı hash'lerle tekrar eder (ör. `RawVec<T,A>::grow_one::h…`). İsim kurtarmada "aynı temel isim, farklı tip" kümelemesi gerekir.

*Panic yolları:* `core::panicking::*`, sınır denetimi ve `unwrap_failed` çağrıları, kaynak `Location` kayıtlarına (dosya yolu, satır, sütun) işaret eder. codex'te 6.183 `.rs` yolu var. Bu, fonksiyonu kaynak dosyasına bağlayan, strip'ten etkilenmeyen bir kanıt. `/rustc/<commit>/` yolları derleyici sürümünü kesin verir.

*Kalan semboller:* codex'te 19.450 `T` ve 25.348 export kalmış, buna karşılık 325.171 fonksiyon başlangıcı var; isimli oran yaklaşık %6. `radr` işareti olduğu için Apple `strip` çalışmış. Global isimlerin kalması `strip -x` benzeri bir kipe işaret ediyor (rustc'nin macOS'ta kullandığı strip kipi **doğrulanmadı**). Codegen-unit'ler arası referanslar sembolleri dışa açık bırakır. GT'de bu isimler "dışa aktarılmış" sayılmalı ve puanlanmamalı.

**Zig ve Bun**

*Gözlem:* bun binary'sinde hiç metin sembolü yok; 87.479 fonksiyon başlangıcı ve 555 export var. Export'lar Node-API (`napi_*`), libuv (`uv_*`) ve V8 uyumluluk katmanından geliyor; amaç yerel eklentilerin bağlanabilmesi. radr işareti yok, yani Apple `strip` dışında bir yolla (bağlayıcı `-x -S` ya da başka araç) soyulmuş; hangisi olduğu **doğrulanmadı**.

*Doğrulanmamış genel bilgi:* Zig, sürüm derlemelerinde LLVM kullanır. İsimleri ad alanlı ve noktalıdır (`fs.File.read` gibi); genel örnekler tip parametresini ya da `__anon_N` sonekini isimde taşır. Bu oturumda bun içinde Zig fonksiyon ismi gözlenemedi.

*Karadul açısından:* İç isimler yok. Kalan kanıt fonksiyon başlangıçları, string'ler (27 `.zig` yolu) ve API export'ları.

---

## 7. Karadul için somut öneriler

### 7.1 Ölçüm ve GT (Mach-O harness)

Mevcut `scripts/measurement/function_f1.py` yalnız ELF'i (pyelftools) destekliyor. Mach-O sürümü için öneriler:

1. **Strip aracını sabitle.** `strip`i her zaman `xcrun strip` ya da `/Library/Developer/CommandLineTools/usr/bin/strip` ile mutlak yoldan çağır. Sürüm bilgisini (`ld -v`, `xcrun --find strip`) GT JSON'una yaz. Stripped dosyada `radr://5614542` OPT sembolünü denetle. Bu işaret yoksa ya da export trie'de yerel olmayan isim varsa uyarı ver; bu, §4.5'teki conda tuzağına karşı bir koruma.
2. **Export'ları ELF `.dynsym` politikasıyla puanla.** Stripped binary'nin export trie'sindeki (`dyld_info -exports`) ve kalan LC_SYMTAB'indeki isimleri "dışa aktarılmış" olarak işaretle; puanlama. Bu, mevcut ELF politikasının birebir karşılığı. Rust binary'lerinde bu ayrım F1'i şişmekten korur (codex: 19.450 isim zaten binary'de).
3. **Takma ad kümeleri tut.** Strip edilmemiş binary'de aynı adresteki tüm `t`/`T` isimleri tek kayıt altında `aliases` listesine yaz. Kümedeki herhangi bir isimle eşleşme TP sayılsın. Bu, dedup durumunu karşılar (E5).
4. **Derleyicinin ürettiği parçaları ayrı sınıflara koy.**
   - `OUTLINED_FUNCTION_\d+`: kaynakta karşılığı yok. CRT gibi GT dışında tut, ama tespit sayısına dahil et.
   - `*.cold.\d+`: "parça" sınıfı. Birincil F1'e girmesin; ayrı bir "parça → ebeveyn bağlama doğruluğu" metriği tanımla.

   Bu iki sınıf Homebrew binary'lerinin yaklaşık üçte ikisinde var (E13).
5. **Normalizasyonu LLVM soneklerine genişlet.** Şu anki kural, `tests/benchmark/metrics.py:684`:
   ```python
   re.sub(r"\.(?:constprop|isra|part|cold|lto_priv|clone)(?:\.\d+)*", "", name)
   ```
   Bu kuralda `llvm` ve `specialized` yok; tam LTO'nun yalın `.N` soneki de yok. Önerilen ekler:
   - `\.(?:llvm|specialized)(?:\.\d+)*`
   - `\.\d+$`

   C tanımlayıcısı nokta içeremediği için noktalı her sonek derleyiciye ya da bağlayıcıya aittir; silmek güvenli.
6. **Yalnız nesne dosyasında görünen sembolleri ele.** `ltmp\d+` (yalnız `.o` ve `.a` içinde) ve `l_`/`L` önekli yerel etiketler GT'ye girmesin.
7. **Derleme bayraklarını GT'ye kaydet.**
   - Homebrew GT'si fiilen **-Os** + soğuk bölme + soğuk parçalarda outline demek.
   - Kontrollü A/B için aynı kaynağı -O2, -Os, -Oz, ThinLTO ve tam LTO ile derle.
   - GT'yi strip edilmemiş eşten al; stripped dosyayı Apple `strip` ile üret.
   - LTO'lu Mach-O'da export trie çok küçülür ve static isimler `.1` sonekiyle tekrar eder. Mach-O "LTO var/yok" ayrımını bu iki işaretle otomatik yap.
8. **Tespit için LC_FUNCTION_STARTS kullan.** Mach-O'da fonksiyon sınırları LC_FUNCTION_STARTS'tan kesin geliyor (`flirt_precision.py` zaten öyle yapıyor). Kapsama ölçümünde Ghidra'nın fonksiyon bulma hatasını bu sınırlarla düzelt. Not: cold ve outline parçaları da bu listede.

### 7.2 İsim kurtarma ve tarif kuralları

| # | Kural | Tetikleyici iz | Çıktı |
|---|---|---|---|
| R1 | Soğuk parça bağlama | Fonksiyon başlangıcı + tek çağıran ya da tek dallanan + `ret` yok + son komut `bl` noreturn (`_abort`, `___stack_chk_fail`, `__assert_rtn`) + TU sonunda | İsim `ebeveyn.cold.N`; decompile'da ebeveyne ekle; ebeveynin hata işleme kanıtı (string'ler) ebeveyne aktarılır. |
| R2 | Outline geri gömme | Prologsuz, 2–8 komutluk, çağıranın callee-saved register'ını tanımsız okuyan, `ret` ya da `b` ile biten fonksiyon; ≥2 `bl` çağıranı | Hiç isim verme; çağrı yerlerine gövdeyi yapıştır (de-outline), sonra decompile et. |
| R3 | Çağıran tarafı genişletme ⇒ tip | `bl f` öncesi `sxtb`/`sxth`/`and #0xff`/`and #0xffff` (`wN`) | `f`'in N. parametresi `signed char`/`short`/`unsigned char`/`unsigned short`. |
| R4 | Variadic çağrı yeri | İlk k argüman register'da, diğerleri `[sp, #8i]` yuvalarında | `f` variadic. Ayrıca x0/x1 bir format string'e işaret ediyorsa printf ailesi ya da logger; format belirteçleri yığın yuvalarının tiplerini verir. |
| R5 | `_chk` boyutu | `___memcpy_chk`/`___strcpy_chk`/`___snprintf_chk` ve sabit boyut argümanı | Hedef yerel dizi ya da struct alanı boyutu (E7: 64). |
| R6 | Kanarya | `___stack_chk_guard` yükleme ve karşılaştırma | Çerçevede 8 bayt veya daha büyük char dizisi ya da alloca var. |
| R7 | sret | Callee'nin x8'e ofsetli yazması; çağıranın x8'e yığın adresi koyması | Dönüş tipi 16 bayttan büyük struct; alan ofsetleri ve boyut. |
| R8 | Kuyruk çağrısı | Epilog + `b X`, X ∈ LC_FUNCTION_STARTS | Çağrı kenarı ekle; X'in çağıran sayısını güncelle (imza/isim yayılımı için). |
| R9 | Vektörlenmiş döngü katlama | min-iterasyon dalları + q-register gövdesi + `addv`/`faddp` + skaler kuyruk | Tek döngü + indirgeme anlamı (sum/dot/axpy) → hesaplama-merkezli isimlendirmeye girdi. |
| R10 | Budanmış imza toleransı | Static (yerel) fonksiyon | Parametre sayısı ve tipi kaynakta daha fazla olabilir (DAE, IPSCCP, ArgPromotion). İmza veritabanında static adaylar için "≤" eşleşmesi kullan. |
| R11 | Dedup kümesi | Bir gövdeye ≥2 farklı isim adayı | İmza veritabanında takma ad kümesi sakla. Herhangi biri doğru; "tek isim seç" zorlaması yanlış FP üretir. |
| R12 | TU komşuluğu | LTO/order file izi yok (§4.4) | Adres sırası kabaca TU sırasını izler; global → static (ilk kullanımdan sonra) → outline/cold. İsimli export'ların arasındaki isimsiz fonksiyonları aynı dosyaya ve modüle kümele. |
| R13 | libcall eşdeğerliği | `fwrite(s, len, 1, stream)` + sabit uzunluk; `puts`; `putchar` | Kaynakta `fprintf(stream,"…")`/`printf("…\n")` olabilir. İsim ve kanıt eşlemesinde eşdeğer kabul et. |
| R14 | Rust panic konumu | `__const` içinde `{&str, line, col}` kaydı + panik çağrısı | Fonksiyonun kaynak dosyası ve satırı. `/rustc/<commit>/` ⇒ rustc sürümü. Legacy hash'ler ⇒ aynı temel isimli monomorfizasyon kümesi. |

### 7.3 Öncelik

1. Önce **R2 ve R1** ile 7.1/4: bunlar Homebrew GT'sini doğrudan bozan iki sınıf.
2. Sonra 7.1/1–3: ölçüm doğruluğu.
3. Sonra **R3–R7**: düşük maliyetli, kesin tip kanıtı.
4. **R9 ve R12** daha araştırma niteliğinde.

---

## 8. Kaynakça

İşaretler: **[D]** bu oturumda okunup doğrulandı · **[Y]** yerel dosyadan doğrulandı · **[E]** yalnız deneyle doğrulandı · **[?]** doğrulanmadı.

**LLVM ve Clang kaynakları**
1. LLVM, `llvm/lib/Passes/PassBuilderPipelines.cpp`, `llvmorg-21.1.0` **[D]**: IPSCCP `AllowFuncSpec`, ArgumentPromotion yalnız O3, `EnableHotColdSplit`, `EnableMergeFunctions = false`, `enable-partial-inlining = false`. https://github.com/llvm/llvm-project/blob/llvmorg-21.1.0/llvm/lib/Passes/PassBuilderPipelines.cpp
2. LLVM, `llvm/include/llvm/Analysis/InlineCost.h`, `llvmorg-21.1.0` **[D]**: 50 / 5 / 250 eşikleri. https://github.com/llvm/llvm-project/blob/llvmorg-21.1.0/llvm/include/llvm/Analysis/InlineCost.h
3. LLVM, `llvm/lib/Analysis/InlineCost.cpp`, `llvmorg-21.1.0` **[D]**: 225 / 325 / 45 / 3000; son çağrı static bonusu TTI'dan geliyor (değeri **[?]**). https://github.com/llvm/llvm-project/blob/llvmorg-21.1.0/llvm/lib/Analysis/InlineCost.cpp
4. LLVM, `llvm/lib/Transforms/IPO/HotColdSplitting.cpp`, `llvmorg-21.1.0` **[D]**: `"cold." + to_string(id)` soneki, `Cold` + `MinSize` öznitelikleri, soğuk blok ölçütleri. https://github.com/llvm/llvm-project/blob/llvmorg-21.1.0/llvm/lib/Transforms/IPO/HotColdSplitting.cpp
5. Clang, `clang/lib/Driver/ToolChains/Darwin.cpp`, `llvmorg-21.1.0` **[D]**: `shouldLinkerNotDedup`, ld64 ≥ 262 koşulu, `-moutline` → `-enable-machine-outliner`. https://github.com/llvm/llvm-project/blob/llvmorg-21.1.0/clang/lib/Driver/ToolChains/Darwin.cpp
6. AArch64 MachineOutliner'ın varsayılan olarak yalnız `minsize` fonksiyonlarda çalışması **[E]**: kaynak satırı (`AArch64InstrInfo.cpp`) bu oturumda okunmadı.
7. Apple'ın `-fsplit-cold-code` cc1 seçeneği ve `cpa-optimizer` geçişi **[E]**: Apple kaynak deposunda doğrulanmadı **[?]**.

**Apple belgeleri ve araçları**

8. Apple, "Writing ARM64 code for Apple platforms" **[D]**: x18, x29, çağıran tarafı genişletme, variadic yığın yuvaları, red zone 128, tip boyutları. https://developer.apple.com/documentation/xcode/writing-arm64-code-for-apple-platforms
9. Apple `ld(1)` man sayfası, CommandLineTools, ld-27037.1 **[Y]**: `-dead_strip`, `-order_file`, `-export_dynamic`, `-x`, `-S`, `-no_deduplicate`, `-keep_duplicates_list`, `-verbose_deduplicate`, `-no_function_starts`, `-ld_classic`. (`man ld`; dosya `/Library/Developer/CommandLineTools/usr/share/man/man1/ld.1`, CommandLineTools 27.0.0. Yerel kopya `deney_llvm/out/man_ld.txt` Apple'ın metni olduğu için depoya girmez; `man ld | col -b` aynı baytları üretir, sha256 `7487ceeb61ba9fd610d2279b9cf8d7306546feae7e446f295cd2db6fa3575190`, 2026-10-21'de doğrulandı.)
10. Apple `strip(1)` man sayfası **[Y]**: seçeneksiz kullanım yürütülebilirde `-u -r` ile eşdeğer. (`man strip`)
11. macOS SDK (CommandLineTools) **[Y]**:
    - `usr/include/_types.h:64-70`: `_FORTIFY_SOURCE 2` varsayılanı.
    - `usr/include/_abort.h:33`: `abort` `__cold __dead2` olarak bildirilmiş.
    - `usr/include/sys/cdefs.h:183`: `__cold` = `__attribute__((__cold__))`.

**Homebrew ve Rust**

12. Homebrew yerel kaynağı, commit `be45bb102a` (2026-10-12) **[Y]**: `Library/Homebrew/shims/super/cc` (satır 202, 324), `extend/ENV/super.rb` (satır 96), `keg.rb` (satır 684–697).
13. Rust Blog, "Switching to Rust's own mangling scheme on nightly", 2025-11-20 **[D]** (arama özeti + resmî URL). https://blog.rust-lang.org/2025/11/20/switching-to-v0-mangling-on-nightly
14. Rust Blog, "Announcing Rust 1.97.0", 2026-07-09 **[D]**: v0 kararlı sürümde varsayılan. https://blog.rust-lang.org/2026/07/09/Rust-1.97.0/
15. Arm, "Procedure Call Standard for the Arm 64-bit Architecture (AAPCS64)" **[?]**: yalnız Apple belgesinin karşılaştırma bağlamı üzerinden kullanıldı; bu oturumda okunmadı. https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst
