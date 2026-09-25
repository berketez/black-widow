# LTO bağımlılığı: fonksiyon-ismi hatalarının kök sebep teşhisi ve deterministik düzeltme tasarımı

Tarih: 2026-09-25 · Kapsam: karadul gnulib/ELF kurtarma kanalları · Durum: **tasarım** (kod değişikliği yok)
Zemin: `scripts/measurement/` (commit db052bd), taban `baseline_2304560.json` (HEAD 2304560, Ghidra 12.1.2,
`--output-dir` → FLIRT kapalı). LLM/ML yok; bütün kurallar deterministik, isim kaynağı yalnız upstream gnulib
kaynağı (`vendor/gnulib-ref`, pin `bb5bb43`).

## 0. Özet

1. **Debian (LTO'suz) korpusundaki 449 FN'nin 276'sı iki modülden geliyor**: `quotearg.c` (binary başına 34
   fonksiyon, toplam 170) ve `xmalloc.c` (+`xalignalloc`, toplam 106). Bu 276 fonksiyon için parmak izi DB'sinde
   **tek bir giriş yok**. Eşik ya da çakışma sorunu değil, doğrudan kapsam eksiği. Aynı libc imzasını taşıyan
   üyeler yüzünden tekil call-shape eklemek de yetmez; konumsal kanıt gerekiyor.
2. **LTO'ya bağımlı 11 FP'nin tek bir kök sebebi var**: parmak izi, çıpayı tutan fonksiyona zincirin **en dış API
   adını** veriyor (`version_etc`, `hard_locale`, `full_write`). LTO'da zincir tek fonksiyona çöktüğü için bu doğru.
   LTO'suz derlemede çıpa en içteki fonksiyonda (`version_etc_arn`, `setlocale_null_r`, `safe_write`) kalıyor,
   dış fonksiyonlar ise ayrı ve isimsiz.
3. **FP'lerin çoğu parmak izinden değil, c_namer `string_context` yedeğinden geliyor**: Debian'da 40/51,
   Ubuntu'da 16/16. Bu kanal 57 isimde yalnız 1 doğru üretti (`cut_fields`).
4. Önerilen kurallar kaydedilmiş taban artefaktları üzerinde harness'in kendi `score()` fonksiyonuyla çevrimdışı
   simüle edildi. Taban yeniden üretimi birebir tuttu. Sonuç Debian F1 **0,123 → 0,903**, Ubuntu **0,479 → 0,691**.
   Kaybedilen TP 0, kural kaynaklı FP 0. Tasarım sırasında görülmemiş 6 hold-out binary'de Debian
   **0,121 → 0,882**, Ubuntu **0,416 → 0,565**, yine kural kaynaklı FP 0. Bunlar **tahmindir**; gerçek koşu
   §5'teki kapıdan geçmeden kabul edilmez.
5. Öncelik sırası: Faz 1 (D1–D5) zincir farkındalığı ve küçük parmak izleri, düşük risk, Debian F1 0,397.
   Faz 2a (D6) quotearg hub'ları, Ubuntu'ya da +15 TP. Faz 2b (D7–D9) modül blok hizalaması; en büyük kazanç,
   orta risk, gnulib sürümüne bağımlı. P1 (c_namer politikası) Berke'nin kararına bırakılan bir ürün kararı.

## 1. Yöntem

| Adım | Nasıl | Doğrulama |
|---|---|---|
| Kanal atfı | 2304560'taki `_recover_main_from_entry` + `_recover_gnulib_from_fingerprints` + `_recover_elf_boilerplate` mantığı kaydedilmiş workspace'ler üzerinde (`static/ghidra_output/{decompiled,call_graph.json}`) yeniden oynatıldı | Oynatılan her ad `naming_map.json` ile birebir aynı. Tek fark CRT sanitizasyonu (`_start`→`start`), o da puanlanmıyor |
| c_namer adları | `naming_map.global` eksi oynatılan ön adlar | `naming_by_strategy` sayaçlarıyla tutarlı: fonksiyon adlarının tamamı `string_context` (cut'ta 1 `type_based`) |
| Simülasyon | Önerilen kurallar aynı artefaktlar üzerinde uygulandı, puanlama `function_f1.score()` (salt okuma içe aktarım) ile yapıldı. GT yalnız puanlama adımında yüklendi | Kural kapalıyken 10 binary'nin her birinde TP/FP birebir tabanla aynı (Ubuntu 41/16, Debian 35/51) |
| Hold-out | Aynı paketlerden, ölçüm korpusunda olmayan binary'ler: Debian `head, tr, uniq, nl`, Ubuntu `head, tr`. Baseline worktree'den koşuldu (en çok 2 paralel, `timeout 900`), GT aynı `extract_gt` ile üretildi | 6/6 rc=0. `~/.cache/karadul/cfg_cache` md5'i koşu öncesi ve sonrası aynı |

Çalışma dosyaları repo dışında, `/private/tmp/arge_lto/` altında (`sim.py`, `replay_channels.py`, `holdout/`).
`/tmp` kalıcı değil. Kuralların uygulanabilir tanımı bu belgenin §4 bölümünde duruyor.

## 2. Hata envanteri

### 2.1 Debian 9.4-3 (LTO'suz, 484 GT; TP 35, FP 51, FN 449)

TP kaynakları: FIX-1 `main` 5 · string-fp 11 (`usage` 5, `xalloc_die` 4, `close_stdout` 2) · call-shape 15
(`close_stream`, `rpl_fclose`, `rpl_mbrtoc32` ×5) · disambiguation 3 (`close_stdout`) · c_namer 1 (`cut_fields`).

**FP (yanlış isim; her biri aynı zamanda FN)**

| Kategori | FP | cat/cut/wc/expr/comm | Örnek |
|---|---|---|---|
| c_namer `string_context`, **gnulib** fonksiyonunda | 27 | 4/4/8/6/5 | `set_program_name←argv_passed_through` ×5, `proper_name_lite←utf` ×5, `emit_bug_reporting_address←general_help_using` ×5, `locale_charset←ascii` ×5, wc `xalloc_die←memory_exhausted`, `print_and_abort←memory_exhausted_2`, `argmatch_invalid/valid`, expr `mbschr/mbslen←mbuiterf_next`, comm `collate_error` |
| c_namer, **program-özgü** fonksiyonda | 13 | 1/3/1/5/3 | `write_error←write`, `eval4←non_integer_argument`, `compare_ranges←compare_func` (type_based) |
| call-shape, LTO'ya göre ayarlı (iç fonksiyona düştü) | 6 | 2/1/1/1/1 | `setlocale_null_r←hard_locale` ×5, cat `safe_write←full_write` |
| string-fp, LTO'ya göre ayarlı (iç fonksiyona düştü) | 5 | 1/1/1/1/1 | `version_etc_arn←version_etc` ×5 |
| main / disambiguation / boilerplate / FLIRT (kapalı) / diğer kanallar | 0 | — | Signature DB yalnız import'ları eşliyor. capa/bsim/cfg_iso bu koşularda FUN_ adı üretmedi |

**FN (isimsiz; 398)**

| Kategori | FN | cat/cut/wc/expr/comm | Neden |
|---|---|---|---|
| `quotearg.c` modülü | 170 | 34 ×5 | DB'de giriş yok (§3 K2/K3) |
| `xmalloc.c` (+`xalignalloc`) | 106 | 22/21/21/21/21 | DB'de giriş yok; libc imzaları özdeş |
| Diğer gnulib (çoğu tek binary'de) | 45 | 1/6/20/3/15 | wc: argmatch, argv-iter, readtokens0, physmem; comm: linebuffer, memcoll, … |
| Program-özgü (coreutils `src/`, `gl/lib`) | 21 | 3/5/4/7/2 | 8'i `fadvise`/`fdadvise`; gnulib kapsamı dışında |
| Tek fonksiyon, yeni call-shape/zincirle yakalanabilir | 20 | 5/4/4/3/4 | `rpl_fflush` 5, `rpl_fseeko` 5, `c_strcasecmp` 5, `fpurge` 3, `safe_read` 2 |
| Zincir kardeşleri | 15 | 3 ×5 | `version_etc_va`, `version_etc_ar`, `setlocale_null` |
| Zincirin dış API'si (adı iç fonksiyona gitti) | 11 | 3/2/2/2/2 | `version_etc` 5, `hard_locale` 5, cat `full_write` |
| `closeout.c` setter'ları (16 bayt) | 10 | 2 ×5 | callee'siz, çağıransız |

### 2.2 Ubuntu 9.4-3ubuntu6 (LTO, 114 GT; TP 41, FP 16, FN 73)

TP: `main` 5 · string-fp 14 · call-shape 19 · disambiguation 3. **FP 16'nın 16'sı da c_namer'dan**
(12'si program-özgü; 4'ü gnulib: wc'de üç "memory_exhausted*", comm'da `xmemcoll←strings_compared_were`).
İsimsiz 57: quotearg 21 (LTO'da kalan hub'lar: `quotearg_buffer_restyled`, `quotearg_n_options`, `gettext_quote.part.0`
ve sarmalayıcılar), diğer gnulib 19 (`proper_name_lite` ×5 dahil), program 13, `safe_read` 2, `rpl_fseeko` 1, `xpalloc` 1.

### 2.3 Not: GT'nin yarısından fazlası doğrudan çağrılmıyor

Debian GT'sinde 272/484 fonksiyonun çağrı grafiğinde doğrudan çağıranı yok. Bunların çoğu arşivden bütün `.o`
dosyasıyla bağlanmış ölü kod (ör. cat'te x*alloc üyelerinin 18/21'i). Bu yüzden kazanımın ne kadarının
yalnız ölü kodu isimlendirmekten geldiği ayrıca kontrol edildi (§4.3).

## 3. Kök sebepler

**K1. Çıpayı tutan fonksiyon ile API adı farklı fonksiyonlar (zincir çökmesi).** FIX-2/2b tabloları yalnız Ubuntu
LTO derlemesine bakılarak ayarlandı. LTO/IPA bir çağrı zincirini tek fonksiyona çöktürür ve bu fonksiyon dış API'nin
adını `.constprop` ekiyle taşır. LTO'suz derlemede gnulib fonksiyonları ayrı çeviri birimlerinde durur; birimler
arası inline olmaz ve çıpa zincirin en içinde kalır. Aynı kaynaktan (cat) ölçülen fark:

| Çıpa | Ubuntu (LTO) | Debian (LTO'suz) |
|---|---|---|
| `"Written by"` | `version_etc.constprop.0` (1152 B; `__fprintf_chk, dcgettext, fputc_unlocked, __stack_chk_fail`; çağıran `main`) | `version_etc_arn` (920 B, çıpa) ← `version_etc_ar` (40 B, yalnız arn), `version_etc_va` (196 B, arn+SSP, çağıransız), `version_etc` (252 B, arn+SSP, **variadic prolog**, çağıran `main`). va, version_etc'ye inline edilmiş |
| `setlocale` | `hard_locale.constprop.0` (216 B; `setlocale, strlen, memcpy, strcmp, __stack_chk_fail`; `"POSIX"`) | `setlocale_null_r` (172 B; `setlocale, strlen, memcpy`) ← `hard_locale` (176 B; yalnız `setlocale_null_r`+SSP; `strcmp`, `0x43 / 0x49534f50 ('POSI') / 0x58` sabit karşılaştırmalarına açılmış, literal yok) · `setlocale_null` (12 B, yalnız `setlocale`) |
| `write` | `full_write.constprop.0` (208 B; `write, __errno_location`; çağıran `main`) | `safe_write` (124 B; `write, __errno_location`) ← `full_write` (156 B; yalnız `safe_write`+`__errno_location`) |

Zincirin derinliği derlemeye göre değişiyor: Debian'da bile `version_etc_va`, `version_etc`'ye inline edilmiş.
Bu yüzden kural derinliği sabit varsaymamalı, **binary'nin çağrı grafiğinden çıkarmalı**.

**K2. Kapsam: DB yalnız LTO'da ayakta kalan fonksiyonları biliyor.** Tablolarda 7 string, 7 call-shape ve
1 ayrıştırıcı var. LTO'da gnulib'in büyük kısmı inline edilir ya da atılır, bu yüzden hiç gerekmediler.
LTO'suz (ve `--gc-sections`'sız) bağlamada arşivin bütün üyesi gelir: `quotearg.o`'nun 34 ve `xmalloc.o`'nun
21 fonksiyonu her binary'de var. Bu iki modül Debian GT'sinin %57'si (276/484) ve hepsi **isimsiz** (FP değil
FN): string literalleri olmadığından c_namer da bir şey uyduramıyor.

**K3. Tekil call-shape bu modülleri ayırt edemez.** cat'te x*alloc üyelerinin libc imzaları:
`{malloc}` ×3, `{realloc}` ×3, `{reallocarray}` ×7, `{calloc}` ×4, `{malloc,memcpy}` ×3. quotearg'ın 21 sarmalayıcısında
iç callee yalnız hub'dır; tek ek bilgi SSP/`abort` var mı yok mu. unique-in-binary koruması bunları **doğru** reddediyor.
Ayırt edici bilgi konumsal: modül içi yayın sırası ve bu sıranın konum başına imza doğrulaması.

**K4. Tanım ve belirsizlik hataları.**
- `argmatch` girişi (`"ambiguous argument"` ∧ `"Valid arguments"`) hiçbir derlemede `argmatch` fonksiyonuna
  düşmez. Çıpalar `argmatch_invalid` ve `argmatch_valid`'a ait. LTO'da ikisi `__xargmatch_internal`'a (Ubuntu
  wc'de `main`'e) gömülür. Sonuç: LTO'suz derlemede eşleşme 0, LTO'da ancak yanlış hedef.
- `quotearg_buffer_restyled` call-shape'i 2026-07-14'te "2023 quotearg.c'de `iswprint` yok, ~0 TP" gerekçesiyle
  kaldırılmış. Ölçülen durum farklı: **16/16 binary'de** bu fonksiyon `iswprint` çağırıyor. Çağrı `c32isprint`
  üzerinden geliyor (`uchar.in.h:286-288`, `c32isprint.c:24`). Kaynak dosyada birebir geçme şartı, gnulib
  başlık açılımlarını görmüyor.
- `"memory exhausted"` obstack'in `print_and_abort`'unda da geçiyor. wc'de belirsiz kalıyor ve c_namer'a düşüyor.
  `mbslen` call-shape'i expr'de `mbschr` ile çakışıyor (2 aday, atama yok).

**K5. c_namer `string_context` kimlik iddiası üretiyor.** Parmak izi bir fonksiyonu isimlendirmezse c_namer string
anahtar kelimelerinden ad kuruyor (`utf`, `ascii`, `general_help_using`). Tabanda Debian'da 41 adın 1'i, Ubuntu'da
16'nın 0'ı doğru. c_namer ön adlara saygı gösterdiği için (guard) her yeni parmak izi o fonksiyondaki bir c_namer
FP'sini de siliyor. Precision'ın kapsamla birlikte artmasının nedeni bu.

**K6. `min_fanout=2` thunk sezgisi gerçek sarmalayıcıları da eliyor.** PLT thunk'larını elemek için konmuş, ama tek
callee'li gnulib fonksiyonlarını da (`fpurge→__fpurge`, `setlocale_null→setlocale`, `locale_charset→nl_langinfo`)
dışarıda bırakıyor. Ghidra'nın `is_thunk` bayrağı ya da import adlı düğüm filtresi daha keskin bir ayrım.

## 4. Düzeltme tasarımı

### 4.1 Yerleşim (dosya sahipliği)

| Dosya | Değişiklik |
|---|---|
| `karadul/analyzers/gnulib_fingerprints.py` | **Yalnız veri**: yeni string/call-shape girdileri; `GnulibFingerprint.exclude`, `GnulibCallShape.exclude_callees` + `exact_optional` (callee ⊆ gerekli ∪ opsiyonel); yeni `GnulibChain` ve `GnulibModuleBlock` tabloları; testteki `_BEHAVIOR_KEY` modüle taşınır (`GNULIB_ABI_EXPANSION`: `iswprint←c32isprint`, `__freading←freading`, `dcgettext←gettext/_(`, `__fprintf_chk←fprintf`, `__ctype_get_mb_cur_max←MB_CUR_MAX`, `__errno_location←errno`) |
| `karadul/analyzers/gnulib_structural.py` (**yeni**) | Saf, I/O'suz motor: `FunctionView` (adres sırası, boyut, `is_thunk`, iç callee/libc callee, çağıranlar, literal'ler, disasm satırları), `apply_chains()`, `apply_module_blocks()`, `variadic_prologue(disasm, arch)`, `store_width(disasm, arch)` |
| `karadul/stages.py::_recover_gnulib_from_fingerprints` | İnce yapıştırıcı. Mevcut string-fp → call-shape → ayrıştırma adımlarından sonra `static_dir/ghidra_output/{functions.json, call_graph.json, decompiled/}` okunur ve yeni motor çağrılır. Yeni istatistikler: `gnulib_chain_recovered`, `gnulib_block_recovered`, `gnulib_block_rejected` (sebep listesi). **Yeniden adlandırma izni yalnız** aynı geçişte gnulib kanalının verdiği adlar içindir; `main`, override ve boilerplate adlarına dokunulmaz. İkinci çağrı işlem yapmaz (idempotent) |
| `karadul/reconstruction/c_namer.py` | Yalnız P1 onaylanırsa: global FUN_ dışlama listesine `string_context`/`type_based` eklenir ya da bunlar `{ipucu}_{adres4}` rol etiketine çevrilir |
| `tests/test_gnulib_fingerprints.py`, yeni `tests/test_gnulib_structural.py`, mutation spec | §5 |

⚠ `karadul/stages.py` şu an başka bir ajanın commit edilmemiş değişikliklerini taşıyor (`git status`: M).
Bu iş o değişiklikler commit edildikten **sonra**, sıralı yapılmalı.

### 4.2 Kurallar (öncelik sırası)

Kısaltmalar: *ince çağıran* = isimsiz; iç callee kümesi = {F}; libc callee'leri izinli kümenin alt kümesi;
string literali yok. Bütün atamalar tekillik şartı taşır ve önceden isimli fonksiyonu ezmez (zincirdeki izinli
yeniden adlandırma hariç).

**Faz 1: LTO bağımlılığını kaldır, bilinen yanlışları düzelt (düşük risk)**

| # | Kural (dosya: `gnulib_fingerprints` verisi + `gnulib_structural` motoru) | Etki (sim., in-sample) | Hold-out (Debian; Ubuntu ayrıca yazılmışsa) | Risk |
|---|---|---|---|---|
| D1 | **version-etc zinciri.** F = `"Written by"` tutucusu (mevcut). W = F'nin libc ⊆ {`__stack_chk_fail`} ince çağıranları. W boşsa F=`version_etc` (çökmüş durum, Ubuntu'nun 4 TP'si korunur). Doluysa F=`version_etc_arn`; W'de libc'siz tek üye → `version_etc_ar`; SSP'li üyelerden variadic prologlu tek üye → `version_etc`, prologsuz tek üye → `version_etc_va`. Variadic prolog: AArch64'te ilk 40 komutta ≥4 `str qN` (VR kayıt alanı; simülasyonda kullanılan ölçüt; `stp x4..x7` ek kanıt olabilir); x86-64'te `test al,al` + `movaps xmmN`. Kaynak: version-etc.c (ar/va'da `version_etc_arn (` çağrısı, version_etc'de `va_start`, va'da `authtab[10]` → SSP) | Debian +20 TP / −5 FP; Ubuntu 0 | +16 / −4 | Düşük. Prolog tanınmazsa yalnız arn+ar atanır |
| D2 | **hard-locale zinciri.** F = call-shape `setlocale` tutucusu. F'de `strcmp` veya `"POSIX"` varsa çökmüş → `hard_locale` (mevcut). Yoksa ve libc ⊆ {`__stack_chk_fail`,`strcmp`} olan **tek** ince çağıran G varsa: F=`setlocale_null_r`, G=`hard_locale`; ayrıca callee'si tam {`setlocale`}, ≤32 B tek fonksiyon → `setlocale_null`. G yoksa hiçbir şey değişmez | Debian +15 / −5; Ubuntu 0 | +12 / −4 | Düşük |
| D3 | **write/read zinciri.** `write` tutucusu F'nin libc ⊆ {`__errno_location`} tek ince çağıranı varsa F=`safe_write`, çağıran=`full_write`; yoksa `full_write`. Yeni call-shape `safe_read`: callee kümesi **tam** {`read`} ∪ ⊆{`__errno_location`}; tek ince çağıranı → `full_read` | Debian +4 / −1; Ubuntu +2 | +3 / 0; Ubuntu +1 | Düşük. Hold-out dersi: Ubuntu tr'de `safe_read` LTO ile `plain_read`'e gömülmüş ({read, errno, dcgettext, error}); "⊇{read}, fanout≤4" biçimi FP verdi, bu yüzden **tam küme** zorunlu |
| D4 | **Yeni string parmak izleri ve zincirler.** `set_program_name` ← `"A NULL argv[0] was passed through an exec system call"` (progname.c:54). `emit_bug_reporting_address` ← `"Report bugs to: "` ∧ `"General help using GNU software"`, hariç `"Usage: "` (version-etc.c:249,260). `argmatch` girişi **kaldırılır**; yerine: `__xargmatch_internal` ← `"invalid argument"` ∧ `"Valid arguments are:"` (çökmüş durum, sırada ilk), `argmatch_invalid` ← `"invalid argument"` ∧ `"ambiguous argument"` hariç `"Valid arguments"`, `argmatch_valid` ← `"Valid arguments are:"` hariç `"invalid argument"`; ikisinin ortak tek çağıranı → `__xargmatch_internal`, onun {strlen,strncmp} çağıran iç callee'si → `argmatch`. `collate_error` ← `"string comparison failed"` ∧ `"Set LC_ALL="`; iç callee'si {collate_error, X} ve libc ⊆ {errno} olan tam 2 çağıran → kaynak sırasıyla `xmemcoll`, `xmemcoll0`; çağıran yoksa ve tutucu `strcoll`+`memcmp` çağırıyorsa → `xmemcoll` (LTO). "memory exhausted" ayrıştırıcısı: `xalloc_die` = `error` var, `exit/fprintf/__fprintf_chk` yok (xalloc-die.c:34); `print_and_abort` = `exit` ∧ fprintf (obstack.c:339-341). `locale_charset` ← {nl_langinfo} ∧ `"ASCII"`, fanout≤2; onu çağıran, dcgettext'li, `"UTF-8"`li tek fonksiyon → `proper_name_lite`; onun yaprak iç callee'si → `c_strcasecmp`. Çökmüş durum: callee tam {dcgettext, nl_langinfo} → `proper_name_lite` | Debian +34 / −25; Ubuntu +8 / −3 | +24 / −18; Ubuntu +1 | Düşük |
| D5 | **Call-shape düzeltmeleri.** `mbslen` exclude {`strchr`} + yeni `mbschr` ← {mbsinit, strchr} (mbschr.c:52). `rpl_fseeko` ← {fseeko, lseek} (fseeko.c:117,163). `rpl_fflush` ← {fflush, __freading} exclude {`fclose`} (Ubuntu cut'ta `rpl_fclose` rpl_fflush'ı gömüyor). `fpurge` ← tam {`__fpurge`}, ≤48 B, thunk değil. Yeni girdilerde thunk filtresi `min_fanout=2` yerine `is_thunk`/FUN_ adı; eski girdiler olduğu gibi kalır | Debian +15 / −2; Ubuntu +1 | +11 / 0 | Düşük |

Faz 1 toplamı (sim.): **Debian 0,123 → 0,397** (TP 35→123, FP 51→13); Ubuntu 0,479 → 0,581 (TP 41→52, FP 16→13).

**Faz 2a: quotearg hub'ları (her iki derleme)**

| # | Kural | Etki | Hold-out | Risk |
|---|---|---|---|---|
| D6 | `quotearg_buffer_restyled` ← libc ⊇ {iswprint, mbsinit, `__ctype_get_mb_cur_max`, memcmp}, fanout≥6. 16/16 binary'de tek eşleşme; wc'nin ikinci `iswprint` çağıranı ele. Leakage testi `iswprint←c32isprint` açılımıyla. `gettext_quote` ← qbr'nin tek callee'li iç callee'si (callee `nl_langinfo` ya da tanınmış `locale_charset`). `quotearg_n_options` ← qbr'yi çağıran ve `free` çağıran tek fonksiyon. `quotearg_buffer` ← iç callee {qbr}, libc ⊆ {errno}. `quotearg_alloc_mem` ← qbr + tek ayırıcı callee, `free` yok. `quotearg_alloc` ← yalnız alloc_mem'i çağıran ≤32 B | Debian +30; **Ubuntu +15** | Debian +24; Ubuntu +6 | Düşük |

Faz 2a sonrası: Debian 0,471 · **Ubuntu 0,691**.

**Faz 2b: modül blok hizalaması (en büyük kazanç, orta risk)**

| # | Kural | Etki | Hold-out | Risk |
|---|---|---|---|---|
| D7 | **quotearg bloğu.** Hub'ın (quotearg_n_options) isimsiz çağıranlarından iç callee'si yalnız hub olanlar adres sırasıyla dizilir; **tam 21** olmalı, aralarında başka kod fonksiyonu olmamalı. İmza dizisi quotearg.c tanım sırasından türetilir (1=yalnız hub, 2=+SSP, 3=+SSP+`abort`): `1111 3333 2222 33333 1111`. SSP'siz derleme varyantı 1/3; sonuç aynı ölçüldü. Birebir uyarsa tanım sırasıyla ad verilir. Setter'lar: hub'dan hemen sonraki 6 fonksiyon (`clone_quoting_options` {errno+1 iç}, 4 callee'siz, `set_custom_quoting` {abort}), hepsi doğrulanırsa. `quotearg_free`: `quotearg_alloc`'tan sonraki, callee'si tam {free} olan fonksiyon | Debian +140 (28×5); Ubuntu 0 (LTO'da blok yok, kural devreye girmez) | +112 | Orta |
| D8 | **xmalloc.o bloğu.** `xalloc_die`'nin isimsiz, ≤300 B, libc ⊆ {malloc, calloc, realloc, reallocarray, aligned_alloc, memcpy, strlen, errno} çağıranları. `aligned_alloc`'lı tek aday → `xalignalloc`. Kalanlar **tam 21 ve bitişik** olmalı; her konum şu tabloyla doğrulanır (tolerans {errno, SSP}): xnrealloc{ra} xmalloc{m} ximalloc{m} xcharalloc{m} xrealloc{r} xirealloc{r} xreallocarray{ra} xireallocarray{ra} xnmalloc{ra} xinmalloc{ra} x2realloc{ra} x2nrealloc{ra} xpalloc{r} xzalloc{c} xizalloc{c} xcalloc{c} xicalloc{c} xmemdup{m,memcpy} ximemdup{m,memcpy} ximemdup0{m,memcpy} xstrdup{strlen,m,memcpy}. Sıra = xalloc.h extern-inline (`xnrealloc`) + xmalloc.c tanım sırası. Kümeler kaynak + gnulib-içi inline açılımından geliyor (`nonnull`, ialloc.h `imalloc/irealloc/icalloc/ireallocarray`, `XNMALLOC`) | Debian +106 | +84 | Orta |
| D9 | **closeout setter'ları.** `close_stdout`'tan hemen önceki iki kod fonksiyonu: ≤16 B, callee'siz, isimsiz. İlki 64-bit global yazar (AArch64 `str x0,[..]`), ikincisi bayt yazar (`strb w0,[..]`) → `close_stdout_set_file_name`, `close_stdout_set_ignore_EPIPE` (closeout.c tanım sırası ve tipleri) | Debian +10 | +8 | Düşük-orta; mimariye özgü (x86-64: `mov [rip+..],rdi` / `mov byte [rip+..],dil`) |

D7–D9'un ortak riski: yayın sırası varsayımı. GCC birbirini çağırmayan fonksiyonları tanım sırasıyla, çağrılanı
çağırandan önce yayar. Konum başına imza doğrulaması eksik/fazla üyeyi ve imza kaymasını yakalar ve o durumda
hiç isim verilmez. Ama **aynı imzalı ardışık üyeler kendi aralarında yer değiştirirse bunu göremez**
(`xmalloc/ximalloc/xcharalloc`, 6'lı `{reallocarray}` dizisi, 4 yaprak setter). Üye listeleri gnulib sürümüne
bağlı (bb5bb43): başka sürümde doğrulama tutmaz ve kural sessiz kalır (recall kaybı, FP yok). Sürüm tablosu
eklenerek genişletilir. Bu fazın kabulü için §5'te ek kapı var.

**P1: politika (Berke kararı, ölçüt ayarı değil).** c_namer `string_context`/`type_based` adları FUN_ kimliği
olarak yazılmaz. Rol etiketi (`{ipucu}_{adres4}`, kod tabanında zaten var olan geri dönüş biçimi) ya da yorum
olarak kalır. Tek başına: Ubuntu 0,479→0,529 (FP 16→0), Debian 0,123→0,129 (TP 35→34 `cut_fields`, FP 51→11). Faz 1+2
sonrası: Debian 0,903→0,915, Ubuntu 0,691→0,740, FP 0/0. Bedeli, kullanıcının daha az isim görmesi. Kimlik
iddiası sözleşmesi olarak ele alınmalı; lenient F1 ve "kaldırılan ad sayısı" ile birlikte raporlanmalı.

### 4.3 Kümülatif simülasyon (strict mikro; TP/FP/FN F1)

| Adım | Debian (5 bin, 484) | Ubuntu (5 bin, 114) | Hold-out Debian (4 bin, 383) | Hold-out Ubuntu (2 bin, 48) |
|---|---|---|---|---|
| taban | 35/51/449 0,123 | 41/16/73 0,479 | 28/51/355 0,121 | 16/13/32 0,416 |
| +D1 | 55/46/429 0,188 | 41/16/73 0,479 | 44/47/339 0,186 | 16/13/32 0,416 |
| +D2 | 70/41/414 0,235 | 41/16/73 0,479 | 56/43/327 0,232 | 16/13/32 0,416 |
| +D3 | 74/40/410 0,247 | 43/16/71 0,497 | 59/43/324 0,243 | 17/13/31 0,436 |
| +D4 | 108/15/376 0,356 | 51/13/63 0,573 | 83/25/300 0,338 | 18/13/30 0,456 |
| +D5 | 123/13/361 0,397 | 52/13/62 0,581 | 94/25/289 0,374 | 18/13/30 0,456 |
| +D6 | 153/13/331 0,471 | 67/13/47 0,691 | 118/25/265 0,449 | 24/13/24 0,565 |
| +D7 | 293/13/191 0,742 | 67/13/47 0,691 | 230/25/153 0,721 | 24/13/24 0,565 |
| +D8 | 399/13/85 0,891 | 67/13/47 0,691 | 314/25/69 0,870 | 24/13/24 0,565 |
| +D9 | 409/13/75 0,903 | 67/13/47 0,691 | 322/25/61 0,882 | 24/13/24 0,565 |
| +P1 | 408/0/76 0,915 | 67/0/47 0,740 | 322/0/61 0,913 | 24/0/24 0,667 |

Kontroller (D1–D9 birlikte): taban TP'lerinden kaybedilen **0** (Ubuntu'nun 41'i korunuyor); kural kaynaklı FP
**0**, kalan FP'lerin tamamı c_namer'dan. Yalnız doğrudan çağıranı olan fonksiyonlar sayıldığında da artış
sürüyor: Debian F1 0,164 → 0,802 (212 GT), Ubuntu 0,428 → 0,679 (100 GT). Yani kazanç ölü kodu şişirmekten
gelmiyor.

**Tahminin sınırları.** (1) Kuralların etkilemediği fonksiyonlarda c_namer adları taban koşusundan alındı.
Gerçekte callee'ler yeniden adlandırılınca c_namer bağlamı değişebilir; bu yalnız FP sayısını az miktarda
oynatır. (2) In-sample sayılar iyimser, çünkü kurallar bu 10 binary'ye bakılarak tasarlandı. (3) İki
inceltme hold-out sonucu görüldükten sonra yapıldı: `safe_read` tam-küme şartı (−1 FP) ve D3'te "tek çağıran"
yerine "tek ince çağıran" (+1 TP). Bu ikisi için hold-out bağımsız değil. (4) Hold-out aynı paket, aynı derleyici,
aynı gnulib ve aynı mimariden (arm64) geliyor. Başka gnulib sürümü ve x86-64 ölçülmedi.

## 5. Doğrulama ve kabul planı

**Her faz ayrı commit olur ve ayrı ölçülür** (Faz 1 · 2a · 2b · P1). Ana ağaç başka ajanların kirli dosyalarını
taşıdığı için aday **kendi worktree'sinden** koşulur (README §5'teki sembolik bağ adımlarıyla):

```bash
git worktree add ~/karadul_olcum/aday-<sha> <sha>     # + sigs/vendor/signatures_* sembolik bağları (README §5)
python -m pytest -q tests/test_gnulib_fingerprints.py tests/test_gnulib_structural.py   # tam suite değil
python scripts/mutation_probe.py --spec <yeni spec> -v
python scripts/measurement/measure.py analyze --tree ~/karadul_olcum/aday-<sha> --label aday-<sha>   # ≤2 paralel
python scripts/measurement/measure.py score --label aday-<sha> --out ~/karadul_olcum/results/aday-<sha>.json
python scripts/measurement/measure.py compare ~/karadul_olcum/results/baseline-2304560.json ~/karadul_olcum/results/aday-<sha>.json
```

**Kabul kapısı (hepsi birden):**
1. **Ubuntu:** tabandaki 41 TP'nin tamamı korunur (`compare` "kaybedilen" listesi boş), FP artmaz, F1 düşmez.
2. **Debian:** kaybedilen TP 0, FP artmaz, F1 ≥ taban. Gerçek koşu, fazın simülasyon tahmininden ±5 TP'den fazla
   saparsa kök sebep bulunmadan kabul edilmez.
3. **Hold-out** (Debian head/tr/uniq/nl, Ubuntu head/tr; `corpus.json`'a dokunmadan ayrı bir manifest):
   kural kaynaklı yeni FP 0.
4. **Faz 2b için ek kapı:** farklı bir gnulib sürümüyle derlenmiş en az bir korpusta (ör. Debian bookworm
   coreutils 9.1 arm64 + dbgsym) D7–D9 **hiç yanlış isim üretmez** (sessiz kalması kabul, yanlış isim ret).
5. **Determinizm:** aday iki kez koşulur, fonksiyon durumu farkı 0 olmalı (README §5 yöntemi).
6. **Leakage:** (a) her yeni çıpa/callee `vendor/gnulib-ref` kaynağında ya da belgelenmiş `GNULIB_ABI_EXPANSION`
   açılımında geçer; (b) her zincir kenarı (sarmalayıcı → iç fonksiyon) kaynakta gerçek bir çağrıdır;
   (c) blok tablolarının üye sırası testte vendor kaynağından **otomatik** çıkarılan tanım sırasıyla karşılaştırılır,
   yani elle GT sırasına ayarlanamaz; (d) `karadul/` altında `gt.json` / `karadul_olcum` referansı yok (grep).
7. **Birim testleri (sentetik `FunctionView`):** çökmüş ve çökmemiş zincir; ince çağıran yoksa değişiklik yok;
   blokta eksik/fazla üye, araya giren fonksiyon ya da imza kayması olunca ret; `plain_read` benzeri gömülü
   `safe_read` ret. Mutation hedefleri: ince çağıran kontrolü, tam-küme şartı, bitişiklik, konum doğrulaması,
   exclude listeleri, idempotent ikinci çağrı.
8. **Rapor:** `compare` çıktısı (binary başına ΔF1, kazanılan/kaybedilen, McNemar p). P1 uygulanırsa strict ve
   lenient birlikte ve kaldırılan ad sayısı ayrıca.

## 6. Açık riskler ve sınırlar

- **FLIRT/veri kökü:** taban `--output-dir` ile alındı (FLIRT ve n-gram kapalı). Veri kökü düzeltilirse taban
  yeniden koşulmalı ve FLIRT adlarının (0,95 güven) yeni ön adlarla etkileşimi ölçülmeli. Mevcut imza DB'si
  (homebrew arm64) bu sorunun çözümü değil.
- **Genelleme:** tek program ailesi, tek gnulib sürümü, arm64. D1–D6 yapısal ve zincir farkındalığı
  sayesinde sürümden görece bağımsız. D7–D9 sürüm tablosu ister.
- **Kalan FN (D1–D9 sonrası Debian 62 isimsiz):** 21'i program-özgü (gnulib kapsamı dışı), gerisi tek binary'de
  görünen gnulib modülleri (argv-iter, readtokens0, linebuffer, memcoll, physmem, long-options, fopen/fcntl
  ailesi). Sonraki adım (ölçülmedi): vendor kaynağından otomatik call-shape çıkarımı + ABI açılım tablosu.
  Aynı kapılarla ölçülür.
