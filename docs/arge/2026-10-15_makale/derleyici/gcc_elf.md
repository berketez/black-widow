# GCC: C kaynağından ELF x86-64 binary'ye — Karadul için derleyici notları

Hazırlayan: derleyici ekibi, GCC/ELF alanı · Tarih: 2026-10-15
Kapsam: GCC orta katmanı (GIMPLE/IPA), RTL'nin RE'yi etkileyen kısmı, ELF bağlama, Debian/Ubuntu derleme bayrakları.
Kapsam dışı (diğer ajanlar): Clang/LLVM, arm64'e özgü ayrıntı, makine kodu deyim kataloğu, teorik sınırlar.

Etiketler: **[K]** kaynak kodundan bu oturumda doğrulandı · **[Ö]** bu oturumda ölçüldü (§7) ·
**[B]** belge/duyuru (arama sonucu ya da sayfa) · **[Ç]** çıkarım ya da bellekten bilgi, doğrulanmadı.

---

## 1. Özet

1. GCC 9.4 ile güncel GCC arasında RE açısından dört büyük fark var. `-finline-functions` GCC 10'dan beri -O2'de açık. Vektörleme GCC 12'den beri -O2'de (very-cheap maliyet modeliyle). IPA-SRA GCC 10'da gerçek bir IPA geçişine dönüştü. Klon numaraları GCC 9'dan beri isim başına sayılıyor (`.constprop.0`) [K].
2. Fonksiyon kimliğini dört sonek değiştirir: `.constprop.N` (ipa-cp), `.isra.N` (ipa-sra), `.part.N` (ipa-split), `.cold` (sıcak/soğuk bölme; yalnız x86'da -O2'den itibaren varsayılan). LTO bunlara `.lto_priv.N` ekler. Sonekler zincirlenebilir: `alan_oku.constprop.0.isra.0` [Ö].
3. Klonun DWARF DIE'sinde `DW_AT_name` yoktur, yalnız `DW_AT_abstract_origin` vardır. Kaynak adı soyut örnekten gelir. Bu, Ubuntu dbgsym'de doğrulandı [Ö].
4. Karadul korpusu **x86-64 değil, arm64**. GCC 13.2 kullanılmış. Debian: `-O2`, LTO yok. Ubuntu: `-O2 -flto -ffat-lto-objects -fno-omit-frame-pointer`. Bayraklar DWARF producer dizesinden okundu [Ö].
5. LTO etkisi: binary başına fonksiyon sembolü Debian'da 97–122, Ubuntu'da 25–41. Debian'da `.constprop` 0, Ubuntu'da 30 [Ö]. Yani F1 0,12 → 0,48 farkının büyük kısmı derleyiciden geliyor. LTO paydayı küçültüyor (ölü ve küçük gnulib fonksiyonları siliniyor), zincirleri tek fonksiyonda topluyor ve çıpayı dış API adının yanına taşıyor.
6. LTO'suz derlemede bir modülün fonksiyonları kaynak sırasıyla değil, çağrı grafiğinin RPO sırasıyla (önce çağrılan) yayılır. Bu yalnız -O1 ve üstünde geçerli, -O0'da kaynak sırası korunur [K][Ö]. Karadul'un "modül blok hizalaması" tasarımı buna göre kurulmalı.
7. `main`, `.text.startup` bölümüne girdiği için iki korpusta da `.text`'in ilk fonksiyonu (`_start`'tan önce) [Ö]. Bu, ucuz ve deterministik bir konum ipucu.

---

## 2. Hat ve -O seviyesi × geçiş tablosu

### 2.1 Hat (GCC 13.2 `passes.def` sırası [K])

```
C kaynağı → GENERIC (ön uç ağacı)
  → gimplify → GIMPLE (yüksek) → lower (CFG, EH) → into-SSA
  → erken yerel geçişler (fonksiyon başına): einline, esra, fre1, evrp, tailr1, switchconv,
       local-pure-const, modref, fnsplit (.part)
  → küçük IPA: free-fnsummary, tree-profile, ...
  → düzenli IPA (LTO'da WPA'da karar, LTRANS'ta uygulama):
       odr → whole-program → profile → icf → devirt → cp (.constprop) → sra (.isra)
       → cdtor → fn-summary → inline → pure-const → modref → reference → single-use → comdats
  → geç GIMPLE (fonksiyon başına, RPO sırasıyla): fre, vrp, sra, pre, döngü geçişleri
       (ldist, vect, slp, unswitch, ivopts), tailc, switchlower
  → expand → RTL: cse, gcse, combine, ira/lra, pro_and_epilogue (shrink-wrap), sched2,
       bbro, bbpart (.cold), peephole2; x86'ya özgü: stv, vzeroupper, endbr ekleme
  → final (.s) → as (.o) → ld (ELF)
```

GCC 9.4'te farklı olanlar [K]: IPA-SRA erken yerel geçiş (`pass_early_ipa_sra`, satır 92) ve yalnız çeviri birimi içinde çalışıyor. GCC 13.2'de `pass_ipa_sra` ipa-cp'den sonra ve LTO'ya uyumlu. GCC 9.4'te `pass_ipa_modref`, `pass_ipa_odr` ve `pass_harden_*` yok; `pass_ipa_hsa` var.

### 2.2 Seviye tablosu

Kaynaklar: GCC 9.4 `opts.c` ve 13.2 `opts.cc` `default_options_table` [K]; i386 ve aarch64 hedef tabloları [K]. Son sütun gcc-16'nın `-fdump-passes` çıktısından [Ö] (aarch64-darwin hedefi, orta katman aynı).

| Geçiş / bayrak | Sonek / iz | O0 | O1 | O2 | O3 | Os | GCC 9.4 farkı |
|---|---|---|---|---|---|---|---|
| einline (erken inline) | — | yalnız `always_inline` | ✓ | ✓ | ✓ | ✓ | `early-inlining-insns` 9.4: 14 · 13.2: O2 6 / O3 14 |
| `-finline-functions-called-once` | tek çağrılan static yok olur | — | ✓ (Og hariç) | ✓ | ✓ | ✓ | aynı |
| `-finline-small-functions` | — | — | — | ✓ | ✓ | ✓ | aynı |
| `-finline-functions` | — | — | — | ✓ (10+) | ✓ | ✓ | **9.4: yalnız O3 ve Os** |
| ipa-cp `-fipa-cp` | `.constprop.N` | — | — | ✓ | ✓ | ✓ | aynı |
| `-fipa-cp-clone` | `.constprop.N` (orijinal de kalır) | — | — | — | ✓ | — | aynı |
| ipa-sra `-fipa-sra` | `.isra.N` | — | — | ✓ | ✓ | ✓ | 9.4: erken, TU içi |
| fnsplit `-fpartial-inlining` | `.part.N` | — | — | ✓ | ✓ | ✓ | aynı |
| ipa-icf `-fipa-icf` | alias / sarmalayıcı / yok olma | — | — | ✓ | ✓ | ✓ | aynı |
| ipa-pure-const | — (noreturn/const keşfi) | — | ✓ | ✓ | ✓ | ✓ | aynı |
| ipa-modref | — | — | ✓ (Og hariç) | ✓ | ✓ | ✓ | 9.4'te yok (GCC 11) |
| `-fipa-ra` | çağrı arası yazmaç sözleşmesi bozulur | — | — | ✓ | ✓ | ✓ | aynı |
| `-fipa-vrp`, `-fipa-bit-cp` | — | — | — | ✓ | ✓ | ✓ | aynı |
| esra/sra `-ftree-sra` | yapılar yazmaçlara dağılır | — | ✓ (Og hariç) | ✓ | ✓ | ✓ | aynı |
| fre | — | — | ✓ | ✓ | ✓ | ✓ | aynı |
| pre `-ftree-pre` | — | — | — | ✓ | ✓ (+partial-pre) | ✓ | aynı |
| evrp/vrp `-ftree-vrp` | — | — | — | ✓ | ✓ | ✓ | aynı |
| ldist `-ftree-loop-distribute-patterns` | döngü → `memset`/`memcpy` çağrısı | — | — | ✓ | ✓ | ✓ | **9.4: yalnız O3** |
| vect/slp | SSE/AVX kodu | — | — | ✓ (very-cheap) | ✓ (dynamic) | — | **9.4: yalnız O3** |
| `-funswitch-loops`, `-fpeel-loops`, `-fsplit-loops` | gövde çoğalır | — | — | — | ✓ | — | aynı |
| x86: `-funroll-loops -munroll-only-small-loops` | küçük döngü açılımı | — | — | ✓ (Os hariç) | ✓ | — | **9.4'te yok** |
| tailc/tailr `-foptimize-sibling-calls` | `call` → `jmp` | — | — | ✓ | ✓ | ✓ | aynı |
| switchconv `-ftree-switch-conversion` | switch → tablo | — | — | ✓ | ✓ | ✓ | aynı |
| `-fisolate-erroneous-paths-dereference` | NULL yolu → `ud2` tuzağı | — | — | ✓ | ✓ | ✓ | aynı |
| `-fomit-frame-pointer` | `rbp` çerçevesi yok | — | ✓ | ✓ | ✓ | ✓ | aynı (aarch64 hedefi kapatıyor) |
| `-ftoplevel-reorder` | yayın sırası RPO | **kapalı** (kaynak sırası) | ✓ | ✓ | ✓ | ✓ | aynı |
| `-freorder-functions` | `.text.startup/.hot/.unlikely` | — | — | ✓ | ✓ | ✓ | aynı |
| `-freorder-blocks-and-partition` | `.cold` | — | — | x86 ✓ | x86 ✓ | x86 ✓ | aynı; **aarch64'te varsayılan değil** |
| `-fthread-jumps` | — | — | ✓ | ✓ | ✓ | ✓ | 9.4: O2'den |

Sürüm geçişleri ayrıca 10.1.0, 11.1.0 ve 12.1.0 tablolarından doğrulandı [K]:
- `-finline-functions` ve `-ftree-loop-distribute-patterns` GCC 10'da -O2'ye indi.
- `pass_early_ipa_sra` GCC 10'da `pass_ipa_sra` oldu.
- `pass_ipa_modref` GCC 11'de geldi.
- `-ftree-loop-vectorize` GCC 12'de -O2'ye indi (`2_PLUS_SPEED_ONLY`).

gcc-16'da açık geçiş sayısı [Ö]: O0 139, O1 228, O2 280, O3 288, Os 274. Dump'ta -O0'da "ON" görünen einline ve ipa-inline yalnız `always_inline` işler.

İnline eşikleri (GCC 9.4 `params.def` / 13.2 `params.opt` ve -O3 geçersiz kılmaları [K]):

| Parametre | GCC 9.4 | GCC 13.2 O2 | GCC 13.2 O3 |
|---|---|---|---|
| `max-inline-insns-single` (inline bildirilmiş) | 200 | 70 | 200 |
| `max-inline-insns-auto` (bildirilmemiş) | 30 | 15 | 30 |
| `early-inlining-insns` | 14 | 6 | 14 |
| `inline-min-speedup` | 15 | 30 | 15 |
| `inline-unit-growth` | 40 | 40 | 40 |
| `large-function-insns` / `-growth` | 2700 / 100 | 2700 / 100 | 2700 / 100 |
| `partial-inlining-entry-probability` | 70 | 70 | 70 |
| `ipa-cp-eval-threshold` | 500 | 500 | 500 |
| `lto-partitions` / `lto-min-partition` | 128 / 10000 | 128 / 10000 | 128 / 10000 |

Not: GCC 9.4'te `-finline-functions` -O2'de kapalı olduğu için `max-inline-insns-auto` orada fiilen yalnız küçük fonksiyon yolunda etkili. SymGen'in -O2 kümesi bu yüzden güncel -O2'den daha az inline içerir [Ç: bayrak tablosundan çıkarım].

---

## 3. IPA klonları ve GT eşleştirme kuralları

Klon adı üretimi [K]:
- GCC 9.4 `cgraphclones.c`: `clone_function_name_numbered` her ad için ayrı sayaç tutar (`clone_fn_ids`). Bu yüzden ad `foo.constprop.0`, `foo.constprop.1` biçimindedir.
- GCC 8.5'te tek bir global sayaç vardı (`clone_fn_id_num`). Aynı birimde numaralar birikirdi, ör. `foo.isra.7` [K]. GCC 8'in `.cold` adlarının da numaralı olduğu buradan çıkarılıyor [Ç].
- GCC 9'dan beri `.cold` numarasızdır: final.cc'de `clone_function_name (current_function_decl, "cold")` çağrılır [K].
- Ayırıcı nokta. Bu ELF'e özgü bir davranış: `ASM_FORMAT_PRIVATE_NAME` noktayı kullanır. Noktayı desteklemeyen hedeflerde `$` ya da `_` kullanılır [Ç].

| Geçiş | Ne yapar | .symtab (dbgsym) | DWARF | Ghidra (stripped) ne görür | Ölçümde doğru eşleşme |
|---|---|---|---|---|---|
| **Erken + IPA inline** | Gövde çağırana kopyalanır. Çağıran kalmayan static fonksiyon silinir. | Satır içi kopyanın sembolü yok. Dış kopya kaldıysa (adres alınmış ya da global) yalnız o görünür. | Çağıranın içinde `DW_TAG_inlined_subroutine` (abstract_origin + call_site); ayrı adres yok. | Fonksiyon yok. Gövde çağıranın içinde. | GT'ye girmez (symtab tabanlı GT doğru). DWARF tabanlı GT kurulursa inlined kayıtlar **paydaya katılmamalı**. |
| **ipa-cp** `.constprop.N` | Sabit argümanla özelleşmiş kopya. -O2'de çağıranların hepsi bilinen yerel fonksiyon "bütün bağlamlar için" özelleşir. -O3'te `-fipa-cp-clone` ile global fonksiyon da kopyalanır, orijinal kalır. | `LOCAL FUNC foo.constprop.0`. Orijinal ya yok ya ayrı bir sembol. | Klon DIE'sinde ad yok, `DW_AT_abstract_origin` → `foo` [Ö]. | Ayrı fonksiyon (çağrı hedefi). Parametre sayısı kaynaktakinden az. | Sonek soyulur, taban ad eşleşir (`foo`). Orijinal de varsa aynı taban ada **iki GT kaydı** olur. İkisi ayrı ayrı puanlanır, ikisine de `foo` doğru. |
| **ipa-sra** `.isra.N` | Kullanılmayan parametreler silinir. İşaretçiyle gelen yapı alanlara bölünür. GCC 10+ dönüş değerini de silebilir. | `LOCAL FUNC foo.isra.0`; zincir mümkün: `foo.constprop.0.isra.0` [Ö]. | abstract_origin → `foo`. Formal parametreler çoğunlukla optimize edilmiş görünür. | Ayrı fonksiyon. İmza kaynaktan farklı (Karadul'un tip/param kurtarımı için tuzak). | Taban ad eşleşir. **Parametre/tip ölçümünde** klon imzası kaynak imzayla kıyaslanmamalı. |
| **ipa-split** (`-fpartial-inlining`) `.part.N` | Ucuz giriş testi ("başlık") çağırana inline edilir, pahalı gövde `foo.part.0` olur. | `LOCAL FUNC foo.part.0`. Bütün çağıranlar başlığı inline ettiyse orijinal `foo` yok olur. | abstract_origin → `foo` [Ö]. | Ayrı fonksiyon. Girişte erken çıkış testi yok, gövde ortadan başlar. | Taban ad (`foo`) eşleşir. Korpus: `gettext_quote.part.0`, `check_order.part.0`, `require_more_args.part.0`, `mbslen.part.0` [Ö]. |
| **Sıcak/soğuk bölme** `.cold` (`-freorder-blocks-and-partition`) | Olasılığı düşük bloklar (hata, `abort`, noreturn yolları) `.text.unlikely`'ye taşınır. Bu parçaya `call` ile değil `jmp` ile girilir, prologu yoktur ve ana fonksiyonun yığın çerçevesini kullanır. | `LOCAL FUNC foo.cold` (boyutu var). GNU ld betiği `.text.unlikely`'yi `.text`'in başına toplar [Ç: `ld --verbose` ile doğrulanmalı]. | Ayrı DIE yok. `foo`'nun DIE'si `DW_AT_ranges` ile iki aralık taşır [Ç]. Ayrı bir CFI/FDE kaydı vardır [Ç]. | Belirsiz. Ghidra parçayı ya `foo`'nun bitişik olmayan gövdesine katar ya da (FDE veya başlangıç örüntüsüyle) ayrı `FUN_` yapar [Ç: Karadul koşusunda sayılmalı]. | **Fonksiyon değil, parça.** Önerilen: parçanın adresi ana fonksiyona bağlanır. Paydadan çıkarılır, isim verilirse ne TP ne FP sayılır. İkincil raporda "parça" sınıfı ayrıca verilir. Karadul şu an `.cold`'u ayrı GT kaydı yapıp `foo`'ya normalize ediyor (§8). arm64 korpusunda `.cold` sayısı 0 [Ö]. x86-64'te -O2/-O3'te sık [Ç]. |
| **ipa-icf** | Anlamca özdeş iki fonksiyonu birleştirir. Kaynakta 3 sonuç sayılır [K]: (1) **alias**: aynı adrese iki sembol; (2) **sarmalayıcı** (wrapper/thunk): biri ötekine kuyruk çağrısı yapan saplama olur, iki adresin de karşılaştırılabildiği durum; (3) **çağıran yönlendirme**: alias'ın çağıranları orijinale yönlenir, alias yok olur. | (1) aynı adreste iki ad; (2) iki sembol, biri `jmp` saplaması; (3) tek sembol. | (1)/(3) ikinci fonksiyonun DIE'si kalabilir ama adresi yok ya da aynı [Ç]. | (1) tek fonksiyon; (2) Ghidra saplamayı thunk işaretler; (3) tek fonksiyon. | (1) GT ad kümesi: kümeden **herhangi biri** doğru (Karadul GT'si aynı adresteki adları `names` listesinde tutuyor, doğru). (2) saplama ayrı fonksiyon, kendi adıyla. (3) silinen ad GT'de yok. Korpusta aynı adreste birden çok FUNC sembolü olan adres yok (0/700) [Ö]. Deneyde (3) gözlendi: `ikiz_d` yok oldu [Ö]. |
| **ipa-pure-const** | `const`/`pure`/`nothrow`/**`noreturn`** keşfi. Sonuç olarak çağrılar silinebilir, CSE edilebilir, noreturn çağrısından sonra kod üretilmez. | Ad değişmez. Kullanılmayan pure çağrı silinirse fonksiyon da yok olabilir. | `DW_AT_noreturn` yalnız kaynakta bildirilmişse vardır [Ç]. | Keşfedilen noreturn Ghidra'ya bildirilmezse Ghidra çağrıdan sonra **sonraki fonksiyona akar**. Bu, fonksiyon sınırı hatasının klasik kaynağı [Ç]. | Ad eşleşmesini değiştirmez. Sınır doğruluğunu bozar; GT adresinde fonksiyon tespit edilmezse FN olur. |
| **LTO** `.lto_priv.N` | WPA bütün programı görür. Bağlayıcı çözümlemesiyle dışarıya görünmeyen semboller yerelleşir. Bölümler (partition) arasında paylaşılan static semboller gizli (hidden) globale terfi eder ve `.lto_priv.N` adını alır. Farklı TU'larda aynı adlı static'ler de `.lto_priv.N` olur [K][Ö]. | Sonuçta `LOCAL FUNC foo.lto_priv.0` (hidden → yerel). Ubuntu korpusunda 0 [Ö]: küçük program tek bölümde kalıyor ve ad çakışması yok. | LTRANS birimi `<artificial>` CU. abstract_origin özgün CU'ya gider [Ç]. | Ayrı fonksiyon. | Taban ad eşleşir. Aynı taban ada birden çok GT kaydı olabilir (iki farklı static `yardimci`). Ad doğru sayılır, ama kimlik belirsizdir; kaynak dosya bilgisi için DWARF gerekir. |

Ek gözlem [Ö]: ipa-cp'nin dump'ında "Creating a specialized node of olcekle/5 for all known contexts" satırı -O2'de, `-fipa-cp-clone` olmadan görülüyor. LTO'da gnulib fonksiyonları yerelleştiği için ipa-cp bunları da "bütün bağlamlar için" özelleştiriyor. Ubuntu'daki 30 `.constprop`'un, Debian'daki 0'ın sebebi bu.

---

## 4. Diğer geçişler: ne siler, ne iz bırakır, Karadul ne kazanır

| Geçiş | Ne siler | Ne iz bırakır | Karadul ne kazanır / neye dikkat eder |
|---|---|---|---|
| SRA (esra/sra) | Yerel yapı nesnesi, alan erişim deseni | Alanlar ayrı yazmaçlarda | Yapı kurtarımı yerel değişkenlerde zorlaşır; işaretçiyle geçen yapılarda alan ofsetleri hâlâ görünür |
| FRE/PRE, code hoisting | Tekrarlanan hesaplar, bazı yüklemeler | Ortak alt ifade bir kez, döngü dışına taşınmış yük | Kaynak düzeyinde "aynı satır" eşlemesi kaybolur; ifade parmak izi kaynak yapısına değil normalize SSA'ya bakmalı |
| VRP, `-fisolate-erroneous-paths` | Ölü dallar, aralık kontrolleri | NULL yolunda `ud2` tuzağı | `ud2` = derleyicinin kanıtladığı "imkânsız yol"; parmak izi için gürültü, sınır tespiti için noreturn sinyali |
| Döngü dağıtımı (ldist) | Elle yazılmış sıfırlama/kopya döngüsü | `memset`/`memcpy` çağrısı (GCC 10+'da -O2) | **API kanıtı derleyiciden geliyor**, kaynakta `memset` yok. libc-çağrı imzası GCC 9 ile 13 arasında farklılaşır |
| Vektörleme (SSE/AVX) | Skaler döngü | Vektör gövdesi + skaler kuyruk + hizalama ön döngüsü; aynı döngünün 2-3 versiyonu | Decompile çıktısı şişer. GCC 12+ -O2'de de görülür, GCC 9.4 -O2'de görülmez |
| Döngü açma, unswitch, peel | — | Gövde kopyaları | Boyut tabanlı özellikler -O seviyesine çok duyarlı |
| Kuyruk çağrısı (`-foptimize-sibling-calls`) | `call` + `ret` | `jmp foo` | Çağrı grafiği kenarı `jmp` olarak gelir. Ghidra bunu fonksiyon içi atlama ya da thunk sanabilir; çağrı-şekli imzalarında **kuyruk çağrıları da callee sayılmalı** |
| Switch dönüşümü | `switch` | Atlama tablosu (`.rodata` + dolaylı `jmp`) ya da arama tablosu (değer dizisi) | Tablo hedefleri fonksiyon başı sanılmamalı |
| `-fomit-frame-pointer` (O1+) | `push rbp; mov rbp,rsp` | `rsp` tabanlı çerçeve | Prolog örüntüsüyle fonksiyon başı bulma zayıflar. Ubuntu 24.04 çerçeve işaretçisini geri açtı [Ö: `-fno-omit-frame-pointer` producer'da]: sınır tespiti kolaylaşır, derlemeler arası prolog farkı oluşur |
| Yığın koruyucu (`-fstack-protector-strong`) | — | `fs:0x28` kanaryası + `__stack_chk_fail` çağrısı (yalnız dizi ya da adresi alınan yerel değişkeni olan fonksiyonlarda) | SSP var/yok iyi bir ikili özellik, ama **bayrağa bağlı**: upstream GCC varsayılanında kapalı, Ubuntu GCC'de açık [B] |
| `-fstack-clash-protection` | — | Büyük çerçevede sayfa sayfa yoklama döngüsü | Prolog biçimini değiştirir |
| `_FORTIFY_SOURCE` (glibc başlıkları) | `printf`, `memcpy`, `read` ... | `__printf_chk`, `__memcpy_chk` ... Nesne boyutu derlemede bilinip yeterliyse çağrı düz `memcpy`'ye katlanır. Düzey 3, `__builtin_dynamic_object_size` ile daha çok `_chk` üretir [Ç] | Ölçüldü [Ö]: cat'te Debian (FORTIFY=2) `__printf_chk`, `__fprintf_chk` alırken Ubuntu (FORTIFY=3) bunlara ek olarak `__memset_chk`, `__memmove_chk` alıyor. API imza tabloları `__X_chk → X` eşlemesiyle **normalize** edilmeli |
| Builtin katlama | `printf("x\n")`, `strlen("sabit")`, küçük `memcpy` | `puts`, sabit sayı, satır içi `mov` dizisi; `sprintf(b,"%s",s)` → `strcpy` [Ç] | Kaynaktaki çağrı binary'de **başka bir libc adıyla** görünür; çağrı-şekli imzası ters katlama tablosu taşımalı (`puts` ⇐ `printf`) |
| `-fipa-ra` | Çağrı sınırında caller-saved varsayımı | Yerel çağrı sonrası, ABI'ye göre bozulmuş olması gereken yazmaç kullanılmaya devam eder | Ghidra çağrı sözleşmesine güvendiği için "başlatılmamış değişken" üretebilir [Ç] |
| CET `-fcf-protection` (x86) | — | Her dolaylı çağrılabilir fonksiyonun başında `endbr64`; `.note.gnu.property` IBT/SHSTK | **Güçlü fonksiyon başı sinyali** (adresi alınabilen ya da global fonksiyonlar). `endbr64` olmayan yerel fonksiyonlar yalnız doğrudan çağrılır. Ubuntu 19.10+ GCC varsayılanı [B]; Debian dpkg "branch" özelliği [B] |
| `-freorder-functions` | — | `main` (ve kurucular) `.text.startup`'ta, `.text`'in başında [Ö] | `main` = `.text`'in ilk fonksiyonu (iki korpusta da `_start`'tan önce) [Ö] |

---

## 5. ELF, strip ve debug bilgisi

**`.symtab` ile `.dynsym`:**
- `.symtab` bütün yerel ve global sembolleri tutar, yalnız bağlama ve hata ayıklama içindir; çalışma zamanında yüklenmez. `strip --strip-all` (Debian'da `dh_strip`) bunu siler.
- `.dynsym` dinamik bağlayıcı için gereklidir, strip edilmez. İçinde yalnız içe aktarılan (ve `-rdynamic` ile dışa aktarılan) semboller vardır. Korpusta cat'in `.dynsym`'inde 58–60 FUNC var, hepsi libc içe aktarımı [Ö].
- Sonuç: stripped binary'deki iç fonksiyon adlarının tek kaynağı ayrı debug dosyasıdır.

**Ayrı debug dosyası:**
- Stripped binary iki bağ taşır: `.note.gnu.build-id` (NT_GNU_BUILD_ID) ve `.gnu_debuglink` (dosya adı + CRC). İki korpusta da ikisi var [Ö].
- Debian ve Ubuntu dbgsym paketleri debug dosyasını `/usr/lib/debug/.build-id/xx/yyyy….debug` altına koyar. Karadul'un `measure.py`'si bu yolu kullanıyor ve eşleşmeyi BuildID ile kanıtlıyor [Ö: kod]. Ubuntu bu paketleri `.ddeb` olarak `ddebs.ubuntu.com`'da yayımlar [Ö: corpus.json].
- **dwz:** iki dağıtımın dbgsym'i dwz'den geçmiş. Ortak DWARF ayrı bir dosyada: `/usr/lib/debug/.dwz/aarch64-linux-gnu/coreutils.debug`, bağı `.gnu_debugaltlink` [Ö]. `DW_AT_producer` gibi dizeler `DW_FORM_GNU_strp_alt` ile oraya işaret eder. Bu dosya olmadan producer dizesi okunamaz (§7). Alt dosya aynı dbgsym paketinde geliyor [Ö].
- Debug dosyasında `.symtab` tamdır. Kod bölümleri NOBITS'tir: adres var, bayt yok.

**PLT/GOT:**
- İçe aktarılan fonksiyon çağrıları `.plt` saplaması → `.got` yuvası yoluyla gider.
- `-z now` (BIND_NOW) ile bütün yuvalar yüklemede çözülür ve RELRO sonrası salt okunur olur. Ubuntu cat'te BIND_NOW var, Debian cat'te yok (Debian'da `bindnow` varsayılan değil) [Ö][B].
- x86-64'te IBT açıkken PLT ikiye ayrılır (`.plt` + `.plt.sec`) [Ç].
- `-fno-plt` ile çağrı doğrudan `call *foo@GOTPCREL(%rip)` olur; Debian/Ubuntu varsayılanı değil [Ç].
- Karadul açısından PLT saplamaları adlarını `.dynsym`/relocation'dan alır. Bunlar isimlendirme işi değildir; harness onları doğru olarak dışlıyor [Ö: kod].

**IFUNC (`STT_GNU_IFUNC`):** glibc'nin `memcpy`/`strlen` gibi fonksiyonları çalışma zamanında CPU'ya göre seçilir. Uygulama binary'sinde IFUNC nadirdir. Ama statik bağlı binary'lerde ve libc'nin kendisinde çözücü (resolver) fonksiyonlar ayrı birer fonksiyon olarak görünür [Ç]. Karadul GT'si `STT_GNU_IFUNC`'u FUNC gibi sayıyor [Ö: kod]; bu doğru.

**`-ffunction-sections` + `--gc-sections`:**
- Her fonksiyon kendi `.text.foo` bölümüne girer. Bağlayıcı ulaşılamayan bölümleri atar.
- Debian/Ubuntu dpkg-buildflags bunu varsayılan eklemez [B: man sayfasında yok]. Bu yüzden LTO'suz bağlamada `.o` dosyasının tamamı gelir. Debian GT'sinin %57'si (quotearg.o + xmalloc.o, 276/484) buradan geliyor (Karadul ARGE belgesi).
- LTO bu etkiyi zaten yaratır: WPA ulaşılamayan fonksiyonları siler.

**PIE:**
- İki korpus da `ET_DYN` + `DF_1_PIE` [Ö]. GCC `--enable-default-pie` ile derlenmiş: Debian 9 (stretch) ve sonrası, Ubuntu 16.10 ve sonrası [Ç].
- Adresler 0 tabanlıdır, yükleyici kaydırır. Debug dosyası ile stripped binary aynı sanal adresleri kullanır, ofset gerekmez. Ghidra'nın görüntü tabanı (ELF PIE için varsayılan 0x100000) GT adresiyle karşılaştırılırken çıkarılmalıdır [Ç: Karadul'un FLIRT bulgusundaki "PIE ofseti" notu bununla tutarlı].

**CET (`endbr64`):**
- `-fcf-protection` ile her fonksiyonun başına `endbr64` gelir: global, adresi alınabilen ya da dolaylı çağrılabilen fonksiyonlar. GCC, adresi hiç alınmayan yerel fonksiyonlara `endbr64` koymayabilir [Ç].
- Bağlayıcı, yalnız bütün girdi nesneleri IBT işaretliyse `.note.gnu.property`'ye IBT yazar (AND semantiği) [Ç].
- Benzer bir durum arm64 korpusunda gözlendi [Ö]: iki derlemede de producer'da `-mbranch-protection=standard` var, ama stripped binary'de `GNU_PROPERTY` segmenti yok. Muhtemelen işaretsiz bir girdi nesnesi yüzünden [Ç].

---

## 6. Debian ile Ubuntu farkı ve Karadul ölçümüne etkisi

### 6.1 Bayraklar

**Ubuntu'da LTO:**
- Ubuntu 21.04'ten (hirsute) beri amd64, arm64, ppc64el ve s390x paketleri `-flto=auto -ffat-lto-objects` ile derleniyor (riscv64 hariç). Mekanizma dpkg'nin Ubuntu satıcı modülü [B].
- Güncel dpkg kaynağındaki `Dpkg/Vendor/Ubuntu.pm`'de `$use_feature->{optimize}{lto} = 1` bu dört mimari için açık. Aynı modül `fortify-level` değerini 3'e çekiyor ve ppc64el'de `-O3` kullanıyor [K].
- Debian'da `lto` özelliği "Disabled by default" (dpkg 1.21.0'dan beri destekleniyor) [B].

**Hardening (dpkg-buildflags man sayfası [B]):** `-D_FORTIFY_SOURCE=2`, `-fstack-protector-strong`, `-fstack-clash-protection`, `-Wformat -Werror=format-security`, `-Wl,-z,relro` varsayılan. "branch" özelliği amd64'te `-fcf-protection`, arm64'te `-mbranch-protection=standard` ekliyor. `bindnow` Debian'da varsayılan değil.

**Ubuntu GCC'nin kendi varsayılanları (dpkg dışında, [B] Ubuntu wiki):** PIE, `-fstack-protector-strong`, `-fstack-clash-protection` (19.10+), x86'da `-fcf-protection` (19.10+). `_FORTIFY_SOURCE=2`'nin GCC varsayılanı olduğu bu oturumda doğrulanamadı.

**Korpusun gerçek bayrakları (DWARF producer, dwz alt dosyasından) [Ö]:**

```
Debian 9.4-3   : GNU C17 13.2.0 -mbranch-protection=standard -mlittle-endian -mabi=lp64 -g -O2
                 -fstack-protector-strong -fstack-clash-protection -fasynchronous-unwind-tables
Ubuntu 9.4-3u6 : GNU C17 13.2.0 -mno-omit-leaf-frame-pointer -mbranch-protection=standard
                 -mlittle-endian -mabi=lp64 -g -O2 -fno-omit-frame-pointer -flto -ffat-lto-objects
                 -fstack-protector-strong -fasynchronous-unwind-tables -fstack-protector-strong
                 -fstack-clash-protection
.comment       : "GCC: (Debian 13.2.0-9) 13.2.0" / "GCC: (Ubuntu 13.2.0-23ubuntu3) 13.2.0"
```

Aynı derleyici sürümü, aynı -O2. Fark üç tane: **LTO**, **çerçeve işaretçisi** (Ubuntu 24.04) ve **FORTIFY 3** (`-D` producer'a yazılmaz; `_chk` içe aktarımlarından görülüyor, §4). Ubuntu ayrıca BIND_NOW kullanıyor.

### 6.2 Sayılar [Ö]

| | cat | cut | wc | expr | comm |
|---|---|---|---|---|---|
| Debian FUNC sembolü (LOCAL/GLOBAL) | 97 (11/86) | 103 (15/88) | 122 (15/107) | 104 (20/84) | 109 (14/95) |
| Ubuntu FUNC sembolü (LOCAL/GLOBAL) | 25 (21/4) | 31 (27/4) | 41 (31/10) | 36 (32/4) | 32 (28/4) |
| Debian `.constprop` / `.part` | 0 / 1 | 0 / 1 | 0 / 1 | 0 / 2 | 0 / 2 |
| Ubuntu `.constprop` / `.part` | 6 / 1 | 7 / 1 | 7 / 1 | 5 / 3 | 5 / 2 |

`.isra`, `.cold`, `.lto_priv` ve aynı adreste birden çok ad: iki korpusta da 0. Karadul'un puanlanan GT'si: Debian 484, Ubuntu 114 (ARGE belgesi).

### 6.3 F1 0,48 (Ubuntu) ile 0,12 (Debian) farkının derleyici açıklaması

1. **Payda.** LTO'suz bağlamada `libgnu.a`'dan çekilen her `.o` bütünüyle gelir (`--gc-sections` yok). Örnek: quotearg.o'nun 34 ve xmalloc.o'nun 21 fonksiyonu, çoğu hiç çağrılmasa bile binary'de durur. LTO'da WPA bütün programı görür. Bağlayıcı eklentisinin çözümlemesiyle `main` dışındaki semboller yerelleşir (GLOBAL 84–107 → 4–10). Ulaşılamayan fonksiyonlar silinir, küçükler inline edilir. Puanlanan GT 484'ten 114'e iner ve kalanlar büyük, çıpa (string, libc çağrısı) taşıyan fonksiyonlardır. Recall paydası LTO'suz derlemede ~4 kat büyük ve eklenen kısım çıpasız.
2. **Zincir çöküşü ve çıpanın yeri.**
   - LTO'suz derlemede çeviri birimleri arası inline imkânsız. Birim içi inline bile `-O2` eşikleriyle sınırlı: `version_etc_va`, `version_etc`'ye girmiş, ama `version_etc_arn` girmemiş (ARGE belgesi §3). Bu yüzden `"Written by"` çıpası en içteki `version_etc_arn`'da kalır. Karadul'un LTO'da ayarlanmış parmak izi ise dış API adını (`version_etc`) bu fonksiyona yapıştırır: FP + FN.
   - LTO'da `version_etc` yerelleşir ve tek çağıranı (`main`) olduğu için ipa-cp onu bütün bağlamlar için özelleştirir (`version_etc.constprop.0`). İç zincir de içine inline edilir. Sonuçta çıpa ile API adı aynı fonksiyonda buluşur.
   - Aynı mekanizma `hard_locale` ← `setlocale_null_r` ve `full_write` ← `safe_write` için de geçerli [Ö: `.constprop` listesi].
3. **"Komşu fonksiyona düşme" ve yerleşim.**
   - LTO'suz derlemede bir gnulib modülünün fonksiyonları bitişik bir blok oluşturur: tek `.o`, bağlayıcı girdi sırası.
   - Blok içindeki sıra kaynak sırası değildir. -O1 ve üstünde GCC fonksiyonları **çağrı grafiğinin ters sonsırası (RPO) ile, önce çağrılanlar** yayar. Kaynaktaki yorum [K]: "Output functions in RPO so callees get optimized before callers ... far from optimal code layout". Deneyde de böyle çıktı [Ö]: -O0'da sıra kaynak sırası, -O2'de çağıran `kullan` en sonda.
   - Bu yüzden çıpayı tutan iç fonksiyon bloğun önünde, API sarmalayıcısı birkaç fonksiyon arkasındadır. Çıpaya bakan bir kural adı "zincirin bir önceki/sonraki komşusuna" verir.
   - LTO'da yerleşim WPA bölümlemesi ve LTRANS içi RPO ile belirlenir. Modül blokları dağılır (iki bölüm, `-flto=auto`). Konumsal kanıt LTO'da işe yaramaz; LTO'suzda ise güçlüdür, yeter ki RPO sırası modellensin.
4. **İsim eklerinin rolü küçük.** Sonek normalizasyonu Karadul'da var (`metrics.py` FIX-4). Ubuntu'daki 38 sonekli ad doğru normalize ediliyor. Fark sonekten değil, fonksiyon kümesinin kendisinden geliyor.

Sonuç: Ubuntu ile Debian F1'i aynı "binary" üzerinde ölçülmüş iki ayrı görevdir. LTO'lu görev "az sayıda, büyük, çıpalı fonksiyon"; LTO'suz görev "çok sayıda, küçük, çıpasız, modül bloklarına dizili fonksiyon". Makalede ikisi ayrı satır olarak raporlanmalı ve ortak fonksiyon kesişimi üzerinde ayrıca F1 verilmelidir (§8).

---

## 7. Deney kayıtları

Ortam: Docker çalışmıyordu (`docker.sock` yok). Yeni imaj çekilmedi, Docker başlatılmadı. macOS'ta x86-64-linux hedefli GCC yok. Homebrew gcc-16 yalnız aarch64-darwin (Mach-O) üretiyor. Bu yüzden ELF x86-64 derleme deneyi **yapılamadı**. Yerine iki deney yapıldı:

**D1 — Karadul korpusunun gerçek ELF'leri (arm64, GCC 13.2).** Kaynak: `~/karadul_olcum/corpus/{debian-9.4-3,ubuntu-9.4-3ubuntu6}` (salt okuma). Araç: Homebrew `llvm-readelf`/`llvm-dwarfdump`.
- `.comment` ve producer: dbgsym'deki `DW_AT_producer` `DW_FORM_GNU_strp_alt` biçiminde, `()` döndü. Dize, dwz alt dosyasının `.debug_str`'inden okundu (§6.1). Çıktı: `deney_gcc/elf_korpus/producer_flags.txt`, `comment_producer.txt`.
- Fonksiyon sembolleri ve sonek sayımı (700 FUNC sembolü): `func_syms.txt`, `suffix_stats.txt` (§6.2).
- Klon DIE'leri: Ubuntu `cat.debug`'da `version_etc.constprop.0` (0x3390) ve `gettext_quote.part.0` (0x2ff0) DIE'lerinde `DW_AT_name` yok, `DW_AT_abstract_origin` var.
- Stripped özellikler (`stripped_ozellikler.txt`): ikisi de PIE ve GNU_RELRO, ikisinde de `.gnu_debuglink` var; BIND_NOW yalnız Ubuntu'da; `_chk` içe aktarımları farklı (§4).
- `main`'in yeri: dört örnekte de `main` `.text`'in ilk adresinde, `_start`'tan önce (Debian cat 0x1d00 = `.text` başı; Ubuntu cat 0x1b00 = `.text` başı).

**D2 — GCC orta katmanı (gcc-16, aarch64-darwin, `deney_gcc/mid_end/`).**
- `klon.c` (ipa-cp, ipa-sra, ipa-split, ICF örnekleri). `-O0/-O1/-O2/-O3/-Os -fdump-passes` → `passes_*.txt`, matris `pass_matrisi_gcc16.txt`.
- `-O2 -S` → `klon_O2.s`: semboller `olcekle.constprop.0`, `alan_oku.constprop.0.isra.0`. `ikiz_d` ICF ile yok oldu (dump: "Reclaiming functions: ikiz_d/11", "Equal symbols: 2"). Adresleri alınan `ikiz_a`/`ikiz_b` birleşmedi. Mach-O alias desteklemediği için ELF'teki alias/sarmalayıcı davranışı burada gözlenemez.
- Yayın sırası: -O0'da `olcekle, alan_oku, bol, ikiz_a, ikiz_b, ikiz_c, ikiz_d, adres_al, adres_al2, kullan` (kaynak sırası). -O2'de `ikiz_a, ikiz_b, ikiz_c, bol, olcekle.constprop.0, alan_oku.constprop.0.isra.0, kullan, …` (çağrılanlar önce).
- ipa-cp dump'ı: "Creating a specialized node of olcekle/5 for all known contexts" (-O2, `-fipa-cp-clone` yok).
- `-freorder-blocks-and-partition` Darwin'de `.cold` üretmedi. x86 ELF davranışı yalnız kaynaktan (i386 seçenek tablosu, final.cc) belgelendi.
- LTO (`mid_end/lto/`): iki TU'da aynı adlı static `yardimci` → hem `-flto-partition=max` hem `=one` ile `yardimci.lto_priv.0` ve `yardimci.lto_priv.1`. Darwin'de bağlayıcı eklentisi olmadığı için `a_dis`/`b_dis` global kaldı; ELF'te eklenti çözümlemesiyle yerelleşmeleri beklenir [Ç].

**D3 — Kaynak okuma.** `raw.githubusercontent.com/gcc-mirror/gcc` (etiketler `releases/gcc-8.5.0`, `9.4.0`, `10.1.0`, `11.1.0`, `12.1.0`, `13.2.0`) `curl | grep` ile okundu, diske yazılmadı. Okunan dosyalar: `passes.def`, `opts.c[c]`, `params.def`/`params.opt`, `cgraphclones.c`, `final.cc`, `ipa-icf.cc`, `lto/lto-partition.cc`, `cgraphunit.cc`, `common/config/{i386,aarch64}/*-common.c[c]`. dpkg: `salsa.debian.org` `Dpkg/Vendor/Ubuntu.pm` ve Debian man sayfası.

Yapılamayanlar: x86-64 `.cold` sıklığı, `endbr64` dağılımı, GNU ld bağlayıcı betiği sırası (`ld --verbose`). Hepsi Docker'da bir Debian/Ubuntu x86-64 imajıyla 10 dakikalık iştir (§8-9).

---

## 8. Karadul için somut öneriler

1. **Derleme künyesini ölç, varsayma.** `measure.py prepare` adımı dwz alt dosyasından `DW_AT_producer`'ı ve `.comment`'i okuyup `manifest.json`'a yazsın: LTO, -O, çerçeve işaretçisi, `-fcf-protection`/BTI. FORTIFY düzeyi için `.dynsym`'deki `_chk` içe aktarımları kaydedilsin. Makaledeki her korpus satırı bu künyeyle verilsin.
2. **GT'de "parça" sınıfı.** `foo.cold` ana fonksiyonun parçasıdır. GT'de `fragment_of: foo` olarak işaretlensin, F1 paydasından çıkarılsın, ayrı satırda raporlansın. arm64 korpusunda etkisi 0. x86-64'e (ve SymGen kıyasına) geçince zorunlu.
3. **Sonek kuralını tamamla.** `metrics.py`'deki regex'e `localalias` (PIC'de `-fsemantic-interposition` yerel takma adı) ve `artificial_thunk` eklensin. GCC ≤8 binary'leri için numaralı `.cold.N` zaten kapsanıyor. Ölçüm raporuna "sonekli GT oranı" yazılsın (Ubuntu 38/165, Debian 7/535).
4. **İkinci GT kaynağı: DWARF abstract_origin.** Klon adını DIE'den (`abstract_origin` → `DW_AT_name`) almak sonek ayrıştırmasını gereksiz kılar ve `DW_AT_decl_file` verir: hangi gnulib modülü, hangi `.c`. Bu, D7–D9 modül blok kuralları için yer-gerçeği (GT) üretir. dwz alt dosyası da okunmalı (`DW_FORM_GNU_ref_alt` / `strp_alt`).
5. **Modül blok sırası RPO'dur, kaynak sırası değildir.** D7–D9 için beklenen sıra şöyle üretilmeli: pin'lenmiş gnulib (`vendor/gnulib-ref`) **aynı GCC sürümü ve bayraklarla** (`-O2`, LTO'suz) derlenir, `.o` başına fonksiyon sırası çıkarılır. Bu deterministiktir, LLM içermez ve derleyici sürümü değişince yeniden üretilir. -O0 binary'lerinde kaynak sırası geçerlidir.
6. **Zincir kuralı derleme kipine göre.** LTO'suzda çıpa en içteki fonksiyondadır, API adı ise aynı modülde çağıran yönünde 1–3 adım ötededir. Derinliği çağrı grafiğinden çıkar (ARGE K1 ile uyumlu). LTO'da çıpa ile API aynı `.constprop` fonksiyonundadır. Kip, binary'den ucuzca tahmin edilebilir: yerel/global oranı stripped binary'de görünmez, ama `.gnu.lto_` izi, fonksiyon sayısı / kod boyutu oranı ve modül bloklarının bütünlüğü kullanılabilir [Ç: doğrulanmalı].
7. **`main` konum ipucu.** GCC -O2 + GNU ld'de `main` `.text.startup`'tadır ve `.text`'in başındadır. x86-64'te önünde `.text.unlikely` (`.cold` parçaları) bulunabilir [Ç]. FIX-1 `main` kurtarımına bağımsız bir ikinci kanıt olarak eklenebilir.
8. **noreturn listesi Ghidra'ya.** `xalloc_die`, `usage` (yalnız `exit` çağıran yol), `__stack_chk_fail`, `__fortify_fail`, `__chk_fail`, `abort`, `exit`, `_exit`, `__assert_fail`, `error` (yalnız status≠0; koşullu) gibi adlar analizden önce noreturn işaretlensin. GCC noreturn yollarını fonksiyon sonuna (x86'da `.cold`'a) taşıdığı için yanlış akış sınırları bozar.
9. **API kanıtında ters katlama tablosu.** `__X_chk → X` (`printf, fprintf, sprintf, snprintf, vfprintf, memcpy, memmove, memset, strcpy, stpcpy, strcat, strncpy, read, fgets, realpath` …) ve GCC builtin katlamasının tersi (`puts/putchar ⇐ printf`, `fputs/fwrite ⇐ fprintf`, `strcpy ⇐ sprintf("%s")`), ayrıca `memset`/`memcpy` çağrısının döngü dağıtımından gelebileceği notu. GCC 15'in varsayılan `gnu23` standardı glibc ≥2.38 ile `strtol` → `__isoc23_strtol` yönlendirmesi getirir [Ç: doğrulanmalı]; tablo bunu da kapsamalı.
10. **Adil LTO kıyası.** İki korpusta da var olan (taban adı eşleşen) fonksiyonların kesişimi üzerinde ayrı F1 verilsin. Böylece "LTO paydayı küçülttü" etkisi ile "Karadul daha iyi isimlendirdi" etkisi ayrılır.
11. **SymGen (GCC 9.4, O0–O3, x86-64) ile kıyas için.**
    - GCC 9.4 -O2'de `-finline-functions` ve vektörleme yok, IPA-SRA erken geçiş, `.cold` var (x86). Güncel GCC -O2 binary'leriyle aynı dağılım varsayılmamalı.
    - SymGen'in GT'sinin sonekleri nasıl ele aldığı ve `.cold` parçalarını sayıp saymadığı, yayımlanan artefaktta kontrol edilmeli. Kendi normalizasyonumuzla uyumsuzsa sonuç iki biçimde verilmeli.
    - GCC 9.4.0 Ubuntu 20.04'ün sistem derleyicisi olduğundan SymGen binary'lerinde Ubuntu GCC varsayılan hardening'i (PIE, SSP-strong, CET, stack-clash) bulunabilir [Ç]. Bu, ilk 10 binary'nin `.comment` ve `endbr64` varlığıyla doğrulanmalı.
12. **x86-64 boşluğunu kapat (Docker açılınca).** Yerelde bulunan bir Debian/Ubuntu amd64 imajıyla (yeni imaj çekmeden) ya da Berke'nin onayıyla tek bir amd64 coreutils + dbgsym çiftiyle şunlar sayılsın: `.cold` oranı, `.part`/`.constprop` sayıları, `endbr64` ile başlayan fonksiyon oranı ve Ghidra'nın `.cold` adreslerinde fonksiyon açıp açmadığı. Bu yarım saatlik iş §3'teki [Ç] işaretli Ghidra satırlarını ölçüme çevirir.

---

## 9. Kaynakça

GCC kaynak kodu (bu oturumda okundu, [K]):
- passes.def — [GCC 9.4.0](https://github.com/gcc-mirror/gcc/blob/releases/gcc-9.4.0/gcc/passes.def), [GCC 13.2.0](https://github.com/gcc-mirror/gcc/blob/releases/gcc-13.2.0/gcc/passes.def)
- -O seviye tabloları — [opts.c 9.4.0](https://github.com/gcc-mirror/gcc/blob/releases/gcc-9.4.0/gcc/opts.c), [opts.cc 13.2.0](https://github.com/gcc-mirror/gcc/blob/releases/gcc-13.2.0/gcc/opts.cc)
- Parametreler — [params.def 9.4.0](https://github.com/gcc-mirror/gcc/blob/releases/gcc-9.4.0/gcc/params.def), [params.opt 13.2.0](https://github.com/gcc-mirror/gcc/blob/releases/gcc-13.2.0/gcc/params.opt)
- Klon adları — [cgraphclones.c 9.4.0](https://github.com/gcc-mirror/gcc/blob/releases/gcc-9.4.0/gcc/cgraphclones.c), [cgraphclones.c 8.5.0](https://github.com/gcc-mirror/gcc/blob/releases/gcc-8.5.0/gcc/cgraphclones.c), [final.cc 13.2.0 (`.cold`)](https://github.com/gcc-mirror/gcc/blob/releases/gcc-13.2.0/gcc/final.cc)
- [ipa-icf.cc 13.2.0](https://github.com/gcc-mirror/gcc/blob/releases/gcc-13.2.0/gcc/ipa-icf.cc) (alias/sarmalayıcı/yönlendirme yorumu)
- [lto/lto-partition.cc 13.2.0](https://github.com/gcc-mirror/gcc/blob/releases/gcc-13.2.0/gcc/lto/lto-partition.cc) (`lto_priv`, terfi)
- [cgraphunit.cc 13.2.0](https://github.com/gcc-mirror/gcc/blob/releases/gcc-13.2.0/gcc/cgraphunit.cc) (RPO yayın sırası, `no_reorder`)
- Hedef tabloları — [i386-common.cc 13.2.0](https://github.com/gcc-mirror/gcc/blob/releases/gcc-13.2.0/gcc/common/config/i386/i386-common.cc), [i386-common.c 9.4.0](https://github.com/gcc-mirror/gcc/blob/releases/gcc-9.4.0/gcc/common/config/i386/i386-common.c), [aarch64-common.cc 13.2.0](https://github.com/gcc-mirror/gcc/blob/releases/gcc-13.2.0/gcc/common/config/aarch64/aarch64-common.cc)

GCC belgeleri (bu oturumda açılmadı; okur için başvuru):
- [GCC Optimize Options](https://gcc.gnu.org/onlinedocs/gcc/Optimize-Options.html), [GCC Internals: Passes](https://gcc.gnu.org/onlinedocs/gccint/Passes.html), [GCC 10 değişiklikleri](https://gcc.gnu.org/gcc-10/changes.html), [GCC 12 değişiklikleri](https://gcc.gnu.org/gcc-12/changes.html)

Debian/Ubuntu:
- [dpkg-buildflags(1), Debian unstable](https://manpages.debian.org/unstable/dpkg-dev/dpkg-buildflags.1.en.html) — okundu [B]
- [dpkg `scripts/Dpkg/Vendor/Ubuntu.pm`](https://salsa.debian.org/dpkg-team/dpkg/-/blob/main/scripts/Dpkg/Vendor/Ubuntu.pm) — okundu [K]
- [ubuntu-devel: "turning on link time optimizations (LTO) for 21.04"](https://lists.ubuntu.com/archives/ubuntu-devel/2021-March/041421.html) — arama sonucu [B]
- [Ubuntu wiki ToolChain/LTO](https://wiki.ubuntu.com/ToolChain/LTO) — arama sonucu; doğrudan okuma başarısız [B]
- [dpkg 1.20.9ubuntu1 (Launchpad)](https://answers.launchpad.net/ubuntu/+source/dpkg/1.20.9ubuntu1) — arama sonucu [B]
- [Debian wiki ToolChain/LTO](https://wiki.debian.org/ToolChain/LTO) — arama sonucu ("Debian'da varsayılan değil") [B]
- [Ubuntu wiki ToolChain/CompilerFlags](https://wiki.ubuntu.com/ToolChain/CompilerFlags) — arama özeti; doğrudan okuma 404 [B]
- [Phoronix: Ubuntu 21.04 LTO](https://www.phoronix.com/news/Ubuntu-21.04-Does-LTO) — ikincil [B]

ELF/DWARF (bu oturumda açılmadı):
- [System V gABI](https://refspecs.linuxfoundation.org/elf/gabi4+/contents.html), [x86-64 psABI](https://gitlab.com/x86-psABIs/x86-64-ABI), [DWARF 5](https://dwarfstd.org/dwarf5std.html), [dwz](https://sourceware.org/dwz/), [Debian AutomaticDebugPackages](https://wiki.debian.org/AutomaticDebugPackages)

Karadul iç belgeleri:
- `docs/arge/2026-09-25_lto_tani_ve_tasarim.md` (f893d72), `scripts/measurement/{corpus.json,function_f1.py}`, `tests/benchmark/metrics.py` (`_normalize`)
- SymGen veri seti künyesi: aynı scratchpad'deki `makale/veri_setleri.md` (başka ajan; bu belgede bağımsız doğrulanmadı)
