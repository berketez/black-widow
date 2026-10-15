# Derleyici Kalıpları ve Amaç Kanıtları — Tarif Katmanı İçin Kural Malzemesi

Hazırlanış: 2026-10-15 · Alan: derleyicinin C yapılarını makine koduna çevirişi ve derlemeden sağ çıkan amaç kanıtları.
İşaretler: **[Ö]** bu oturumdaki deneyde ölçüldü (§7) · **[L]** makale, resmî belge veya kaynak kodu (§9) · **[B]** alan bilgisi, bu oturumda doğrulanmadı.
Kapsam dışı (diğer ajanlar): teorik sınırlar; Clang/LLVM hattının iç ayrıntısı ve arm64 ABI; GCC hattı, IPA klonları, ELF.

---

## 1. Özet

1. Derleyici, kaynağın "neyi" yaptığını korur ama "nasıl yazıldığını" siler. Sabitle bölme, switch, bellek işlemleri ve döngüler -O2'de tanınmaz biçimlere girer. Ghidra bunların bir kısmını geri katlar (`x / 7`, `switch`), bir kısmını katlayamaz (bit testi maskesi, vektör döngüsü, satır içi `memcpy`) [Ö].
2. Tersi de oluyor: kaynakta olmayan libc çağrıları ortaya çıkıyor. Apple clang -O2'de el yazımı sıfırlama döngüsü `bzero`'ya, kopyalama döngüsü `memcpy`'ye, `while(*p) p++;` döngüsü de `strlen`'e dönüştü [Ö]. Tarif katmanı döngüyü ve çağrıyı aynı fiile eşlemeli.
3. En güvenilir amaç kanıtı, **argüman konumuna ve veri akışına bağlanmış** dış API çağrılarıdır (`open` → `read` → `close` aynı fd). Bayrak sabitleri işletim sistemine bağlıdır: `O_CLOEXEC` Darwin'de `0x1000000`, Linux'ta `0x80000` [Ö][L].
4. FORTIFY'ın `_chk` çağrıları hem API adını korur hem de yığın tamponunun boyutunu argüman olarak ele verir: `___strcpy_chk(buf, src, 0x40)` [Ö].
5. Karadul'un kripto sabit taraması (`c_algorithm_id.py::_scan_constants`) bu deneyin 167 fonksiyonunda 36 sabit eşleşmesi üretti. Bunlardan yalnız 1'i doğruydu [Ö]. Nedenleri: alt-dize eşleme (`0xfffffff` ⊂ `0xffffffff`), tek ve yaygın sabitler (`0x1`), işaretli gösterim (`0x9E3779B9` → `-0x61c88647`), sabit havuzu (`_DAT_…`) ve 500 karakter filtresi. Düzeltme yöntemi §3.1'de.
6. capa'nın kural formatı (YAML, mantık ağacı, kapsamlar, `match` ile bileşim, kural başına zorunlu örnek) tarif kuralları için iyi bir şablon. Ama capa Mach-O okumuyor (capa 9.4.0 deney binary'sini reddetti) ve kuralların çoğu Windows API'sine dayanıyor [Ö]. Sayıları argüman konumuna bağlamaması da sahte pozitif kaynağı.
7. Derleyici kökeni (derleyici, sürüm, -O düzeyi) kural setini seçmek için kullanılmalı. Eşikler hedefe göre değişiyor: atlama tablosu x86-64'te 4 vakada, AArch64'te ancak 10 vakada başlıyor [Ö].
8. §8'de "kanıt → fiil/nesne" biçiminde 22 tarif kuralı ve her birinin güven gerekçesi var.

---

## 2. Kalıp kataloğu

Deney: Apple clang 21.0.0 ile `arm64-apple-macos13` ve `x86_64-apple-macos13` hedefleri, `-O0` ve `-O2`. Ghidra 12.1.2 headless decompile. Linux hedefleri için yalnız nesne dosyası (`-c`) üretildi (§7). Hücrelerde biçim: **x86-64 / arm64**, gerekiyorsa **-O0 → -O2**.

### 2.1 Denetim akışı ve aritmetik

| Kalıp | Makine kodundaki işaret | Ghidra'daki görünüm | Kaynaktaki karşılık |
|---|---|---|---|
| **switch → atlama tablosu** | x86-64: `cmp $N; ja default; lea tbl(%rip); movslq (%rcx,%rax,4); add; jmp *%rax`. Tablo 32 bit göreli girişli; Mach-O'da `__text` içinde, ELF'te `.rodata`'da [Ö]. arm64: `cmp; b.hi; adrp/add lJTI; adr; ldrb w11,[x9,x8]; add x10,x10,x11,lsl #2; br x10`. Girişler 1 baytlık, 4 ile ölçeklenen sıkıştırılmış farklar [Ö]. | Tablo çözülürse `switch(x) { case 0: … }`. -O0 x86-64'te tam `switch` geri geldi [Ö]. | `switch` ve yoğun `case` değerleri. |
| **switch eşiği (hedefe göre)** | Her vakada farklı dış çağrı yapan -O2 testi: x86-64'te denenen en küçük değer olan **4 vakada** bile tablo var. AArch64'te (Linux ve Darwin) **≤9 vakada karşılaştırma ağacı, 10+ vakada tablo** [Ö]. arm64 -O0'da (8 vaka) tablo yok, `subs w8,w8,#k; b.eq` zinciri var [Ö]. | Tablo yoksa iç içe `if`. Aynı kaynak, mimariye göre farklı görünür. | Aynı `switch`. Kural setinde "switch'i tanı" işi mimariye göre ayarlanmalı. |
| **switch → arama tablosu** | Tüm vakalar sabit döndürüyorsa -O2'de dallanma kalkar: `cmp $7; ja; lea tbl; movl (%rcx,%rax,4)` / `ldr w0,[x8,w0,uxtw #2]` [Ö]. Bu atlama tablosu değil, **veri** tablosu. | `if (x < 8) return *(undefined4*)(&DAT_… + x*4); return 0xffffffff;` [Ö] | `switch (x) { case k: return SABİT; }` ya da `const int tbl[]`. Kaynakta switch mi dizi mi olduğu ayırt edilemez. |
| **switch → ikili arama** | Seyrek değerler: önce pivotla karşılaştırma (`cmp $0x1387; jle`), sonra eşitlik dalları [Ö]. arm64'te büyük değerler `mov/movk` ile kurulur. | İç içe `if (x < 5000) { if (x == 3) … } else if (x < 0x12fd1) …` [Ö] | Seyrek `case` değerleri. Pivot (4999, 0x12FD0) kaynakta yoktur; derleyicinin seçtiği orta noktadır. |
| **switch → bit testi** | Aynı hedefe giden küçük aralıklı vakalar: `cmp $0x3b; ja; movabs $0x800100100003e00; bt %rcx,%rdx` / `lsl x8,1,x; mov/movk maske; tst` [Ö]. | `if (c < 0x3c && ((1L << (c & 0x3f)) & 0x800100100003e00U) != 0)` [Ö]. Ghidra switch'e geri katlamıyor. | `case ' ': case '\t': … return 1;` Maske, karakter kümesini kodluyor: bitler {9–13, 32, 44, 59} = `\t \n \v \f \r`, boşluk, `,`, `;`. **Tarif için altın değerinde (§8 K7).** |
| **switch → aritmetiğe katlanma** | 16 vakanın hepsi `g(i, v+3i+1)` ise tablo da dal da kalmıyor: `add w8,w0,w0,lsl #1; add w8,w8,w1; add w1,w8,#1; b _g` [Ö]. | Tek çağrı ve bir formül. | Düzenli vakalı switch. Kaynaktaki vaka yapısı kaybolur. |
| **İşaretsiz sabitle bölme** | `x/7`: `imul $0x24924925` (x86) / `mov #0x4925; movk #0x2492,lsl 16; umull` (arm64), ardından `sub; shr 1; add; shr 2` düzeltmesi [Ö]. 64 bit `/1000`: `shr 3; mul 0x20C49BA5E353F7CF; shr 4` [Ö]. | Ghidra 12 katlıyor: `param_1 / 7` [Ö]. | `x / sabit`. Yöntem Granlund–Montgomery (PLDI 1994) [L]. |
| **İşaretli bölme** | `x/7` (int): sihirli sayı `0x92492493` (x86 ekranda `-0x6db6db6d`), `smull`/`imul` + `add x` + `sar 2` + işaret biti düzeltmesi (`shr 31; add`) [Ö]. | `param_1 / 7` [Ö] | `int / sabit` |
| **Mod** | `x%10`: `0xCCCCCCCD` çarpımı + `shr 35` + geri çarpıp çıkarma: `lea (%rdx,%rdx,4); add; sub` (x86) / `msub` (arm64) [Ö]. | `param_1 % 10` [Ö] | `x % sabit`. Döngüde `'0' + x%10` ve `x/10` birlikteyse sayıdan metne çevirme. |
| **İşaretli 2'nin kuvvetine bölme** | `x/16`: `lea 0xf(%rdi); test; cmovns; sar 4` / `add #0xf; cmp; csel; asr #4` [Ö]. | **Katlanmıyor:** `iVar1 = x + 0xf; if (-1 < x) iVar1 = x; return iVar1 >> 4;` [Ö] | `int / 16`. Tarif katmanı bu kalıbı `x / 16`'ya geri yazmalı. |
| **Koşullu seçim** | `cmovg`, `cmovs`, `cmovl` (x86); `csel`, `cneg`, `cset` (arm64) [Ö]. -O0'da dallı. | Kısa `if` ve atama: `if (a < b) a = b; return a;` [Ö] | `a > b ? a : b`, `abs`, `clamp` |
| **popcount** | `while(x){x&=x-1;c++;}`: arm64 -O2'de deyim tanındı → `fmov; cnt.8b; addv.8b` (NEON) [Ö]. x86-64 tabanında (`-mpopcnt` yok) döngü korundu [Ö]. `__builtin_popcount` x86-64 tabanında `0x55555555, 0x33333333, 0x0F0F0F0F, 0x01010101` maskeleriyle açıldı [Ö]. | arm64: bayt başına `POPCOUNT(...)` ve `CONCAT` gürültüsü [Ö]. | Bit sayma. Not: bu dört maske **derleyici ürünü**dür; kripto ya da "sihirli sabit" kanıtı sayılmamalı. |
| **bswap / rotate** | Elle yazılmış bayt çevirme → `bswap` / `rev` [Ö]. Döndürme → `rol %cl` / `neg + ror` (arm64'te rol yok) [Ö]. | bswap maskeli kaydırma olarak görünür: `(x & 0xff00ff00) >> 8 | …` [Ö]. Döndürme ise `x >> (-r & 0x1f) | x << 0x20 - …` [Ö]. | `htonl/ntohl`, hash/kripto karıştırma. Bayt çevirme yanında ağ API'si varsa ağ bayt sırası. |
| **2'nin kuvveti testi** | `lea -1; test; sete` / `sub; tst; cset; csel` [Ö] | `x & (x-1)` biçimine yakın, okunur. | `is_pow2` |

### 2.2 Bellek ve dizgi işlemleri, deyim (idiom) tanıma

| Kalıp | Makine kodundaki işaret | Ghidra'daki görünüm | Kaynaktaki karşılık |
|---|---|---|---|
| **Satır içi memcpy (küçük, sabit boyut)** | 16 bayt: `movups (%rsi); movups (%rdi)` / `ldr q0; str q0` [Ö]. | `memcpy` **yok**. İki 8 baytlık atama görünür: `param_1[1] = param_2[1]; *param_1 = …` [Ö] | `memcpy(d, s, 16)` veya struct ataması `*d = *s`. Ayırt edilemez. |
| **Satır içi memset (sabit boyut)** | 64 bayt sıfır: `xorps; movups ×4` / `movi.2d v0,#0; stp q0,q0 ×2` [Ö]. | Sekiz tane `= 0` ataması [Ö] | `memset(p, 0, 64)`, `= {0}`, `bzero` |
| **Değişken boyutlu sıfırlama (Darwin)** | `memset(p, 0, n)` → arm64'te **`bzero`**, x86-64'te **`__bzero`** çağrısına dönüşür (Mach-O sembolleri `_bzero` / `___bzero`) [Ö]. | `_bzero(p, n)` | `memset(…, 0, …)`. Darwin'de `bzero` görmek kaynakta `bzero` yazıldığını göstermez. |
| **strlen(sabit)** | Derleme zamanında katlanır: `mov w0, #7` [Ö] | `return 7;` | `strlen("karadul")`. Kanıt **tamamen kaybolur**. |
| **strcmp / strncmp sabitle** | Clang -O2'de çağrı **kaldı**: `lea "GET"; call _strcmp` [Ö]. GCC'nin kısa sabitlerde satır içi bayt karşılaştırması üretebildiği bilinir [B]. | `iVar1 = _strcmp(param_1,"GET"); return iVar1 == 0;` [Ö] | Komut veya anahtar kelime karşılaştırması. Literal, en güçlü isim kanıtlarından biri. |
| **Döngü → libc çağrısı (deyim tanıma)** | -O2: `for(i<n) a[i]=0` → sınır kontrolü, ardından `b _bzero` (boyut `ubfiz x1,x1,#2,#32` = n·4). Kopyalama döngüsü → `b _memcpy`. `while(*p)p++` → `b _strlen` [Ö]. strlen deyimini LLVM 2025'te ekledi [L]. | `if (0 < n) _bzero(p, n << 2);` [Ö]. Yalnız tek kuyruk sıçramasından ibaret fonksiyonları Ghidra **thunk** sayar, strip edilmiş binary'de hedefin adını alırlar [Ö]. | El yazımı döngü. -O0'da döngü olarak kalır: `for (…) *(p + i*4) = 0;` [Ö] |
| **Ters yön: çağrı → döngü veya vektör** | Sabit küçük boyutlu `memcpy/memset` vektör yükleme ve saklamaya dönüşür (yukarıda) [Ö]. | Alan atamaları | `memcpy/memset` çağrısı |
| **Struct kopyalama** | Satır içi memcpy ile aynı. Büyük struct'ta `memcpy` çağrısı kalabilir [B]. | Alan alan atama | `*d = *s` |

### 2.3 Çağrı kuralı kalıpları

| Kalıp | Makine kodundaki işaret | Ghidra'daki görünüm | Kaynaktaki karşılık |
|---|---|---|---|
| **Büyük struct dönüşü (sret)** | x86-64 SysV: gizli işaretçi `%rdi`, dönüşte `%rax`. Çağıran `lea -0x40(%rbp),%rdi` verir. arm64: dolaylı sonuç yazmacı **x8**, çağıran `mov x8, sp` verir [Ö]. | x86: `_make_big(local_48, param_1)`, yani gizli işaretçi ilk parametre gibi görünür [Ö]. arm64'te x8 parametre listesinde görünmeyebilir [B]. | `struct Big f(long)`. Tarif için "yapı oluşturucu" ipucu. |
| **Küçük struct dönüşü** | 8 bayt tek yazmaçta paketlenir: `orr x0,x9,x8,lsl #32` / `shl $32; or` [Ö]. | `return CONCAT44(param_1 * 3, param_1);` [Ö] | `struct {int a,b;}` dönüşü. `CONCAT44` küçük struct dönüşünün işaretidir. |
| **varargs (çağrılan taraf)** | x86-64 SysV: `rsi…r9` yığına dökülür; `test %al,%al; je` ile `xmm0-7` kaydı atlanır; `va_list` başlangıcı `movabs $0x3000000008` (gp_offset=8, fp_offset=48) [Ö]. arm64 Darwin: yazmaç kayıt alanı yok, `va_list` yığın işaretçisi (`add x8, sp, #0x10`), her adımda +8 [Ö]. | x86: 14 parametre ve `in_AL` [Ö]. arm64 Darwin: `register0x00000008` üzerinden işaretçi yürüyüşü [Ö]. | `int f(int n, ...)` + `va_arg` döngüsü |
| **varargs (çağrı yeri)** | arm64 Darwin'de değişken argümanlar **yığından** geçer (Apple belgesi) [L][Ö]. x86-64 SysV'de `%al` = kullanılan vektör yazmacı sayısı [B]. | Darwin arm64'te Ghidra değişken argümanları **göstermez**: `_fprintf(pFVar5, "open %s: %s\n");` [Ö] | `fprintf(stderr, fmt, a, b)`. Format string yine görünür, argüman sayısı format'tan çıkarılabilir. |
| **Kuyruk çağrısı** | -O2: `b _hedef` / `jmp _hedef`. x86 Darwin'de çerçeve işaretçisi korunduğu için önce `pop %rbp` gelir [Ö]. -O0'da `bl` ve epilog [Ö]. | Normal çağrı ve `return`. Tek sıçramalıysa thunk [Ö]. | `return g(x + 1);` |

### 2.4 Güvenlik ve hata yolu kalıpları

| Kalıp | Makine kodundaki işaret | Ghidra'daki görünüm | Kaynaktaki karşılık |
|---|---|---|---|
| **Yığın koruyucu (canary)** | Darwin (her iki mimari): GOT'tan `___stack_chk_guard` yüklenir, çerçeve tepesine yazılır, epilogda karşılaştırılır, uyuşmazlıkta `___stack_chk_fail` [Ö]. Linux x86-64: `mov %fs:0x28,%rax` [Ö]. Linux AArch64: GOT'tan `__stack_chk_guard` [Ö]. Darwin'de `__SSP__` varsayılan olarak tanımlı [Ö]. | `local_18 = *(long *)PTR____stack_chk_guard_…; … if (*(long*)PTR… == local_18) return …; ___stack_chk_fail();` [Ö] | Kaynakta yoktur. Yığında dizi (tampon) olduğunu gösterir; isim değil tip ipucudur. |
| **FORTIFY** | Darwin'de `-O2` ile `_FORTIFY_SOURCE=2` varsayılan [Ö]. `strcpy(buf[64], s)` → `___strcpy_chk(buf, s, 0x40)`. `memcpy(tmp[32], s, n)` → `___memcpy_chk(tmp, s, n, 0x20)` [Ö]. glibc: `__memcpy_chk` gibi `__*_chk` adları ve `open` ailesi için `__open_2` [L]. `__printf_chk`'nin başa eklenen `flag` argümanı [B]. | `___strcpy_chk(acStack_58, param_1, 0x40);` Ghidra boyut argümanını tipe yansıtmıyor, tamponu `char acStack_58[3]` + `local_55` diye bölüyor [Ö]. | `strcpy`, `memcpy`, `snprintf`… Hedef boyutu derleyicinin bildiği tampon. |
| **errno** | Darwin: `bl ___error` ve `ldr/str [x0]`. glibc: `call __errno_location` ve `mov %ebx,(%rax)` [Ö]. | `piVar4 = ___error(); *piVar4 = 5;` [Ö] | `errno = EIO;` / `strerror(errno)` |
| **-1 dönüşü ve işaret testi** | `fd < 0` → `tbnz w0, #31` (arm64), `ssize_t < 0` → `tbnz x0, #63` [Ö]. x86: `test; js` [B]. | `if (iVar1 < 0)`. Dönüş tipi yanlış çıkarıldığında `-1` `0xffffffff` olarak görünür (`sVar3 = 0xffffffff`) [Ö]. | POSIX hata sözleşmesi |
| **goto cleanup** | Hata dalları ortak kuyruk bloklarına atlar: `free` → `close` → `ret` zinciri, düşüşle (fall-through) bağlı [Ö]. GCC bunları `foo.cold` bölümüne ayırabilir [B, GCC ajanının alanı]. | Ghidra iç içe `if/else` olarak yapılandırdı. `goto` görünmedi, kaynaklar ters sırada serbest bırakılıyor [Ö]. | `goto out_free; … out_close: close(fd);` |

### 2.5 Vektörleme ve sabitlerin kodlanması

| Kalıp | Makine kodundaki işaret | Ghidra'daki görünüm | Kaynaktaki karşılık |
|---|---|---|---|
| **Vektörlenmiş döngü** | arm64: yineleme başına 16 eleman (4 q yazmacı, `ldp q0,q1` / `add.4s`), ardından 4'lük vektör epilogu (`tst x8,#0xc`), ardından skaler kalan [Ö]. Yineleme sayısı maskesi `and x9,x8,#0x7ffffff0` [Ö]. x86: `movdqu/paddd`, 8 eleman, skaler kalan [Ö]. | 1 satırlık `vsum` döngüsü arm64 -O2'de **116**, x86 -O2'de 57 satır oldu. `crc32_make_table` 23 → **392** satır, yüzlerce `auVar [16]` değişkeniyle [Ö]. | Tek basit döngü. Tarif katmanı ana, epilog ve kalan döngüsünü **tek döngüye** indirgemeli. |
| **Vektör indirgeme** | Tamsayı toplamda 4 akümülatör + `addv.4s` [Ö]. `float` nokta çarpımında (fast-math yok) çarpma vektörlendi (`fmul.4s`) ama toplama sırayla skaler `fadd` ile yapıldı [Ö]. | Uzun ve okunmaz | `s += a[i]` / `s += a[i]*b[i]`. Sıralı `fadd`, FP katılığının kanıtı. |
| **Sabit havuzu** | `md5_init`'in dört 32 bitlik sabiti -O2'de 16 baytlık tek literal oldu: `ldr q0, [x8,#0x6a0]` / `movaps` [Ö]. | `uVar1 = _DAT_1000016a0; param_1[1] = _UNK_1000016a8;` Sabitler **metinde yok** [Ö]. | `st[0] = 0x67452301; …` |
| **arm64 sabit bölme** | 32 bit sabit iki komuta bölünür: `mov w8,#0x79b9; movk w8,#0x9e37,lsl #16` [Ö]. x86'da komut içinde `imm32` olarak durur. | Ghidra birleştiriyor, ama işaretli tipte gösteriyor: `-0x61c88647` [Ö]. | `delta = 0x9E3779B9`. `.text`'te bayt deseni araması arm64'te bu yüzden sonuç vermez. |

---

## 3. Kanıt kataloğu

| Kanıt türü | Güvenilirlik | Derleyici etkisi | Tarif için kullanım |
|---|---|---|---|
| **Dış API çağrısı (dinamik bağlı)** | **Yüksek.** Import adı derleyiciden ve strip'ten sağ çıkar. Yanıltma yolları: sarmalayıcı (wrapper) fonksiyonlar, kütüphanenin kendi iç çağrıları. | Libc çağrıları **satır içine alınabilir** (sabit `strlen` katlanır, küçük `memcpy` vektöre döner) [Ö]. **Tersine de üretilebilir:** döngü → `bzero/memcpy/strlen` [Ö]. FORTIFY adı değiştirir (`___strcpy_chk`) [Ö]. Statik bağlamada import kalmaz; gövde tanınmalı (§4). LTO sınırları kaldırır, sarmalayıcıları eritir [B]. | Fiilin ana kaynağı. Ad normalize edilir: `___X_chk`/`__X_chk` → `X`, `__open_2` → `open`, `_bzero` → "sıfırla". |
| **API argümanları (sabit bayrak, sabit tür)** | **Yüksek**, yeter ki argüman konumuna bağlansın ve OS'e göre çözülsün. capa'nın yaptığı gibi temel blokta sayı aramak bağlamsızdır. | Sabitler korunur. Ama **OS'e özgü**: `O_CREAT` Darwin `0x200` / Linux `0x40`; `O_CLOEXEC` `0x1000000` / `0x80000`; `AF_INET6` Darwin `30`, Linux'ta `10` [Ö][L][B: Linux AF_INET6]. Darwin arm64'te değişken argümanlar yığından geçer, Ghidra onları göstermez [Ö]. | Nesneyi ve kipini verir: okuma/yazma/oluşturma, TCP/UDP, IPv4/IPv6. |
| **FORTIFY `_chk` varyantları** | **Çok yüksek.** Hem API adını hem **hedef tampon boyutunu** taşır (`0x40`) [Ö]. glibc `__printf_chk`'ye ek bir `flag` argümanı ekler, argüman sırası kayar [B]. | `-O1+` ve FORTIFY açıkken çıkar. Darwin'de `-O2` ile varsayılan [Ö]. Boyut bilinmiyorsa düz çağrı kalır (`snprintf` örneği) [Ö]. | Tip kurtarma: `char[N]`. Argüman konumu eşlemesi `_chk` imzasına göre düzeltilmeli. |
| **errno / strerror / perror** | **Yüksek** (hata yolu işareti). | Erişici OS'e göre değişir: `___error` (Darwin), `__errno_location` (glibc) [Ö]. | Fonksiyona ad vermez, ama "hata yolu" ve "POSIX tarzı -1 dönüşü" etiketini verir. Başarısız işlemin adı format string'inden alınır ("open %s: %s"). |
| **Kripto ve sihirli sabitler** | **Çok sabitli grup ve tam değer eşleşirse yüksek; tek sabit ya da alt-dize eşleşmesiyse düşük.** Bazı sabitler paylaşılır: MD4/MD5/SHA-1/RIPEMD aynı IV'leri kullanır, `0x9E3779B9` hash karıştırmada da geçer [B]. | -O2'de sabitler **sabit havuzuna** taşınır (`_DAT_`) [Ö]. arm64'te `movz/movk` ile bölünür [Ö]. Ghidra işaretli gösterir (`-0x61c88647`) [Ö]. Vektörleme sabiti vektör havuzuna koyar [Ö]. | Algoritma adı (`crc32_*`, `md5_init`) + yapısal doğrulama (§3.1). |
| **Derleyici ürünü sabitler** | **Kanıt değil, gürültü.** `0xCCCCCCCD`, `0x24924925`, `0x92492493`, `0x20C49BA5E353F7CF` bölme sihirli sayılarıdır [Ö]. `0x55555555 / 0x33333333 / 0x0F0F0F0F / 0x01010101` popcount maskeleridir [Ö]. | Derleyicinin kendisi üretir. | Dışlama listesine girer. Bölme sabiti → "x / k" (k, sihirli sayıdan geri hesaplanır). |
| **Bit maskesi (switch bit testi)** | **Orta-yüksek.** Maske karakter kümesine çözülebilir [Ö]. | -O2'de üretilir. -O0'da karşılaştırma zinciri olur [Ö]. | Küme → sınıf adı ("boşluk/ayraç", "rakam", "onaltılık"). |
| **Format string** | **Orta-yüksek.** `%d`/`%s` yapısı ve sözcükler amaç verir. Yanıltma: format bir log yardımcısına parametre olarak geçiyorsa string çağırana aittir. | Korunur. glibc FORTIFY altında `__printf_chk(1, fmt, …)` olur [B]. Darwin arm64'te argümanlar görünmez ama format görünür [Ö]. | Nesne adı ("deger=%d" → değer), işlem adı ("open %s" → aç). |
| **Hata ve log mesajları** | **Orta.** Çoğu zaman fonksiyonun kendi işini anlatır. Ama paylaşılan hata yardımcıları, makro ile çoğaltılmış mesajlar ve kopyala-yapıştır yanıltır. | Korunur. Birleştirilen (merge) özdeş literal'ler tek adrese iner, aynı string birden çok fonksiyonda görünür [B]. | Fiil ve nesne adayları. Tek başına isim vermez. |
| **Tek string'e güvenmek (tuzak)** | **Düşük.** Tek string hem yanlış fonksiyona (çağırana ait parametre) hem yanlış işe (yalnız hata mesajı) işaret edebilir. Aynı literal, inlining ile birçok fonksiyona kopyalanır [B]. | Inlining string referansını çağırana taşır. | Asgari kural: ≥2 bağımsız kanıt türü. String yalnız API veya veri akışıyla birlikte kullanılır. |
| **Çağıran ve çağrılan fonksiyonlar** | **Orta.** Yaprak (leaf) fonksiyon, dağıtıcı ve sarmalayıcı rolleri güvenilir. Çağıranın adından isim taşımak orta güvenlidir. | Inlining kenarları siler [L: Jia vd.]. Kuyruk çağrısı `call`'u `jmp`'e çevirir [Ö]. Tek sıçramalı fonksiyon thunk olur [Ö]. LTO çağrı grafını yeniden şekillendirir [B]. | Rol adları: `X_sarmalayici`, `dagitici`. API'ye geri çağrı (callback) olarak geçen fonksiyon rolünden isim alır (§8 K19). |
| **Veri akışı (API → API)** | **Çok yüksek.** `open`'ın dönüşü `read`/`close`'un arg0'ına giderse tesadüf olasılığı düşüktür. | -O2'de değer yazmaçta kalır, Ghidra'da akış temiz görünür [Ö]. Inlining akışı fonksiyon sınırları arasında birleştirir. | Bileşik fiiller: `read_file`, `tcp_connect`, `string_duplicate` (§8 K1, K3, K4). |
| **Döngü yapısı** | **Orta.** İç içe döngü sayısı, sabit tur sayısı (32 tur → TEA), indis adımı gibi bilgiler korunur. | Vektörleme tek döngüyü 3'e böler [Ö]. Deyim tanıma döngüyü çağrıya çevirir [Ö]. Açma (unroll) sabit turu gizler [B]. | Kanonikleştirme sonrası sayılır: "256 × 8 iç tur + xor" → CRC tablosu. |
| **Yığın tamponu boyutu** | **Yüksek** (`_chk` boyut argümanı, canary varlığı). | SSP yalnız dizi veya adres alınan yerel varsa eklenir (strong) [B]. | Tip: `char buf[N]`. N=4096 → yol/sayfa, N=256 → ad tamponu gibi zayıf ipuçları. |
| **Global veri tabloları** | **Yüksek** (256×4 baytlık CRC tablosu, S-box gibi tam tablolar). | Tablo `.rodata`/`__const`'ta bayt olarak durur. Kod yalnız `DAT_` referansıyla görünür [Ö]. | Bayt düzeyinde tarama (LE ve BE) + referans eden fonksiyon. |

### 3.1 Güvenilir sabit eşleme — Karadul `_scan_constants` teşhisi ve önerisi

**Ölçüm [Ö]:** Karadul'un `CAlgorithmIdentifier._scan_constants` fonksiyonu bu deneyin dört Ghidra çıktısında çalıştırıldı. Karadul'un fonksiyon ayıklayıcısı 167 gövde buldu; her yapıda 4 kripto benzeri fonksiyon var (`md5_init`, `crc32_make_table`, `crc32_buf`, `tea_encrypt`). Depoya yazılmadı, bytecode üretimi kapalıydı.

| Yapı | Sabit eşleşmesi | Doğru |
|---|---|---|
| arm64 -O0 | 6 | 0 |
| arm64 -O2 | 9 | 1 (CRC32) |
| x86-64 -O0 | 7 | 0 |
| x86-64 -O2 | 14 | 0 |

**Sahte pozitiflerin kaynağı** (`karadul/reconstruction/c_algorithm_id.py`):
1. **Alt-dize eşlemesi.** `hex_lower in body_lower` satırı tam değer değil metin parçası arıyor. `hex(0x0FFFFFFF)` = `0xfffffff`, `0xffffffff`'in içinde geçtiği için her `== -1` kontrolü "Poly1305" sayılıyor (`read_file_head`, `vadd`, `vsum`, `crc32_buf`). Kod örneği yapay bir gövdede de aynı sonucu verdi.
2. **Tek ve yaygın sabitli gruplar.** `Keccak/SHA-3` grubu `[0x1, 0x8082]`; gerekli eşleşme `max(1, 2//2) = 1`. `0x1` (veya ondalık `1`) hemen her gövdede geçiyor ve güven 0,7 çıkıyor. GOST S-box'ının küçük ondalıkları ve AES `rcon` (`0x1, 0x2, 0x4 …`) de aynı sorunu yaşıyor.
3. **Güven, grup oranından hesaplanıyor.** Tek grubu olan bir algoritmada tek eşleşme bile 0,7 veriyor.

**Gözden kaçanların kaynağı:**
4. **500 karakter filtresi.** -O0 `md5_init` (119 karakter, dört sabitin dördü de açık) ve -O0 `crc32_make_table` (açık `0xedb88320`) taranmadan atlanıyor.
5. **İşaretli gösterim.** TEA sabiti `0x9E3779B9` imza tablosunda var, ama Ghidra `-0x61c88647` yazdığı için bulunamıyor.
6. **Sabit havuzu ve vektör havuzu.** -O2 `md5_init` ve x86 -O2 CRC tablosu üreticisi `_DAT_…` referansına indirgeniyor.

**Önerilen yöntem** (metin aramasından değer kümesine):
1. **Sözcük birimine ayır, alt-dize arama.** Decompile metnindeki tamsayı literal'lerini bir sözcük çözücüyle çıkar: `(?<![\w.])-?(0x[0-9a-f]+|\d+)[uUlL]*(?![\w.])`. Her değeri hem 32 hem 64 bit ikiye tümleyen biçime normalize et (`-0x61c88647` → `0x9E3779B9`). Eşleme küme üyeliğiyle yapılır. Daha iyisi, metin yerine Ghidra P-code'undaki sabit varnode'ları okumaktır. arm64 `movz/movk` birleşimi orada zaten çözülmüştür.
2. **Veri bölümlerini tara.** `.rodata`, `__const`, `__literal16` baytlarında çok sabitli grupları (LE ve BE, 32 ve 64 bit) ara. Bulunan adresi referans eden fonksiyonlara kanıt olarak bağla (`_DAT_1000016a0` → MD5 IV). findcrypt ve signsrch türü araçlar bu yoldan çalışır [B].
3. **Seçicilik ağırlığı.** Her sabitin arka plan frekansını kripto içermeyen bir binary derleminde ölç. Ağırlığı bilgi içeriğiyle ver: `w = −log p`. `0, 1, 0xff, 0xffffffff`, 2'nin kuvvetleri, bölme sihirli sayıları ve popcount maskeleri ≈0 ağırlık alır. Karar, toplam bilgi eşiğine göre verilir; fonksiyon uzunluğu filtre olmaz.
4. **Grup bütünlüğü.** 32 bitlik "rastgele görünen" sabitlerde aynı gruptan en az 2–3 farklı değer, tablolarda en az 8 ardışık giriş şartı. Ortak IV'ler (MD4/MD5/SHA-1) aday listesi döndürür. Ayrım ek sabitle yapılır (SHA-1'in 5. IV'si `0xC3D2E1F0`, MD5'in tur sabitleri `0xD76AA478…`).
5. **Yapısal doğrulama.** Sabit kanıtı yalnız aday üretir. Güveni döngü yapısı yükseltir: tur sayısı (32/64/80), döndürme ve xor yoğunluğu, tablo erişim kalıbı (`T[(c ^ b) & 0xff] ^ (c >> 8)`). Gröbert vd. (RAID 2011) sabitleri girdi-çıktı doğrulamasıyla birleştirir [L].

---

## 4. Satır içine alınmış ve statik bağlanmış kütüphane kodunu tanıma

**Neden kritik?** Tarifin fiilleri büyük ölçüde API çağrılarından gelir. Üç yoldan bozulur:
- (a) Çağrı **satır içine alınır**. Fiil kaybolur, gövde "döngü + bayt karşılaştırma" gibi anlamsız bir tarif alır.
- (b) Libc **statik bağlanır**. Binary'de yüzlerce libc fonksiyonu kullanıcı kodu gibi durur. Bunlar tarif değil **kesin ad** almalı; aksi hâlde hem yanlış ad verilir hem de çağıranlar API kanıtını kaybeder.
- (c) Derleyici kaynakta olmayan çağrılar **üretir** (`bzero`, `memcpy`, `strlen`) [Ö]. Bu tarif için zararsız, hatta yararlıdır; ama "yazar libc kullanmış" çıkarımı yanlış olur.

**Tanıma yöntemleri:**

| Durum | Tanıma | Not |
|---|---|---|
| Satır içi küçük `memcpy`/`memset` | Aynı tabandan ardışık vektör yükleme ve saklama çiftleri; sıfır yazmacından ardışık saklamalar (`movi v0,#0; stp q0,q0`) [Ö]. | Ghidra alan atamalarına çevirir. Tarif katmanı "N bayt kopyala/sıfırla" diye kanonikleştirir. |
| Sabit argümanlı `strlen` | Kanıt tamamen kaybolur (`return 7`) [Ö]. | Kurtarılamaz; bilgi kaybı sınırı. |
| Kelime-kelime `strlen`/`strchr` (libc iç gövdesi) | `0x0101010101010101` ve `0x8080808080808080` maskeleri: `(x − ONES) & ~x & HIGHS` sıfır bayt testi. musl'ın `strlen.c` dosyası bu `HASZERO` makrosunu kullanır [B]. | Statik bağlı libc gövdesinin parmak izi. |
| Döngü → çağrı deyimi | -O2 Darwin'de `bzero/memcpy/strlen` kuyruk çağrısı + önünde sınır kontrolü [Ö]. | Fiil eşdeğerlik tablosu: {döngü sıfırlama, `memset(…,0,…)`, `bzero`} → "sıfırla". |
| Statik libc, sistem çağrısı sarmalayıcıları | `mov eax, NR; syscall` (x86-64), `svc #0` + `x8 = NR` (AArch64 Linux) [B]. Darwin `svc #0x80` + `x16`. | Sistem çağrısı numarası → kesin ad (`read`, `openat`). Jacobson vd. (PASTE 2011) "anlamsal betimleyici" yaklaşımı tam olarak bunu sürümden bağımsız kullanır [L]. |
| Statik libc, genel fonksiyonlar | FLIRT (IDA; bayt deseni + yer değiştirme maskesi) [B]. Ghidra FunctionID (maskeli komut hash'leri) [B]. BSim (P-code özellik vektörleri) [B]. | Yerel Ghidra 12.1.2'deki FunctionID veritabanları **yalnız Visual Studio 2012–2019** için (`vs20xx_x64/x86.fidbf`) [Ö]. glibc, musl ve Darwin için FID veritabanını Karadul kendisi kurmalı. Libc sürümüne göre seçilmeli (§5). |
| Kullanıcı kodunda inlining | Inlining, -O2/-O3'te birikimli olarak artar. Jia vd. bazı ayarlarda oranın %70'e yaklaştığını raporluyor [L]. | Inlining tespiti tarif güvenini düşürür: büyük, çok-API'li gövde "birleşik" tarif alır. |

**Sonuç:** Tarif katmanının sırası şöyle olmalı: **(1)** kütüphane gövdesini tanı ve kesin ad ver (FID/FLIRT/syscall) → **(2)** satır içi kalıpları ve deyimleri kanonikleştir (vektör epilogu, `memcpy` çiftleri, bölme) → **(3)** kalan kullanıcı koduna tarif uygula.

---

## 5. Derleyici kökeni (compiler provenance)

**Literatür (künyeleri doğrulandı):**
- Rosenblum, Miller, Zhu. *Extracting Compiler Provenance from Program Binaries*, PASTE 2010. Yalnız derleyiciyi tanır [L].
- Rosenblum, Miller, Zhu. *Recovering the Toolchain Provenance of Binary Code*, ISSTA 2011, s. 100–110, "Distinguished Paper". Kökeni sınıflandırma problemi olarak ele alır (kaynak dili, derleyici, sürüm, seçenekler). Bazı bileşenlerde ≈%100, birbirine benzeyen çıktılarda ≈%90 doğruluk raporlar [L].
- Rosenblum, doktora tezi (Wisconsin, 2011) [L].
- Rahimian, Shirani, Alrabaee, Wang, Debbabi. *BinComp: A stratified approach to compiler provenance attribution*, Digital Investigation 14 (S1), S146–S155, DFRWS USA 2015. Üç katmanlı yapı; derleyici ailesi, sürümü ve optimizasyon düzeyi [L].
- Pizzolotto, Inoue. *Identifying Compiler and Optimization Level in Binary Code from Multiple Architectures*, IEEE Access 9, 2021 (öncülü ICSME 2020). 7 mimari, -O0…-Os. GCC/Clang ayrımı yalnız x86-64 ve AArch64'te; derleyicide >%99,95, -O düzeyinde %92–98 [L].
- Otsubo, Otsuka, Mimura. *Compiler Provenance Recovery for Multi-CPU Architectures Using a Centrifuge Mechanism*, arXiv 2211.13110, 2022. Aynı gruptan *o-glassesX* (BAR 2020) [L; o-glassesX'in yazar listesi bu oturumda doğrulanmadı].

**Karadul için deterministik sinyaller (öğrenmesiz):**

| Sinyal | Ne verir | Durum |
|---|---|---|
| ELF `.comment` ("GCC: (Debian …) 12.2.0", "clang version …") | Derleyici ve sürüm | [B], GCC/ELF ajanının alanı |
| Mach-O `LC_BUILD_VERSION` | Platform, minos, SDK ve **ld sürümü**. Deney binary'si: `platform macos, sdk 27.0, minos 13.0, tool ld 27037.1`. clang sürüm dizgisi binary'de yok [Ö]. | Mach-O'da derleyici sürümü dolaylıdır. |
| Go buildinfo, Rust `/rustc/<hash>/` yolları | Dil ve araç zinciri sürümü | [B] |
| -O0 izleri | Her değişken yığına dökülür (`str w0,[sp,#8]; ldr w8,[sp,#8]`). Kuyruk çağrısı yok, `csel/cmov` yok. arm64'te switch karşılaştırma zinciri olur [Ö]. | Basit karar kuralı yeter. |
| -O2 izleri | `csel/cmov`, bölme sihirli sayıları, vektör epilogları, kuyruk çağrıları, deyim çağrıları (`bzero`) [Ö]. | |
| Hizalama dolgusu | Clang x86 `nopw %cs:(%rax,%rax)` [Ö]. GCC'nin farklı NOP dizileri [B]. | Klasik köken özelliği |
| OS/libc imzası | `___stack_chk_guard` (GOT) ile `%fs:0x28`; `___error` ile `__errno_location`; `___memcpy_chk` ile `__memcpy_chk` [Ö]. | Bayrak tablosunu seçer |

**Karadul nasıl kullanır?**
1. **Kural seti seçimi.** Profil = (OS/libc, mimari, derleyici, -O düzeyi). Bu profil şunları seçer:
   - bayrak sabit tablosu (Darwin ile Linux `open`, `socket` değerleri),
   - errno erişici adı,
   - FORTIFY ad ve argüman eşlemesi,
   - switch eşikleri (x86-64'te 4, AArch64'te 10 vaka [Ö]),
   - deyim kümesi (Darwin'de `bzero`),
   - FID/FLIRT veritabanı.
2. **Güven kalibrasyonu.** -O0'da API çağrısının **yokluğu** da kanıttır (inlining yok). -O2/LTO'da yokluk kanıt sayılmaz, ağırlığı düşürülür.
3. **İmza veritabanı seçiciliği.** Libc sürümü `.comment`, sürüm dizgileri ve build-id'den çıkarılırsa yanlış sürümün imzaları elenir. Bu, hafızadaki "imza DB'si seçici değil" bulgusuna doğrudan çözüm adayı.
4. **Makale ölçümü.** İsabet köken profili başına raporlanmalı. -O0 ile -O2 farkı ve x86-64 ile arm64 farkı ayrı satırlarda gösterilmeli.

---

## 6. capa'dan alınacaklar

**Kural formatı [L]:**
- YAML'de `rule: {meta, features}`.
- `meta` alanları: `name`, `namespace`, `authors`, `scopes`, `att&ck`, `mbc`, `references`, `examples` (zorunlu), `lib`.
  - `scopes` statikte `instruction / basic block / function / file`, dinamikte `call / span of calls / thread / process / file` değerlerini alır.
- Özellikler:
  - `api`, `number`, `string` (ve `/regex/`), `substring`, `bytes`, `offset`, `mnemonic`, `operand[N].number/offset`,
  - `characteristic` (`loop`, `tight loop`, `nzxor`, `stack string`, `calls from/to`, `recursive call`, `indirect call` …),
  - `match` (başka kurala atıf), `os/arch/format`, `import/export/section`, `function-name`.
- Mantık: `and`, `or`, `not`, `optional`, `N or more`, `count(…)`.
- Sayılar işaretsiz yazılır; negatifler ikiye tümleyen biçimindedir.

**Örnek kural, `create TCP socket` [L]:** kapsam `basic block`. Koşul: `api: socket` ∧ `number: 2` (AF_INET) ∧ `number: 1` (SOCK_STREAM) ∧ (`number: 0` ∨ `number: 6`). **Zayıflık:** sayılar argüman konumuna bağlanmıyor. Aynı temel blokta tesadüfen 1 ve 2 geçmesi yetiyor. Karadul'un veri akışı bu konuda capa'dan güçlü olabilir.

**Kapsama [Ö][L]:**
- capa PE, ELF, .NET, shellcode ve sandbox raporlarını okur. **Mach-O'yu okumaz:** capa 9.4.0 deney binary'sini "girdi türü bilinmiyor" hatasıyla reddetti.
- AArch64 yalnız Ghidra BinExport2 arka ucuyla destekleniyor (v7.3.0, Android hedefli).
- Yerel kural seti (`~/.cache/karadul/capa-rules`): 1045 kural; 387'si `nursery` ("tam cilalanmamış"). `os: linux` 60 dosyada, `os: macos` **1** dosyada geçiyor. Kuralların büyük kısmı Windows API adlarına dayanıyor.

**Karadul'daki mevcut kullanım [Ö]:**
- Dosyalar: `karadul/analyzers/capa_scanner.py` (CLI, `-j` JSON), `karadul/pipeline/steps/capa_annotation.py`, `_capa_comment_inject.py`, `stages.py::_apply_capa_naming`.
- Yetenek adları fonksiyon adına iki kaynaktan çevriliyor: `_CAPABILITY_NAME_MAP` ve `resources/capa_name_map.json` (87 girdi).
- Ayarlar: `enable_capa=True`; güven `capa_capability: 0.85`.
- Değerlendirme:
  - Mac binary'lerinde capa **hiç katkı vermez**.
  - Linux x86-64'te verir.
  - 0,85 güven, bağlamsız sayı eşleşmesi ve `nursery` kuralları düşünülünce yüksek. `nursery` dışlanmalı ya da güveni düşürülmeli.

**Alınacaklar:**
1. **Format iskeleti.** Bildirimsel YAML, mantık ağacı, kapsam hiyerarşisi, `match` ile bileşim, `lib` yapı taşı kuralları.
2. **Her kuralın zorunlu `examples` alanı.** Örnek `<sample>:<offset>` biçiminde. Bu, kural başına test derlemi demek; Karadul'un mutation/regresyon disipliniyle birebir uyumlu. Linter ile metaveri denetimi de buna eklenir.
3. **Fiil taksonomisi.** MBC/ATT&CK isim alanları tarif fiilleri için hazır sözlük: `host-interaction/file-system/read`, `communication/socket/tcp`, `data-manipulation/hashing/md5` …
4. **`characteristic` özellikleri.** `nzxor` (sıfır olmayan xor), `tight loop`, `stack string` doğrudan tarif özelliği olur.
5. **Karadul'un ekleyeceği** (capa'da yok):
   - argüman konumu ve veri akışı bağı (`arg0 ← open.dönüş`),
   - OS'e göre sembolik sabitler (`O_CREAT` adıyla yazılır, profil sayıya çevirir),
   - negatif kanıt,
   - derleyici kökeni koşulu,
   - güvenin ölçülmüş isabetten türetilmesi.

Önerilen tarif kuralı biçimi (taslak):
```yaml
recipe:
  name: read_file            # verb_object
  verb: read
  object: file
  scope: function
  profile: {os: [linux, macos]}
  features:
    - all:
      - call: {api: [open, openat, __open_2], flags: {arg1: O_RDONLY}}
      - call: {api: [read, __read_chk], arg0: {flow: open.ret}}
      - call: {api: close, arg0: {flow: open.ret}}
  confidence_source: measured_precision   # geliştirme setinde ölçülür
  examples: ["tmux:0x41a2c0"]             # örnek biçim; adres temsilîdir
```

---

## 7. Deney kayıtları

**Ortam:** macOS (Darwin 25.6.0, Apple Silicon); Apple clang 21.0.0 (clang-2100.3.34.2); Apple `objdump` (LLVM); Ghidra 12.1.2 (`~/Library/BlackWidowBuild/ghidra_12.1.2_PUBLIC`), headless; JDK 21; capa 9.4.0.
**Klasör:** `…/scratchpad/makale/derleyici/deney_kalip/`. Yeniden üretme: `bash calistir.sh`.

| Dosya | İçerik |
|---|---|
| `kaliplar.c` | 42 fonksiyon: switch (3), bölme (5), seçim ve bit (7), bellek/dizgi ve deyim (9), struct ve varargs (4), SSP/FORTIFY (3), hata yolu (1), kuyruk çağrısı (3), vektör (3), kripto sabiti (4) + `main` |
| `k2.c` | 7 vakalı switch (gerçek dış çağrılar), canary, `__errno_location`. 4 hedef için nesne dosyası. |
| `k3.c`, `bin/jt_N.c` | N vakalı switch (N = 4…11, 8, 12, 16) ile atlama tablosu eşiği |
| `bin/k_{arm64,x86_64}_{O0,O2}` | Mach-O çalıştırılabilirler; ayrıca `k_arm64_O2_nofortify`, `k_arm64_O2_nossp` |
| `asm/*.s`, `asm/*.ann.s` | Disassembly; `.ann.s` stub adresleri sembol adıyla işaretli (`annot.py`) |
| `decomp/*.decomp.c` | Ghidra decompile çıktısı (`ghidra_scripts/DumpDecomp.java`) |
| `fn.sh`, `annot.py`, `calistir.sh` | Yardımcı betikler |

**Ana bulgular (hepsi [Ö]):**
1. **Switch.**
   - Sabit döndüren 8 vakalı switch, -O2'de iki mimaride de **veri arama tablosuna** dönüştü (atlama tablosu değil).
   - -O0 x86-64'te gerçek atlama tablosu oluştu ve Ghidra `switch`'i geri getirdi. -O0 arm64'te karşılaştırma zinciri oluştu.
   - Dış çağrılı switch'te atlama tablosu x86-64'te 4 vakada, AArch64'te 10 vakada başlıyor (9'da yok). Darwin arm64 tablosu 1 baytlık sıkıştırılmış girişler kullanıyor.
2. **Bölme.** Ghidra işaretli ve işaretsiz sabit bölmeyi ve modu geri katlıyor (`/ 7`, `% 10`). İşaretli 2'nin kuvvetine bölmeyi katlamıyor.
3. **Deyim tanıma (arm64 ve x86-64 Darwin -O2).**
   - Sıfırlama döngüsü ve `memset(p,0,n)` → `bzero` (arm64) / `__bzero` (x86-64); kopyalama döngüsü → `memcpy`; `while(*p)p++` → `strlen` (iki mimaride de); popcount döngüsü → `cnt.8b` (yalnız arm64).
   - `strcmp`/`strncmp` sabitle çağrı olarak kaldı. `strlen("karadul")` → `7` oldu.
4. **Thunk.** Tek `b _strlen` / `b _bzero` komutundan oluşan fonksiyonları (`loop_strlen`, `zero_n`) Ghidra thunk olarak sınıflandırdı.
5. **FORTIFY ve SSP.**
   - Darwin -O2'de FORTIFY=2 ve SSP varsayılan olarak açık.
   - `___strcpy_chk(buf, src, 0x40)` ve `___memcpy_chk(tmp, src, n, 0x20)` tampon boyutunu taşıyor.
   - Canary: Darwin'de GOT `___stack_chk_guard`; Linux x86-64'te `%fs:0x28`; Linux AArch64'te GOT `__stack_chk_guard`.
6. **Hata yolu.**
   - `open` bayrağı Darwin'de `0x1000000` (`O_RDONLY|O_CLOEXEC`).
   - `fd<0` → `tbnz w0,#31`; errno yazımı `*___error() = 5`.
   - Ghidra `goto cleanup`'ı iç içe `if/else`'e çevirdi.
   - Darwin arm64'te `fprintf`'in değişken argümanları Ghidra çıktısında görünmüyor.
7. **Vektörleme.**
   - Decompile satır sayısı: `vsum` 12 → 116 (arm64) / 57 (x86); `vadd` 11 → 125 / 73; `crc32_make_table` 23 → 392 / 123.
   - `vdot` (float) çarpımı vektörledi ama toplamayı sıralı tuttu.
8. **Sabitler.**
   - MD5 IV -O2'de 16 baytlık literal havuzuna gitti, Ghidra'da `_DAT_` olarak görünüyor.
   - TEA `0x9E3779B9` arm64'te `movz/movk` ile bölündü; Ghidra iki mimaride de `-0x61c88647` gösterdi.
   - `__builtin_popcount` x86-64 tabanında 4 maske sabiti üretti.
9. **Karadul sabit tarayıcısı.** 167 fonksiyonda 36 eşleşme, 1 doğru (§3.1). Ölçüm, depo kodu bytecode üretimi kapalı olarak içe aktarılarak yapıldı; depoya yazılmadı.
10. **capa.** capa 9.4.0, x86_64 Mach-O deney binary'sini reddetti. Yerel kural sayıları §6'da.
11. **Mach-O kökeni.** `LC_BUILD_VERSION` yalnız platform, SDK, minos ve ld sürümünü veriyor; clang sürüm dizgisi yok.

**Sınırlar.**
- GCC ölçülmedi; Mac'te yok ve GCC ajanının alanı.
- Linux hedefleri yalnız nesne dosyası olarak derlendi (glibc başlıkları olmadığı için FORTIFY ölçülmedi).
- Tek derleyici sürümü kullanıldı.
- Binary'ler strip edilmedi; Ghidra görünümü sembol adlarıyla alındı. Strip, gövdeyi değil yalnız adları etkiler.

---

## 8. Tarif katmanı için somut kural önerileri

Biçim: **kanıt → fiil_nesne** · *güven gerekçesi*.
- Üretilen adlar kod sembolü olduğu için İngilizce (Karadul'un mevcut çıktısıyla uyumlu: `aes_encrypt`); açıklamalar Türkçe.
- "Güven" etiketleri başlangıç sırasıdır. Makalede her kuralın isabeti geliştirme setinde ölçülmeli (dondurulmuş test seti ilkesi).

1. **K1.** `open/openat/__open_2` (salt-okuma bayrağı, profile göre çözülür) + `read/__read_chk` (arg0 ← open.dönüş) + `close` (aynı fd) → **`read_file`** (dosya oku). *Yüksek: üç API ve iki veri akışı kenarı var, tesadüfi birliktelik olasılığı çok düşük. FORTIFY varyantları eşdeğer sayılır.*
2. **K2.** `open(…, O_WRONLY|O_CREAT|O_TRUNC)` (Darwin `0x601`, Linux `0x241`) + `write` (aynı fd) → **`write_file`**; `O_APPEND` varsa **`append_to_file`**. *Yüksek: bayrak argüman konumuna bağlı. Değerler OS'e göre farklı olduğu için profil zorunlu.*
3. **K3.** `socket(AF_INET|AF_INET6, SOCK_STREAM, 0|6)` + `connect` (arg0 ← socket.dönüş) → **`tcp_connect`**. `bind` + `listen` + `accept` → **`tcp_listen`**. `SOCK_DGRAM` + `sendto/recvfrom` → **`udp_send` / `udp_receive`**. *Yüksek: capa'nın kuralından güçlü, çünkü sayılar argüman konumuna, soket fd'si akışa bağlı. AF_INET6 değeri OS'e özgü.*
4. **K4.** `strlen(s)` → `malloc(n+1)` (akış) → `memcpy/strcpy` (hedef ← malloc.dönüş) → dönüş = malloc.dönüş → **`string_duplicate`** (strdup benzeri). *Yüksek: dört adımlı akış zinciri. `strlen` inline olsa bile `malloc(+1)` ve kopya kalır.*
5. **K5.** `malloc` + `NULL` kontrolü + hata dalında `-1/NULL` dönüşü → **hata yolu etiketi** (isim değil, yapı bilgisi). *Orta: çok yaygın, ama ad olarak değil yapı bilgisi olarak güvenilir.*
6. **K6.** `fprintf(stderr, "<op> %s: %s\n", …, strerror(errno))` veya `perror("<op>")` → çağıran fonksiyon `<op>` işlemini yapıyor; hata dalı **`report_<op>_error`**. *Orta-yüksek: format'ın ilk sözcüğü çoğu zaman başarısız API'nin adı ("open %s"). Tek string kuralına tabi: aynı fonksiyonda o API'nin çağrısı da olmalı.*
7. **K7.** Bit testi switch: `x < K ∧ ((1 << x) & M) ≠ 0` → maskeyi karakter kümesine çöz. Küme ⊆ {`\t\n\v\f\r`, boşluk, noktalama} → **`is_separator`** / **`is_space`**. Küme = {'0'…'9'} → **`is_digit`**. *Orta-yüksek: maske deterministik çözülür [Ö]. Küme standart bir sınıfla tam örtüşürse yüksek.*
8. **K8.** Döngüde `x % 10` ve `x / 10` (Ghidra katlamış ya da sihirli `0xCCCCCCCD`) + `'0' +` + tampona geriye doğru yazma → **`int_to_string`** (itoa). `/16` + `"0123456789abcdef"` tablosu → **`int_to_hex`**. *Orta-yüksek: üç bağımsız işaret var (bölme, ASCII ofseti, tampon yazımı).*
9. **K9.** Sabit `0xEDB88320` (veya `0x04C11DB7`) + 8 turluk iç döngü + `>> 1` + koşullu xor → **`crc32_make_table`**. 256 girişli tablo erişimi `T[(c ^ b) & 0xff] ^ (c >> 8)` + başta ve sonda `~` / `0xFFFFFFFF` → **`crc32_update`**. *Yüksek: nadir sabit + yapı. Sabit havuzdaysa veri bölümü taramasıyla bağlanır.*
10. **K10.** Dört IV'nin dördü de (`0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476`; işaretli, `_DAT_` ve havuz biçimleri normalize edilmiş) → **`hash_init`**. Aday listesi: MD5/MD4/SHA-1/RIPEMD. 5. IV `0xC3D2E1F0` → **`sha1_init`**. MD5 tur sabitleri `0xD76AA478…` → **`md5_transform`**. *Yüksek, ama IV'ler paylaşıldığı için tek aday ancak ek sabitle verilir. Fonksiyon uzunluğu filtresi uygulanmaz.*
11. **K11.** `0x9E3779B9` (= `-0x61C88647`) + sabit 32 tur + `<<4`, `>>5`, xor → **`tea_encrypt`** (sum azalıyorsa `tea_decrypt`; `>>11 & 3` anahtar indeksi varsa `xtea_*`). Sabit tek başına → yalnız "altın oran karıştırması". *Yapıyla yüksek, tek sabitle düşük: Fibonacci hashing de bu sabiti kullanır [B].*
12. **K12.** `*___error() = K` / `*__errno_location() = K` + `return -1` → fonksiyon POSIX tarzı hata sözleşmesine uyuyor (sistem çağrısı sarmalayıcı adayı). K errno tablosundan adlandırılır (Darwin ve Linux'ta `EIO = 5`). *Orta: sarmalayıcı rolü güvenilir, fiil başka kanıttan gelir.*
13. **K13.** Gövde tek `bzero/memset(p, 0, n)` (önünde sınır kontrolü olabilir) veya eşdeğer sıfırlama döngüsü → **`zero_buffer`**. Tek `memcpy` → **`copy_buffer`**. Tek kuyruk sıçraması → **callee adı** (sarmalayıcı). *Yüksek: derleyici döngü ile çağrıyı birbirine çeviriyor [Ö], ikisi aynı fiile eşlenir.*
14. **K14.** `strcmp/strncmp(arg, "LITERAL_i")` zinciri, her dalda farklı çağrı → **`dispatch_command`**. Literaller {"GET","POST","HEAD"} → **`parse_http_method`**; {"-h","--help"} → **`parse_options`**. *Orta-yüksek: literal kümesi alanı adlandırır. Clang -O2'de `strcmp` çağrısı korunuyor [Ö].*
15. **K15.** Atlama tablosu (veya ≥4 vakalı karşılaştırma ağacı) + switch değişkeni bir struct alanından ya da bayt okumasından (`*p`, `msg->type`) + her vakada farklı işleyici → **`dispatch_by_type`** / **`dispatch_opcode`**. *Orta: dağıtıcı rolü güvenilir, nesne adı ek kanıt ister. AArch64'te 10 vakadan küçük switch tablo üretmediği için ağaç da kabul edilmeli [Ö].*
16. **K16.** `pthread_mutex_lock(m)` … `pthread_mutex_unlock(m)` (aynı nesne, tüm çıkış yollarında) → gövdenin tarifine **`locked_`** öneki; tek işlem varsa `locked_<op>`. *Orta: kilit eşleşmesi güvenilir, asıl fiil içerideki işlemden gelir.*
17. **K17.** `fopen(path, "r")` + `fgets/getline` döngüsü + `strtok/strchr('=')/sscanf` → **`parse_config_file`**. `"w"` + `fprintf` döngüsü → **`write_report_file`**. *Orta: kip literal'i, döngü ve ayrıştırıcı çağrı birlikte.*
18. **K18.** `getenv("NAME")` (literal argüman) → **`get_NAME_env`**; dönüş `NULL` ise varsayılana düşüyorsa **`get_NAME_or_default`**. *Yüksek: literal argüman doğrudan nesne adı.*
19. **K19.** Geri çağrı rolü:
   - `qsort/bsearch` 4./5. argümanındaki fonksiyon → **`compare_*`**,
   - `pthread_create` 3. argüman → **`thread_main`**,
   - `signal/sigaction(SIGx, h)` → **`handle_SIGx`**,
   - `atexit(f)` → **`cleanup_at_exit`**.

   *Yüksek: API sözleşmesi rolü kesin tanımlar ve çağrılan tarafın gövdesine bakmadan ad verir. Sinyal numaraları profile göre çözülür.*
20. **K20.** `___X_chk(dst, …, N)` / `__X_chk(…, N)` ve dst yığın adresi → **tip**: `char dst[N]` (isim değil). N ∈ {256, 1024, 4096, PATH_MAX} → zayıf nesne ipucu ("yol", "ad"). *Tip için çok yüksek: N, derleyicinin `__builtin_object_size` sonucudur [L][Ö].*
21. **K21 (kanonikleştirme).** Ana vektör döngüsü + vektör epilogu + skaler kalan (aynı yükleme ve saklama akışı) → **tek döngü** kabul et, sonra tarif uygula:
   - `a[i] = b[i] + c[i]` → **`add_arrays`**,
   - `s += a[i]` (`addv` indirgemesi) → **`sum_array`**,
   - `s += a[i]*b[i]` → **`dot_product`**.

   *Orta: kanonikleştirme deterministik, fiil vektör komut türünden (`add.4s`, `fmul.4s`) gelir. 116 satırlık gürültü tek satıra iner [Ö].*
22. **K22 (dışlama kuralı).** Bölme sihirli sayıları, popcount maskeleri, `0/1/0xff/0xffffffff`, 2'nin kuvvetleri ve tek başına string → **hiçbir tarif tetiklemez**. *Zorunlu: §3.1 ölçümündeki 35 sahte eşleşmenin büyük kısmını bu kural keser.*

---

## 9. Kaynakça

Makale ve kitaplar
- T. Granlund, P. L. Montgomery. *Division by Invariant Integers using Multiplication*. PLDI 1994; ACM SIGPLAN Notices 29(6), 61–72. https://gmplib.org/~tege/divcnst-pldi94.pdf
- N. Rosenblum, B. P. Miller, X. Zhu. *Extracting Compiler Provenance from Program Binaries*. PASTE 2010. https://ftp1.cs.wisc.edu/par-distr-sys/papers/Rosenblum10prov.pdf
- N. Rosenblum, B. P. Miller, X. Zhu. *Recovering the Toolchain Provenance of Binary Code*. ISSTA 2011, 100–110. https://ftp1.cs.wisc.edu/par-distr-sys/papers/Rosenblum11Toolchain.pdf · Program: https://issta11.unl.edu/program/analysis-of-systems-and-binary-code/index.html
- N. Rosenblum. Doktora tezi, University of Wisconsin–Madison, 2011. https://ftp.cs.wisc.edu/paradyn/papers/Rosenblum11Dissertation.pdf
- E. R. Jacobson, N. Rosenblum, B. P. Miller. *Labeling Library Functions in Stripped Binaries*. PASTE 2011, 1–8. https://ftp1.cs.wisc.edu/par-distr-sys/papers/Jacobson11Unstrip.pdf
- A. Rahimian, P. Shirani, S. Alrabaee, L. Wang, M. Debbabi. *BinComp: A stratified approach to compiler provenance attribution*. Digital Investigation 14 (S1), S146–S155, 2015 (DFRWS USA). Yazar sırası DBLP'ye göre; DFRWS sayfasında farklı. https://dfrws.org/?p=752
- D. Pizzolotto, K. Inoue. *Identifying Compiler and Optimization Level in Binary Code from Multiple Architectures*. IEEE Access 9, 163461–163475, 2021. doi:10.1109/ACCESS.2021.3132950 · https://doaj.org/article/769db319aff24187ace676b9f2fa4f09
- Y. Otsubo, A. Otsuka, M. Mimura. *Compiler Provenance Recovery for Multi-CPU Architectures Using a Centrifuge Mechanism*. arXiv:2211.13110, 2022. https://arxiv.org/abs/2211.13110
- *o-glassesX: Compiler Provenance Recovery with …* BAR 2020 (NDSS). https://www.ndss-symposium.org/wp-content/uploads/2020/04/bar2020-23001-paper.pdf (yazar listesi bu oturumda doğrulanmadı)
- A. Jia vd. *1-to-1 or 1-to-n? Investigating the effect of function inlining on binary similarity analysis*. arXiv:2112.12928. https://arxiv.org/abs/2112.12928
- F. Gröbert, C. Willems, T. Holz. *Automated Identification of Cryptographic Primitives in Binary Programs*. RAID 2011, LNCS, 41–60. doi:10.1007/978-3-642-23644-0_3
- C. Meijer vd. *Where's Crypto?: Automated Identification and Classification of Proprietary Cryptographic Primitives in Binary Code*. USENIX Security 2021. https://www.usenix.org/conference/usenixsecurity21/presentation/meijer (tam yazar listesi bu oturumda doğrulanmadı)

Belgeler ve kaynak kodu
- capa: https://github.com/mandiant/capa · v7.3.0 sürüm notu (BinExport2, AArch64): https://github.com/mandiant/capa/releases/tag/v7.3.0
- capa kural formatı: https://github.com/mandiant/capa-rules/blob/master/doc/format.md · Kural deposu: https://github.com/mandiant/capa-rules · Örnek: https://github.com/mandiant/capa-rules/blob/master/communication/socket/tcp/create-tcp-socket.yml
- LLVM LoopIdiomRecognize strlen/wcslen tanıma (commit 9694844d, 2025): https://github.com/llvm/llvm-project/commit/9694844d7e36fd5e01011ab56b64f27b867aa72d · Kaynak: https://llvm.org/doxygen/LoopIdiomRecognize_8cpp_source.html
- glibc kılavuzu, Source Fortification: https://sourceware.org/glibc/manual/latest/html_node/Source-Fortification.html
- Linux `include/uapi/asm-generic/fcntl.h`: https://github.com/torvalds/linux/blob/master/include/uapi/asm-generic/fcntl.h
- Apple, *Writing ARM64 code for Apple platforms*: https://developer.apple.com/documentation/xcode/writing-arm64-code-for-apple-platforms
- macOS SDK başlıkları (yerelde okundu): `MacOSX.sdk/usr/include/sys/fcntl.h`, `sys/socket.h`
- Ghidra FunctionID modülü (yerel kurulumda `Ghidra/Features/FunctionID/data`): https://github.com/NationalSecurityAgency/ghidra/tree/master/Ghidra/Features/FunctionID

Bu oturumda doğrulanmadı, [B] işaretli iddiaların dayanağı
- System V AMD64 psABI (`%al` vektör yazmacı sayısı, `va_list` düzeni): https://gitlab.com/x86-psABIs/x86-64-ABI
- Hex-Rays FLIRT: https://hex-rays.com/products/ida/tech/flirt/
- musl `src/string/strlen.c` (`HASZERO` makrosu): https://git.musl-libc.org/cgit/musl/tree/src/string/strlen.c
