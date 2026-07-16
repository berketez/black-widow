# varname_bench — Değişken-adı F1 ölçüm fixture'ı

Karadul'un **değişken isimlendirme** doğruluğunu ölçmek için DWARF ground-truth'lu
bir arm64 Mach-O benchmark. Fonksiyon isimlerinde dynsym/gnulib GT vardı; yerel
değişkenlerde stripped binary'de HİÇ GT yoktur — bu fixture o boşluğu doldurur.

## Ne içerir

- `src/` — GERÇEK gnulib kripto/hash implementasyonları (temsili/oyuncak DEĞİL):
  - `sha1.c/.h`, `sha256.c/.h`, `md5.c/.h`, `crc.c/.h` — Free Software Foundation,
    **LGPL 2.1+** (lisans başlıkları dosyalarda korunmuştur). gnulib master
    `bb5bb43a` sürümünden.
  - `config.h`, `byteswap.h` — bu benchmark için yazılmış minimal macOS derleme
    stub'ları (gnulib'in `<config.h>`/`<byteswap.h>` Linux bağımlılıklarını karşılar).
  - `hashdriver.c` — küçük sürücü (bir mesajın CRC32+MD5+SHA1+SHA256 özetini alır).
- `gen_fixture.sh` — fixture üretici (aşağı bak). `build/` çıktısı git'e KONMAZ
  (`.gitignore`), her makinede script'ten yeniden üretilir.

## Neden gnulib kripto?

- **Gerçek, çalışan kod**: üretilen binary sistem `shasum`/`md5` ile birebir aynı
  özetleri verir (gen script bunu doğrular). El-yazımı oyuncak kod değil → değişken
  adları temsili.
- **Zengin değişken adları**: `sha256_process_block` içinde `a,b,c,d,e,f,g,h,words,
  nwords,endp,x,tm,t0,t1`; parametreler `buffer,len,ctx` — insan yazımı, anlamlı.
- **Küçük**: ~30 fonksiyon → Ghidra analizi dakikalar (CalculiX'in 33 dk'sı değil).

## Fixture'ı üret

```bash
bash tests/fixtures/varname_bench/gen_fixture.sh          # -> build/
# veya baska dizine:
bash tests/fixtures/varname_bench/gen_fixture.sh /tmp/vb
```

Üretilen (her -O0 ve -O2 için):
- `hashbench_O0`           — debug executable (isimler korunmuş)
- `hashbench_O0.dSYM`      — DWARF ground truth (fonksiyon+param+lokal adları)
- `hashbench_O0.stripped`  — gerçek stripped (analiz hedefi; sadece `__mh_execute_header`)

Gereksinim: Apple `clang` + `dsymutil` (Xcode Command Line Tools). Script her
`.c`'yi KALICI `.o`'ya derler; tek-adımlı derlemede geçici `.o`'lar silinip
dsymutil BOŞ dSYM üretiyor (deterministik olmayan sessiz bug) — o yüzden ayrı
derleme + link + dsymutil, ardından `DW_TAG_subprogram >= 5` guard'ı.

## Ölçüm

```bash
# 1) fixture üret
bash tests/fixtures/varname_bench/gen_fixture.sh
# 2) STRIPPED binary'yi karadul ile analiz et (bundle Ghidra/JDK/LMDB ile)
export GHIDRA_INSTALL_DIR="$HOME/Library/BlackWidowBuild/Black Widow.app/Contents/Resources/ghidra"
export JAVA_HOME="$HOME/Library/BlackWidowBuild/Black Widow.app/Contents/Resources/jdk/Contents/Home"
export PATH="$JAVA_HOME/bin:$PATH"
export KARADUL_SIG_LMDB_PATH="$HOME/Library/BlackWidowBuild/Black Widow.app/Contents/Resources/signatures.lmdb"
python3 -m karadul analyze tests/fixtures/varname_bench/build/hashbench_O0.stripped \
    --skip-dynamic --lmdb-sigdb --output-dir /tmp/hb_ws --output /tmp/hb_clean
# 3) DEĞİŞKEN-adı F1'i ölç (GT = dSYM'deki DWARF, analiz = stripped'ten)
python3 scripts/varname_f1_eval.py --debug tests/fixtures/varname_bench/build/hashbench_O0 \
    --recon-src /tmp/hb_clean/src
```

## BASELINE (2026-07-16, main + gnulib fix'li pipeline)

| Metrik            | -O0 (33 fn) | -O2 (17 fn) | Not |
|-------------------|-------------|-------------|-----|
| Fonksiyon F1      | 0.844       | 0.941       | ⚠️ SIZINTILI (aşağı bak) |
| Parametre F1 / recall | 0.000   | 0.000       | tümü `param_N` placeholder |
| Lokal F1 / recall | 0.034 / 0.053 | 0.000 / 0.000 | O0'da 4 kurtarma (`i↔i_3`, `length↔len`) |
| Değişken (P+L) F1 | 0.026       | 0.000       | task #9 baseline'ı |

### ⚠️ İki dürüstlük uyarısı

1. **Fonksiyon F1 SIZINTILI, temsili değil.** Bu fixture gnulib olduğu ve gnulib
   karadul'un imza DB'sinde olduğu için fonksiyon adları imza-eşleşmesiyle "bedava"
   kurtarılır (best-case). Özgün/kapalı kod için geçerli olmaz. (expr 0.92 ezberi
   dersinin aynısı.) **Değişken** adları imza DB'de YOKTUR (DWARF-only) → değişken
   F1 sızıntısız, gerçek ölçüm.
2. **Değişken precision'ı seyreltilmiş.** karadul jenerik hesaplı adlar üretir
   (`accumulator_N`, `val_N`, `raw_value_N`) + decompiler SSA-geçici değişkenleri
   kaynak değişkeni olmayan çok sayıda lokal yaratır. Bunlar hiçbir GT'ye
   eşleşemez → FP patlar, precision çöker. **Güvenilir metrik RECALL'dır** (GT
   değişkeninin kaçı kurtarıldı): ~%0-5. precision'ı bu bağlamda oku.
