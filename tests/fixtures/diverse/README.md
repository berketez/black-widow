# Karadul B25 – Çok-Mimari Fixture'ları

Bu dizin Karadul pipeline'ını **birden çok mimari ve format** üzerinde
doğrulamak için kullanılır. v1.15-A coreutils suite'i sadece **arm64
Linux ELF** içerir; bu yetersizdi. B25 audit'ine göre x86_64 ve farklı
format'lar için ek fixture şarttı.

## Mevcut Fixture'lar

| Dosya                            | Format  | Mimari   | Boyut   | Sembol durumu     |
|----------------------------------|---------|----------|---------|-------------------|
| `hello_macho_arm64_debug`        | Mach-O  | arm64    | ~33 KB  | Debug (`-g`)      |
| `hello_macho_arm64_stripped`     | Mach-O  | arm64    | ~33 KB  | `strip` uygulandı |
| `hello_macho_x86_64_debug`       | Mach-O  | x86_64   | ~9 KB   | Debug (`-g`)      |
| `hello_macho_x86_64_stripped`    | Mach-O  | x86_64   | ~8 KB   | `strip` uygulandı |

Hepsi `hello.c` kaynak dosyasından `clang` ile üretildi.
`-O0 -fno-inline` kullanıldı; aksi halde 4 küçük fonksiyon (`add`,
`multiply`, `get_greeting`, `print_info`) inline'lanıp Ghidra için
test malzemesi kalmıyor.

## Yeniden Build Talimatı (macOS, Apple Silicon)

Apple Silicon Mac'te clang varsayılan olarak hem **arm64** hem
**x86_64** Mach-O üretebilir (cross-toolchain GEREKMEZ):

```bash
cd tests/fixtures/diverse

# Debug variant (nm ground truth için)
clang -arch x86_64 -O0 -fno-inline -g -o hello_macho_x86_64_debug hello.c
clang -arch arm64  -O0 -fno-inline -g -o hello_macho_arm64_debug  hello.c

# Stripped variant (karadul analyze hedefi)
clang -arch x86_64 -O0 -fno-inline -o hello_macho_x86_64_stripped hello.c
clang -arch arm64  -O0 -fno-inline -o hello_macho_arm64_stripped  hello.c
strip hello_macho_x86_64_stripped hello_macho_arm64_stripped

# dSYM bundle'larını sil (binary değil, ayrı debug dizini)
rm -rf *.dSYM
```

Doğrulama:

```bash
file hello_macho_*
nm -a hello_macho_arm64_debug | grep -E "_add|_multiply"
```

## Eksik Fixture'lar (TODO)

Bu mimariler için **cross-compile toolchain** gerekir; Berke'nin
sistemine kurulu değil (`brew install` ile eklenebilir):

| Format      | Komut                                          | Kurulum                    |
|-------------|------------------------------------------------|----------------------------|
| Linux ELF x86_64 | `x86_64-linux-gnu-gcc -o hello_elf_x86_64 hello.c` | `brew install x86_64-elf-gcc` veya Docker |
| Linux ELF arm64  | `aarch64-linux-gnu-gcc ...`                     | `brew install aarch64-elf-gcc` |
| Windows PE32+    | `x86_64-w64-mingw32-gcc -o hello_pe32.exe hello.c` | `brew install mingw-w64` |

**Mevcut çözüm:** B25 ajanı bu mimariler için fixture **YAPMADI**
(toolchain yok, timeout riski). `tests/fixtures/coreutils/binaries/stripped/`
zaten Linux ELF arm64 içerir (Ubuntu apt'tan); Linux x86_64 için Docker
build yolu `tests/fixtures/coreutils/Dockerfile`'da mevcut.

## Pipeline E2E Test

Bu fixture'ları kullanan uçtan uca test:

```bash
pytest tests/test_pipeline_e2e_real_binary.py -v -s
```

Fixture yoksa testler otomatik **skip** olur; build talimatı ekranda
gözükür.

## Boyut Disiplini

Toplam fixture boyutu **< 200 KB** olacak şekilde tutuldu. 1 MB üstü
binary repo'yu şişirir; gerekirse `.gitattributes` ile Git LFS
kullanılmalı.
