# Linux ELF Stripped Fixture

Karadul v1.11.0 Dalga 5 — gercek stripped binary baseline icin.

## Neden gerekli

macOS `strip` sahte-stripping yapar: dyld icin export table korunur,
F1=1.000 cikti yanilticidır. Linux ELF `strip --strip-all` tum sembolleri
siler; sembol tablosu sıfırlanır. Bu fixture gercek stripped binary
zorlugunu olcer.

## Binary bilgisi

- Mimari: **aarch64 ELF** (ARM64 Linux)
- Derleyici: gcc 12 (Docker: `gcc:12` imaji, Colima/aarch64 host)
- Derleme bayraklari: `-g -O1`
- Kaynak: `fixture.c` (bu dizinde)

## Dosyalar

| Dosya | Aciklama |
|-------|----------|
| `fixture.c` | Kaynak C kodu (reproducible build icin) |
| `sample_elf` | Debug sembollü binary (ground truth kaynagi) |
| `sample_elf_stripped` | `strip --strip-all` uygulanmis |
| `sample_elf.ground_truth.json` | `GroundTruth.to_dict()` formatinda sembol haritasi |

## Uretim reçetesi (reproducible)

```bash
# 1. Kaynak dizini hazirla
mkdir -p /tmp/karadul_fixture
# fixture.c'yi buraya kopyala

# 2. Docker ile derle (Colima aarch64)
DOCKER_HOST="unix:///Users/apple/.colima/default/docker.sock" \
docker run --rm -v /tmp/karadul_fixture:/work -w /work gcc:12 bash -c "
  gcc -g -O1 fixture.c -o sample_elf
  cp sample_elf sample_elf_stripped
  strip --strip-all sample_elf_stripped
  nm --defined-only sample_elf > symbols_raw.txt
"

# 3. Ground truth JSON uret
python3 /tmp/gen_ground_truth.py   # bkz: /tmp/gen_ground_truth.py

# 4. Fixture dizinine tası
mkdir -p tests/benchmark/fixtures/linux_elf_stripped/
cp sample_elf sample_elf_stripped sample_elf.ground_truth.json fixture.c \
   tests/benchmark/fixtures/linux_elf_stripped/
```

## Dogrulama

```bash
# macOS'ta file komutu ELF formatini taniyor
file sample_elf sample_elf_stripped
# Beklenen:
#   sample_elf:          ELF 64-bit LSB executable, ARM aarch64, ... with debug_info, not stripped
#   sample_elf_stripped: ELF 64-bit LSB executable, ARM aarch64, ... stripped

# Linux ortaminda nm ile dogrulama (Karadul analiz ortaminda):
nm sample_elf | wc -l          # > 0
nm sample_elf_stripped 2>&1    # -> "no symbols" veya bos
```

## Ground truth sembolleri (6 adet)

| Adres | Isim | Tip |
|-------|------|-----|
| `0x4006e0` | `cleanup_session` | T |
| `0x4006a0` | `encrypt_buffer` | T |
| `0x4006d4` | `init_context` | T |
| `0x4006e4` | `main` | T |
| `0x400684` | `parse_config` | T |
| `0x400698` | `send_packet` | T |

Filtre: buyuk `T` tipi (global text/fonksiyon), `__` ve `_` ile baslayan
runtime/compiler dahili semboller cikarildi (`_start`, `_init`, `_fini`,
`_dl_relocate_static_pie` vb.).

## Boyutlar

- `sample_elf`: ~71 KB
- `sample_elf_stripped`: ~66 KB
