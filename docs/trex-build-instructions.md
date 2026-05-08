# TRex Build Talimatlari (Karadul v1.13 Dalga 3)

TRex (USENIX Security 2025), Rust ile yazilmis bir tip rekonstruksiyon
aracidir. Karadul ``TRexAdapter`` modulu (``karadul/analyzers/trex_adapter.py``)
TRex binary'sini opsiyonel olarak kullanir; binary yoksa pipeline sessizce
devam eder.

## On Kosullar

- macOS, Linux veya Windows (WSL onerilir)
- ~5 GB disk (Cargo cache + release build)
- Rust 1.86+ (USENIX paper'da test edilmis surum)
- Git (zaten kurulu olmali, vendor klasoru git submodule)

## Adim 1 — Rust Toolchain Kurulumu

Sistemde ``cargo``/``rustc``/``rustup`` yoksa rustup ile kur:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustc --version    # Beklenen: rustc 1.86.0 veya yeni
cargo --version
```

Notlar:
- macOS'ta ek olarak Xcode Command Line Tools gerekebilir:
  ``xcode-select --install``
- Apple Silicon icin default toolchain ``aarch64-apple-darwin`` zaten dogru.

## Adim 2 — TRex Build

Karadul kok dizinden:

```bash
cd vendor/trex/trex
cargo build --release
```

Build suresi: M2 Pro icin ~2-3 dakika (ilk seferde dependency derler).

Sonuc binary konumu:
```
vendor/trex/trex/target/release/trex
```

## Adim 3 — Smoke Test

vendor/trex/trex/tests/ icinde hazir orneklerle dene:

```bash
cd vendor/trex/trex
./target/release/trex from-ghidra \
    tests/test-linked-list-slot2.lifted \
    tests/test-linked-list-slot2.vars
```

Beklenen cikti (kisaltilmis):

```
// n@getlast@00100000 : t1*
// nxt@getlast@00100000 : t1*

struct t1 {
  int32_t field_0;
  t1* field_8;
};
```

## Adim 4 — Karadul ile Entegrasyon

Adapter binary'yi otomatik bulur (``vendor/trex/trex/target/release/trex``).
Alternatif olarak env var ile override edilebilir:

```bash
export KARADUL_TREX_PATH=/custom/path/trex
```

Python kontrolu:

```python
from karadul.analyzers.trex_adapter import TRexAdapter

adapter = TRexAdapter()
print("Available:", adapter.is_available())
print("Version:", adapter.get_version())
```

## Pipeline Entegrasyon Plani (v1.13.x veya v1.14)

TRex calismak icin Ghidra PCode export'u (``foo.lifted``) gerektirir; bu
suanda Karadul pipeline'inda yok. Plan:

1. ``pipeline/steps/ghidra_pcode_export.py`` (yeni, Ghidra headless wrapper)
   -> ``foo.lifted`` ve opsiyonel ``foo.vars`` uretir.
2. ``pipeline/steps/trex_struct_recovery.py`` (yeni) -> ``TRexAdapter.analyze()``
   cagrisi, ``TRexResult.structs`` -> ``RecoveredStruct`` listesine cevirir.
3. ``CTypeRecoverer`` icindeki TypeForge merge hook'una benzer bir
   ``merge_trex_structs`` hook'u eklenir (deduplikasyon + confidence agirligi).

Bu adapter dalgasi sadece **subprocess sarmalayici + parser** sunar;
pipeline entegrasyonu sonraki dalgada yapilir.

## Sorun Giderme

| Hata | Neden | Cozum |
|------|-------|-------|
| ``cargo: command not found`` | Rust kurulu degil | Adim 1'i tekrarla |
| ``error: linker `cc` not found`` (macOS) | Xcode CLT eksik | ``xcode-select --install`` |
| ``cannot find -lssl`` (Linux) | OpenSSL dev headers yok | ``apt install libssl-dev`` |
| Binary uretildi ama Karadul gormuyor | Yol farkli | ``export KARADUL_TREX_PATH=...`` |

## Lisans

Vendor TRex kodu BSD-3 Clause; ``vendor/trex/LICENSE`` dosyasina bakin.
Karadul vendor kodunu **degistirmez**, sadece subprocess olarak cagirir.
