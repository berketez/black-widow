# Decompiler Backends

Karadul v1.11.0 itibariyle çoklu decompiler backend'i destekler. Bu
dokümanda hangi backend'i ne zaman seçeceğin, yapılandırma ve fallback
stratejisi açıklanır.

## Hızlı Özet

| Backend | Varsayılan | Kurulum | Hız | Kalite | Desteklenen Platform |
|---------|-----------|---------|-----|--------|----------------------|
| `ghidra` | **Evet** | External (bir defa) | Orta | Yüksek | macho, elf, pe, raw, coff |
| `angr`   | Hayır     | `pip install angr` | Yavaş | Orta | macho, elf, pe |

Karadul tarihsel olarak Ghidra'ya sıkı bağlıydı. Phase 1B itibariyle
`DecompilerBackend` Protocol üzerinden pipeline backend-agnostic hale
getirildi.

## Backend Seçimi

### CLI flag
```bash
karadul analyze --decompiler-backend=angr /bin/ls
karadul analyze --decompiler-backend=ghidra /bin/ls   # default, optional
```

### Config (YAML)
```yaml
decompilers:
  primary_backend: angr          # ghidra | angr
  fallback_chain: [ghidra]       # primary kullanilamazsa sira ile dener
  # enable_parallel_decomp: false    # ileriki sprint (yer tutucu)
  # secondary_backend: null          # paralel mod icin (yer tutucu)
```

## Ne Zaman Hangi Backend?

### Ghidra (varsayılan, önerilen)
**Avantajlar:**
- Endüstri standardı, olgun decompiler
- SLEIGH ile 40+ processor / mimari desteği (x86, ARM, MIPS, PowerPC, 8051...)
- C++ RTTI, Objective-C, Swift metadata'sı iyi çıkarılır
- PDB / DWARF / Mach-O sembol entegrasyonu
- Karadul script'leri (functions.py, call_graph.py, string_extractor.py...)
  JSON export'u bu backend'e göre yazılmış
- Pipeline'ın tam feature set'i (semantic_naming, struct_recovery,
  algorithm_id, computation_fusion) Ghidra çıktısı üzerinde kalibre edilmiş

**Dezavantajlar:**
- Jython / JVM overhead — cold-start ~10-20 sn
- analyzeHeadless kurulumu manuel (installer + PATH + GHIDRA_INSTALL_DIR)
- Büyük binary'lerde (> 100 MB) memory baskısı

**Seç:** macOS / Linux / Windows native uygulamalar, C++ uygulamalar,
production analiz, kalite öncelikli işler.

### angr
**Avantajlar:**
- Saf Python, `pip install angr` ile tek komut kurulum (CI-friendly)
- Headless default — GUI yok
- Symbolic execution ile path coverage analizi yapılabilir
- Platform çeşitliliği: exotic ISA'lar (TriCore, AVR, RISC-V gelişiyor)
- Script API'si Python native — prototipleme hızlı

**Dezavantajlar:**
- Decompile kalitesi Ghidra'dan belirgin düşük (bilinen gap)
- CFGFast + Decompiler pass büyük binary'de yavaş ve RAM-hungry
- C++ name mangling desteği zayıf (Itanium ABI kısmi, MSVC ABI yok)
- PDB entegrasyonu yok, Mach-O DWARF kısıtlı
- Karadul'un downstream step'leri Ghidra-şema'sına göre kalibre — angr
  çıktısı adapter üzerinden aynı şemaya çevrilir fakat bazı alanlar
  (`param_count`, `calling_convention`, `parameters`) eksik kalabilir,
  bu da `semantic_naming` / `struct_recovery` doğruluğunu düşürebilir

**Seç:** ARM firmware, MIPS router binary, embedded / IoT, Ghidra
kurulamayan CI ortamı, symbolic execution gerektiren araştırma.

## Fallback Stratejisi

`fallback_chain` primary backend kullanılamaz durumdaysa devreye girer.
"Kullanılamaz" iki durumu kapsar:

1. `is_available()` False döner (ör. angr modülü import edilemedi)
2. `decompile()` sırasında `RuntimeError` veya benzer fatal hata

Varsayılan yapılandırma:
```yaml
decompilers:
  primary_backend: ghidra
  fallback_chain: [ghidra]
```
Bu durumda primary == chain[0] olduğundan tek deneme yapılır.

**Senaryo:** Berke angr'ı denemek istiyor ama laptop'ta angr kurulu değil:
```yaml
decompilers:
  primary_backend: angr
  fallback_chain: [ghidra]
```
- `create_backend_with_fallback(cfg)` çağrılır.
- `AngrBackend.is_available()` False → log atılır, Ghidra'ya düşülür.
- Log: `Primary decompiler backend 'angr' kullanilamaz durumda; 'ghidra'
  backend'ine dusuldu (fallback chain: ['ghidra']).`

**Senaryo:** angr `decompile()` runtime crash eder (OOM, segfault):
- `MachOAnalyzer._run_ghidra` backend'i çağırır, exception yakalar
- Ghidra `is_available()` ise legacy Ghidra path'e düşer
- Çıktı: `{"success": True, "mode": "ghidra_legacy"}`

## Pipeline Entegrasyonu

Backend seçimi `MachOAnalyzer._run_ghidra` içinde yapılır (isim legacy,
gerçekte backend-agnostic). Pipeline akışı:

1. `primary_backend == "ghidra"` **ve** Ghidra kurulu → eski kod yolu
   (3576 PASS baseline korunur, dokunulmaz).
2. Aksi halde `create_backend_with_fallback(cfg)` çağrılır:
   - angr dönerse `backend.decompile(binary, output_dir)` çalıştırılır,
     `DecompileResult` `karadul/decompilers/pipeline_adapter.py` ile
     Ghidra JSON şemasına (`ghidra_functions.json` /
     `ghidra_strings.json` / `ghidra_call_graph.json` +
     `ghidra_output/decompiled/*.c`) çevrilip `static/` altına yazılır.
   - Downstream pipeline step'leri (`ghidra_metadata`, `binary_prep`,
     `semantic_naming`, `struct_recovery`, `algorithm_id`, ...) **hiç
     değiştirilmeden** aynı dosyaları okur.

Böylece angr entegrasyonu downstream step'lere dokunmaz — adapter
sayesinde "Ghidra-şema sözleşmesi" korunur.

## Backend Kalite / Hız Karşılaştırması

`tests/test_angr_pipeline_integration.py` smoke test'i iki backend'i
aynı mock binary üzerinde karşılaştırır — sonuçlar göstermeliktir:

| Metrik | Ghidra | angr |
|--------|--------|------|
| Fonksiyon tespit | Yüksek | Orta (CFGFast bazı fonksiyonları kaçırır) |
| Pseudocode kalitesi | Yüksek (P-Code tabanlı) | Orta (AIL tabanlı) |
| C++ name demangle | Yüksek | Düşük |
| Süre (10MB binary) | ~30-60 sn | ~60-180 sn |
| RAM (peak) | ~1-2 GB | ~2-4 GB |

Sayısal kıyaslama `benchmark/` suite altında (ileri sprint).

## Gelecek Planlar (v1.11.0+)

- **Paralel mod:** `enable_parallel_decomp: True` → primary + secondary
  paralel çalıştır, sonuçları birleştir / oyla.
- **BinaryNinja backend:** `BinjaBackend` adapter (license sahibi
  kullanıcılar için).
- **IDA Pro backend:** `IDABackend` (HexRays decompiler).
- **Sonuç karşılaştırma raporu:** Aynı binary için iki backend çıktısını
  diff'leyip güven skoru üreten `compare_backends.py` script'i.
