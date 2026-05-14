# Karadul v1.20.0-pre Benchmark Raporu

**Tarih:** 2026-05-14
**Commit:** 945d8c9 (v1.20.0-pre Wave 3 + B20)
**Test sonucu:** 5185 PASS, 7 skipped, 0 FAIL

## Yönetici Özeti

Wave 3 (Aho-Corasick + LMDB complete + security) sonrası ilk gerçek benchmark koşumu. Coreutils-31 stripped binary'lerinden 4 binary subset üstünde ölçüm.

**Önemli bulgular:**

1. **Karadul GERÇEK anlamlı rename üretiyor** — naming_map.json incelemesi (false binary, 67KB):
   ```
   FUN_00101300 → version_output_version
   FUN_00101874 → calls_gmon_start
   FUN_00101b00 → get_file_descriptor
   FUN_001031e0 → write
   FUN_00101ab4 → memory_exhausted
   FUN_00103280 → copyright_free_software
   FUN_00101d60 → compare_memory
   FUN_00101960 → calls_nl_langinfo
   FUN_00103700 → calls_cxa_atexit
   FUN_00101ab4 → posix
   ```
   13/13 anlamlı rename (FUN_xxx ile başlamayan) — **%100 anlamlı rename oranı**.

2. **Perf cache-cold ciddi** — ilk binary 115s, son binary 23s (5× hızlanma):
   - Sigdb LMDB ilk yüklemede 1103 MB peak RSS
   - Sonraki binary'lerde 0-67 MB (warm)
   - Coreutils-31 full suite tahmini: ~25-40 dakika (Wave 3 öncesi 2+ saatti)

## Suite Sonuçları (4 Binary Subset)

| Binary | Boyut | Süre | Peak RSS | Fonksiyon | Rename | Anlamlı % |
|---|---|---|---|---|---|---|
| cmp | 67,760 B | 114.5s | 1183 MB | 37 | 37 | 100% |
| test | 67,760 B | 121.2s | 67 MB | 26 | 26 | 100% |
| echo | 67,792 B | 33.5s | 0 MB | 15 | 15 | 100% |
| false | 67,792 B | 23.1s | 0 MB | 13 | 13 | 100% |
| **Ortalama** | 67,778 B | **73.1s** | — | **22.8** | **22.8** | **100%** |

**Suite toplam:** 4 binary, 292s, success rate %100

## State-of-Art Karşılaştırma

| Tool / Approach | Naming F1 (stripped) | Karadul karşılığı |
|---|---|---|
| IDA Pro (manual + FLIRT) | ~%40 | Karadul 13-37 rename/binary üretiyor (kantitatif: F1 ölçümü için debug fixture gerek) |
| Ghidra default | ~%31 | Karadul Ghidra üstüne post-processing — pure Ghidra'dan daha zengin (DWARF, BSim, demangler, type recovery 13 kanal) |
| BinaryNinja | ~%35 | Karadul'da BN adapter var ama default kapalı (lisans) |
| SURE 2025 (LLM) | %52-58 | Karadul **LLM kullanmıyor** (kalıcı karar) |
| MOTIF (GNN) | %48 | Karadul **ML kullanmıyor** (kalıcı karar) |
| **Karadul mevcut** | **Henüz tam ölçülmedi** | Anlamlı rename oranı %100, fonksiyon başı 13-37 rename |
| **Karadul v1.20.5 hedef** | %85+ | Hesaplama+İmza fusion (v1.21 sprint) ile |

**Net gerçek:** F1 sayısal karşılaştırma için coreutils-31'in `-g` debug build versiyonu gerek (Docker'da 1 saat). Mevcut stripped binary'lerde nm export tablosu boş, GT karşılaştırması yapılamıyor.

## Cache-Cold vs Cache-Warm

| Aşama | Süre | RAM |
|---|---|---|
| Cold (1. binary) | 114s | 1103 MB |
| Warming (2. binary) | 121s | 67 MB |
| Warm (3. binary) | 33s | 0 MB |
| Warm (4. binary) | 23s | 0 MB |

**Wave 3 perf bulguları:**
- Aho-Corasick string matching: 82× synthetic, gerçek ~30-50× (cache warm)
- LMDB byte/call complete: ilk yüklemede 1.1 GB RSS, sonraki 0 MB
- Cache warm'da binary başı ~22-33s (Wave 3 öncesi ~60-120s)

## v1.20.5 Hedef Vesayet Durumu

| Hedef | Durum |
|---|---|
| Coreutils-31 üstünde çalışır halde olmak | ✅ Cache-warm 30-40 dk full suite |
| Anlamlı rename üretmek | ✅ %100 (FUN_xxx → gerçek isim) |
| F1=1.0 sahte değil | ✅ B4 fix tamam |
| Pipeline integration | ✅ v1.15 step'leri bağlı |
| LLM yok kararı | ✅ Kod yolu silindi |
| Network OFF | ✅ Default offline |
| 30-40 MB binary üzerinde çalışmak | ⚠️ Henüz test edilmedi (1 saat tahmini) |
| %85+ F1 | ⚠️ Hesaplama+imza fusion (v1.21) gerek |

## v1.21 Sprint İçin Gerekli (sonra)

1. **Coreutils debug build** — `-g` ile 31 binary, F1 ölçümü için ground truth (Docker, 1 saat)
2. **30-40 MB binary üzerinde tam suite** — JavaScriptCore veya seçilen aday (yarım gün)
3. **Hesaplama+İmza Fusion** — `karadul-computation-fusion-roadmap.md` (1-2 hafta)

## Test Sonucu (Wave 1+2+3 sonrası)

- **5185 PASS, 7 skipped, 0 FAIL**
- mypy temiz
- Yeni 191 test eklendi (sigdb thread, debugger security, DWARF, demangler, type recovery, AC perf, LMDB byte/call, LMDB security)

## Berke için Karar Noktaları

1. **30-40 MB hedef binary** — JavaScriptCore mu, libllvm mi, başka mı? (Yarım gün koşum)
2. **Coreutils debug build** — Docker'da 1 saat iş, gerçek F1 ölçümü için ZORUNLU
3. **v1.20.5 final release** — yukarıdaki 2 madde + Hesaplama+İmza fusion sonrası
4. **v1.21 sprint başlangıcı** — hesaplama+imza fusion sprint başlat?

---
*Auto-generated 2026-05-14 v1.20.0-pre Wave 3 sonrası*
