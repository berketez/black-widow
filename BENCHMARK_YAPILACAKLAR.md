# Karadul — Benchmark Planı (Yapılacaklar)

**Oluşturulma:** 2026-04-25
**Durum:** Plan aşaması — bu sprint'te uygulanmayacak, ileride yapılacak
**Soru:** Karadul'un sembol/yapı kurtarması Ghidra/IDA ve modern decompiler'lardan ne kadar farklı?

---

## 1. Hedef Metrikler

Üç ölçüm katmanı var:

| Katman | Ne ölçüyor | Tipik metrik |
|---|---|---|
| **Function name recovery** | Fonksiyon adlarını ne kadar doğru kurtarıyor | Precision/Recall/F1, BLEU, exact match |
| **Variable name recovery** | Local değişken/parametre adlarını ne kadar doğru kurtarıyor | F1, semantic similarity (CodeBERT) |
| **Structural recovery** | Struct/class/inheritance, RTTI, vtable kurtarımı | Manuel inceleme, oran |

---

## 2. Benchmark Setleri (İndirilecek)

### 2.1 DIRTY (CMU, 2022)

- **GitHub:** `github.com/CMUSTRUDEL/DIRTY`
- **Veri:** 1M+ binary fonksiyon, ground-truth değişken adları
- **Yapı:** Hex-Rays + ground truth eşleştirmesi
- **Avantaj:** Hazır pipeline, F1 hesabı dahil
- **Boyut:** ~50GB

### 2.2 Coreutils (GNU)

- **Kaynak:** `gnu.org/software/coreutils`
- **Avantaj:** Açık kaynak → ground-truth bizde, 100+ küçük binary
- **Yöntem:** Build et:
  ```bash
  ./configure CFLAGS="-g -O2"
  make
  # debug versiyonu (semboller var) → ground truth
  # strip ile semboller alınır → Karadul input
  ```
- **Manuel eşleştirme gerekiyor** (debug ↔ stripped)

### 2.3 Decompile-Eval (CSecAI)

- **GitHub:** `github.com/CSecAI/decompile-eval`
- **Açıklama:** Decompiler kalitesi için açık dataset
- **İçerik:** Çeşitli mimari (x86, ARM), zorlu obfuscation senaryoları
- **Boyut:** ~5GB

### 2.4 CodeArt (2024)

- **GitHub:** `github.com/...` (paper: 2024)
- **Açıklama:** Function name recovery, modern transformer-tabanlı baseline
- **Avantaj:** Karadul vs ML-bazlı yaklaşım kıyaslaması

### 2.5 Real Malware Binaries (opsiyonel)

- **Kaynak:** VirusShare, VirusTotal Academic
- **Avantaj:** Karadul'un asıl kullanım senaryosu
- **Risk:** Yasal/etik filtre gerekiyor, izolasyon (VM)
- **Erişim:** Akademik başvuru gerekebilir

---

## 3. Karşılaştırılacak Rakip Tools

| Tool | Tür | Önemi |
|---|---|---|
| **Ghidra** | NSA, açık kaynak | En yaygın baseline |
| **IDA Pro** | Hex-Rays, ticari | Endüstri standardı |
| **Binary Ninja** | Ticari | Modern alternatif |
| **angr** | Symbolic execution | Statik analiz baseline |
| **DIRE/DIRTY** | ML-based | Variable name recovery state-of-art |
| **CodeArt** | Transformer | 2024 SOTA |

---

## 4. Önerilen Başlangıç Stratejisi

### Faz 1 — Smoke Test (1 gün)
- Coreutils'ten 10 küçük binary build et (debug + stripped)
- Karadul'u stripped üzerinde çalıştır
- Manuel olarak fonksiyon adı eşleştirmesi yap (10 binary × 20 fonksiyon = 200 sample)
- Pilot precision/recall hesabı

### Faz 2 — DIRTY Otomatik Pipeline (3-5 gün)
- DIRTY clone, dependencies kurulum
- Karadul'u DIRTY format'ında output verecek şekilde adapt et
- DIRTY evaluation script'ini Karadul üzerinde çalıştır
- Variable name F1 sonucu

### Faz 3 — Cross-Tool Karşılaştırma (1 hafta)
- Aynı binary set'i Ghidra + IDA + Karadul ile çalıştır
- Sonuçları aynı ground truth'a göre skorla
- Tablo: tool × metric × binary suite

### Faz 4 — Yayın (opsiyonel)
- Sonuçlar iyi çıkarsa kısa teknik rapor (5-10 sayfa)
- arXiv preprint veya GitHub README'de "vs Ghidra/IDA" bölümü

---

## 5. Dosya Konumu Önerisi

```
black-widow/
├── benchmarks/
│   ├── ground_truth/        # Coreutils debug build outputs
│   ├── stripped/            # Stripped binaries (Karadul input)
│   ├── results/
│   │   ├── karadul/         # Karadul output
│   │   ├── ghidra/          # Ghidra script output
│   │   └── ida/             # IDA script output
│   ├── scripts/
│   │   ├── build_coreutils.sh
│   │   ├── run_karadul.py
│   │   ├── run_ghidra.py
│   │   ├── compare.py       # F1/precision/recall hesabı
│   │   └── plot_results.py
│   └── reports/
│       ├── 2026-XX-XX-coreutils-baseline.md
│       └── 2026-XX-XX-dirty-pipeline.md
```

`benchmark_mock_*.json` dosyaları zaten var — bunlar 2026-04-22 tarihli, gerçek ground-truth değil mock. Gerçek pipeline'a geçince bunları `benchmarks/legacy_mock/` altına taşı.

---

## 6. Risk ve Dikkat

- **Karadul output formatı standardize edilmeli** (JSON schema), karşılaştırma için
- **Ground truth seçimi kritik:** debug build'in DWARF bilgisi her zaman ne istediğimiz değil (inline edilmiş fonksiyonlar, optimizer renames)
- **Ghidra/IDA otomasyonu:** Ghidra için headless mod, IDA için IDAPython script — 1-2 gün kurulum
- **İstatistiksel anlamlılık:** En az 100 binary, her biri 50+ fonksiyon olmadan iddia zayıf

---

## 7. Sonraki Adım (gerçekten başladığımızda)

1. Bu dosyayı yeniden oku
2. Coreutils 5 binary ile pilot çalış
3. Sonuca göre Faz 2'ye geç
4. Bu süreçte `benchmarks/reports/` altında haftalık güncelleme tut
