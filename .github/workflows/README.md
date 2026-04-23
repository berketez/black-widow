# GitHub Actions Workflows

## benchmark.yml — Benchmark CI Gate

### Amac

Her PR ve main push'ta karadul'un `renamed_f1` metriğinin önceki sürüme
göre gerilemediğini doğrular. Ghidra gerektirmez; tümüyle pre-computed
fixture ve committed baseline JSON üzerinden çalışır.

### Tetikleyiciler

| Tetikleyici | Koşul |
|-------------|-------|
| `push` | `main` branch |
| `pull_request` | `main`'e açılan PR |
| `workflow_dispatch` | Manuel tetikleme (Actions UI'dan) |

### Adimlar

1. **Checkout** — `actions/checkout@v4`
2. **Python 3.12 kurulum** — `actions/setup-python@v5`, pip cache aktif
3. **Karadul kurulum** — `pip install -e ".[binary,computation,dev]"` + pytest
4. **Smoke testler** — `pytest tests/benchmark/ -m "" -q`
   - `-m ""` tüm marker'ları dahil eder (benchmark-marked testler varsayilan olarak atlanir)
   - 100+ test bekleniyor; herhangi biri fail ederse job fail olur
5. **renamed_f1 gate** — `python scripts/ci_baseline_check.py`
   - Floor: `0.0` (v1.11 beta; v1.13'te `0.5`'e yükselecek)
   - Regresyon kontrolü: `.benchmark-baseline.json` yoksa atlanir (ilk koşu)
6. **Artifact yükleme** — baseline JSON 30 gün saklanir
7. **Job summary** — renamed_f1 ve temel metrikler GitHub UI'da görünür

### Ghidra Neden Yok?

Ghidra headless CI'da kurulumu 2 GB+ indirme + 10 dakika gerektiriyor.
Bu fazda (v1.11) sadece pre-computed fixture ve `_compare_maps` birim
testleri kullanılıyor. Gerçek Ghidra CI'ı v1.12'de ayrı workflow olarak
eklenecek (`ghidra-ci.yml`).

### Dosyalar

| Dosya | Amac |
|-------|------|
| `benchmarks/stripped_baseline_2026_04_23_real.json` | Committed baseline (renamed_f1 kaynak degeri) |
| `tests/benchmark/fixtures/linux_elf_stripped/` | ELF fixture (sample_elf_stripped) |
| `scripts/ci_baseline_check.py` | Floor + regresyon kontrol scripti |
| `.benchmark-baseline.json` | Opsiyonel regresyon baseline (commit edilirse aktif olur) |

### Floor Degerleri (Milestone Tablosu)

| Versiyon | Floor | Aciklama |
|----------|-------|----------|
| v1.11 (simdi) | 0.0 | Stripped user fn henuz resolve edilmiyor |
| v1.13 (hedef) | 0.5 | Renamed fn baseline established olunca artir |
| v1.15 (hedef) | 0.7 | Mature naming pipeline |

### Local Debug

Workflow'u local'de calistirmak icin `act` kullanin:

```bash
# act kurulumu (Homebrew)
brew install act

# Workflow'u simule et
act pull_request -j benchmark

# Sadece belirli adimi debug et
act pull_request -j benchmark -s GITHUB_TOKEN=dummy
```

Alternatif olarak adim adim manual:

```bash
# 1. Kurulum
pip install -e ".[binary,computation,dev]" && pip install pytest pytest-cov

# 2. Smoke testler
pytest tests/benchmark/ -m "" -q --tb=short

# 3. Gate kontrolu
python scripts/ci_baseline_check.py \
    --baseline benchmarks/stripped_baseline_2026_04_23_real.json \
    --floor 0.0

# Beklenen cikti:
# [check] renamed_f1 = 0.0000  floor = 0.0000
# [PASS]  renamed_f1 0.0000 >= floor 0.0000
# [info]  .benchmark-baseline.json not found — regression check skipped
# [OK]    Benchmark gate passed.
```

### Yaygin Hatalar

**`ModuleNotFoundError: No module named 'karadul'`**
Karadul editable install yapilmamis. `pip install -e .` calistirin.

**`pytest: error: unrecognized arguments: -m ""`**
pytest versiyonu cok eski. `pip install "pytest>=8.0"` ile guncellleyin.

**`[FAIL] renamed_f1 X.XXXX < floor Y.YYYY`**
Bir PR naming pipeline'ini bozdu. `benchmarks/` altindaki JSON'lari
inceleyin, hangi commit'te dusus oldugunnu bulmak icin:
```bash
git log --oneline benchmarks/stripped_baseline_2026_04_23_real.json
```

**`[FAIL] REGRESSION: renamed_f1 dropped from ...`**
`.benchmark-baseline.json` mevcut ve mevcut deger daha dusuk.
Kasitliysa floor'u guncelleyin veya `.benchmark-baseline.json`'i commit
edin. Kasitsizsa pipeline'daki regresyonu bulun ve duzeltein.

### PR Comment

`marocchino/sticky-pull-request-comment` eski workflow'dan kaldirildi
(gereksiz external dependency). Gate sonucu GitHub Job Summary'de gorunur.
