# GitHub Actions iş akışları

Bu iş akışlarının hiçbiri ad kalitesini ölçmez ve hiçbirinde doğruluk eşiği yok.
Ad ve tip ölçümleri Ghidra ile, depo dışında koşulur ve sonuçları `docs/arge/`
altında ön kayıtlı belgelerle tutulur. CI makinesinde Ghidra yok.

Önceki "F1 kapısı" kaldırıldı: `scripts/run_mock_benchmark.py` koda sabit yazılmış
bir F1 değerini (0,9091) döndürüyor, iş akışı da bunu 0,85 eşiğiyle kıyaslıyordu.
Yanındaki `scripts/ci_baseline_check.py` adımı da commit'li bir JSON'daki sayıyı
0,0 tabanıyla kıyaslıyordu; kodu ölçmüyordu.

## ci.yml

Tetikleyiciler: `main`'e push, `main`'e açılan PR, elle (`workflow_dispatch`).

| İş | Ne yapar |
|----|----------|
| `tests` | Ubuntu (Python 3.11 ve 3.12) ve macOS (Python 3.12) üzerinde `pip install -e ".[dev,perf,binary,computation,cpp]" pyelftools pyfiglet`, `npm install --prefix scripts`, sonra varsayılan pytest seçimi (`pyproject.toml`: `not integration and not benchmark`) |
| `install-smoke` | Ubuntu, Python 3.11 ve 3.12: temiz sanal ortama düzenlenemez (`pip install .`) kurulum; depo dışından `karadul --version`, `karadul --help`, `karadul analyze --help`, `blackwidow --help`, `python -m karadul --help`; genel API içe aktarımları ve varsayılan aşama listesi; ardından README'nin önerdiği `.[ghidra,binary,perf]` ile `import karadul.reconstruction` |
| `known-issues` | Bilinen iki paketleme hatasını bilerek yeniden üretir; düzeltilene kadar başarısız olması beklenir, `continue-on-error: true` ile iş akışını düşürmez. Yeşile döndüğünde silinmeli |

`known-issues` işinin yakaladığı hatalar:

1. Ek seçmeden yapılan kurulumda (`pip install .`) `import karadul.reconstruction`
   düşer: `pyahocorasick` yalnız `perf` ekinde tanımlı.
2. `karadul-hack` giriş noktası `pyfiglet`'i içe aktarır; hiçbir ek bunu kurmaz.

### Açıkça dışarıda bırakılan testler

Temiz klonda geçmeleri mümkün değil; `--ignore` ile iş akışında adıyla ayrıldılar:

| Dosya | Test sayısı | Neden |
|-------|-------------|-------|
| `tests/test_ngram_db_v2_smoke.py` | 16 | `sigs/ngram_name_db/` gerekiyor; dizin git-ignore'lu, depoda yok. Veri yokken atlamak yerine düşüyor |
| `tests/test_pipeline_e2e_real_binary.py` | 8 (varsayılan seçimde) | `karadul analyze`'ı uçtan uca koşturur, Ghidra gerekir. Ayrıca CLI'ı `shutil.which("karadul")` ile bulduğu için yerelde test edilen ortamın değil, PATH'teki ilk kurulumun kodunu koşturabilir |

### Pakette tanımlı olmayan test bağımlılıkları

- `pyelftools`: `scripts/measurement/` ve testleri (`tests/test_dwarf_tip.py`,
  `tests/test_parametre_hizala.py`) kullanıyor.
- `pyfiglet`: `karadul/hacker_cli.py` içe aktarıyor.

İkisi de iş akışında elle kuruluyor. Kalıcı çözüm `pyproject.toml`'a eklemek.

## benchmark.yml

Tetikleyiciler `ci.yml` ile aynı. Ubuntu, Python 3.12:
`pip install -e ".[dev,perf,binary,computation,cpp]"`, sonra
`pytest -m "benchmark and not integration" --ignore=tests/test_pipeline_e2e_real_binary.py`.

Bu testler ölçüm ve kıyas kodunu commit'li fikstürler üzerinde sınar; Karadul'un
adlarının ne kadar doğru olduğunu ölçmez. `tests/benchmark/test_parallel_naming_perf.py`
paralel adlandırmanın en az 1,3 kat hızlandırdığını denetliyor; yüklü bir CI makinesinde
dalgalanabilir.

## Yerelde aynı adımlar

```bash
python -m venv .venv-ci
.venv-ci/bin/python -m pip install -e ".[dev,perf,binary,computation,cpp]" pyelftools pyfiglet
npm install --prefix scripts --no-audit --no-fund

# ci.yml / tests
.venv-ci/bin/python -m pytest -q -rfEs \
    --ignore=tests/test_ngram_db_v2_smoke.py \
    --ignore=tests/test_pipeline_e2e_real_binary.py

# benchmark.yml
.venv-ci/bin/python -m pytest -q -rfEs -m "benchmark and not integration" \
    --ignore=tests/test_pipeline_e2e_real_binary.py
```

Ghidra kurulu bir makinede `tests/test_ghidra.py::TestRealBinary::test_ghidra_full_analysis`
atlanmaz, gerçekten Ghidra koşturur. `pyghidra` kurulu değilse `analyzeHeadless` yoluna
düşer ve bu yolda düşebilir. CI makinesinde Ghidra olmadığı için atlanır.
