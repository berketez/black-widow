# Karadul Quickstart

Karadul (Black Widow), LLM kullanmayan, reproducible, tamamen Python
tabanli bir binary reverse engineering paketidir. Bu rehber tek
binary analizini 5--10 dakikada calistirmak icin yeterlidir.

## Kurulum

```bash
# 1. Python 3.12+ sanal ortam
python3.12 -m venv .venv && source .venv/bin/activate

# 2. Paket (extras: full == Ghidra bridge + FLIRT + YARA + capa)
pip install -e ".[full]"

# 3. Ghidra 11.x kurulumu ayri gerekli
export GHIDRA_INSTALL_DIR=/opt/ghidra_11.3.1_PUBLIC
```

Isteyen kullanicilar sadece `pip install -e .` ile minimal bagimliliklari
kurar; Ghidra/YARA bulunamadiginda pipeline ilgili stage'leri atlar.

## Ilk analiz -- CLI

```bash
karadul analyze /bin/ls -o /tmp/karadul-ls
# Sonuclar: /tmp/karadul-ls/{raw,analysis,reconstruction,reports}/
cat /tmp/karadul-ls/reports/summary.json
```

## Python API

```python
import karadul

result = karadul.analyze("/bin/ls")
print("Basarili:", result.success)
for name, artifact in result.artifacts.items():
    print(f"  - {name}: {artifact}")
```

Ozel config ile:

```python
from karadul import analyze, Config

cfg = Config.load("/path/to/config.toml")
result = analyze("/bin/ls", config=cfg, stages=["static_analysis", "decompile"])
```

## CLI komut referansi

| Komut | Amac |
|-------|------|
| `karadul analyze <binary>` | Tam pipeline (tespit + decompile + kurtarma + rapor) |
| `karadul score <workspace>` | Kod kalitesi puanlamasi (readability, complexity, naming) |
| `karadul rtti <binary>` | C++ RTTI / vtable / class hiyerarsisi cikarma |
| `karadul batch <dir>` | Bir dizindeki tum binary'leri paralel isle |
| `karadul diff <a> <b>` | Iki binary arasinda BinDiff karsilastirma |

## Isim kurtarma ornegi

```python
from karadul.reconstruction.binary_name_extractor import BinaryNameExtractor
extractor = BinaryNameExtractor()
names = extractor.extract("/bin/ls")
print(f"Kurtarildi: {len(names.recovered_symbols)} sembol")
```

## Sonraki adimlar

- `docs/API.md` -- tam API referansi
- `docs/ARCHITECTURE.md` -- pipeline mimari
- `docs/adr/` -- karar kayitlari (ADR)
- `docs/EXAMPLES.md` -- gercek dunya senaryolari
