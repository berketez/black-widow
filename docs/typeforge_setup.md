# TypeForge Kurulum Rehberi

TypeForge, stripped binary'lerden composite veri tiplerini (struct, union) kurtaran
bir Ghidra Extension'idir (IEEE S&P 2025).

Referans: [noobone123/TypeForge](https://github.com/noobone123/TypeForge)

**Onemli:** TypeForge bir Rust CLI degil, Java tabanlı Ghidra Extension'dir.
`scripts/setup_typeforge.sh`, Ghidra headless modunu saran bir wrapper uretir;
karadul bu wrapper'i subprocess olarak cagirır.

---

## Gereksinimler

| Bagimlilık | Versiyon | macOS Kurulum | Ubuntu Kurulum |
|------------|----------|---------------|----------------|
| Java (JDK) | 17+      | `brew install openjdk@17` | `apt install openjdk-17-jdk` |
| Gradle     | 7+       | `brew install gradle` | `apt install gradle` |
| Git        | herhangi | `xcode-select --install` | `apt install git` |
| Ghidra     | 11.0.3+  | [ghidra-sre.org](https://ghidra-sre.org/) | ayni |

---

## Kurulum

### 1. Ghidra Yukle

```bash
# https://ghidra-sre.org/ adresinden Ghidra 11.0.3+ ZIP indir, ac
unzip ghidra_11.0.3_PUBLIC_*.zip -d $HOME/tools/
export GHIDRA_INSTALL_DIR=$HOME/tools/ghidra_11.0.3_PUBLIC
```

### 2. TypeForge Kur

```bash
GHIDRA_INSTALL_DIR=$HOME/tools/ghidra_11.0.3_PUBLIC \
    bash scripts/setup_typeforge.sh
```

Script sirasiyla:
1. Java + Gradle kontrolu yapar
2. `~/.karadul/typeforge/TypeForge` dizinine repo klonlar
3. `gradle buildExtension` ile Ghidra Extension derler
4. Extension ZIP'ini `$GHIDRA_INSTALL_DIR/Extensions/Ghidra/` altina kopyalar
5. `~/.karadul/typeforge/typeforge` adinda headless wrapper yazar

### 3. Ortam Degiskenlerini Ayarla

`~/.zshrc` veya `~/.bashrc` dosyasina ekle:

```bash
export KARADUL_TYPEFORGE_PATH="$HOME/.karadul/typeforge/typeforge"
```

Sonra terminali yenile:

```bash
source ~/.zshrc   # veya source ~/.bashrc
```

### 4. Dogrula

```bash
karadul analyze --binary /path/to/stripped.elf
# LOG: "TypeForge: N struct (Xs)" mesajini gormeli
```

Direkt wrapper testi:

```bash
$HOME/.karadul/typeforge/typeforge \
    --binary /path/to/stripped.elf \
    --output-dir /tmp/tf_test
cat /tmp/tf_test/typeforge_result.json
```

---

## Kurulum Dizini Ozellestirme

```bash
KARADUL_TYPEFORGE_DIR=/custom/path \
GHIDRA_INSTALL_DIR=/opt/ghidra \
    bash scripts/setup_typeforge.sh
```

---

## karadul Entegrasyonu

### Env Var (Onerilen)

```bash
export KARADUL_TYPEFORGE_PATH="/path/to/typeforge"
```

### Config Dosyasi

`karadul.yaml` veya programatik:

```yaml
binary_reconstruction:
  enable_typeforge: true
  typeforge_path: "/path/to/typeforge"    # bos bırakirsan env var kullanilir
  typeforge_timeout: 600                  # saniye (buyuk binary icin artir)
  typeforge_min_confidence: 0.85          # altı struct filtrelenir
```

### Oncelik Sirasi

Adapter su sirada arar:

1. `KARADUL_TYPEFORGE_PATH` env var
2. `config.binary_reconstruction.typeforge_path`
3. `PATH` uzerinden `shutil.which("typeforge")`

---

## Sorun Giderme

### `Ghidra kurulum dizini bulunamadi`

`GHIDRA_INSTALL_DIR` env var'ini tanimlayin:

```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra_11.0.3_PUBLIC
bash scripts/setup_typeforge.sh
```

### `Java 17+ gerekli`

macOS'te birden fazla Java versiyonu varsa:

```bash
export JAVA_HOME=$(/usr/libexec/java_home -v 17)
export PATH="$JAVA_HOME/bin:$PATH"
bash scripts/setup_typeforge.sh
```

### `gradle buildExtension` Hatası

Gradle Wrapper `gradlew` kullanarak dene:

```bash
cd ~/.karadul/typeforge/TypeForge
chmod +x ./gradlew
./gradlew buildExtension
```

### TypeForge Ghidra Analizi Cok Yavas

Ghidra headless ilk calisirmada auto-analysis yapar (~30-120 saniye).
`typeforge_timeout` degerini artirin:

```yaml
binary_reconstruction:
  typeforge_timeout: 600  # varsayilan 600s, buyuk binary icin 1200
```

### `is_available()` False Donuyor Ama Binary Var

```bash
# Kontrol
ls -la $KARADUL_TYPEFORGE_PATH
file $KARADUL_TYPEFORGE_PATH

# Env var tanimli mi?
echo $KARADUL_TYPEFORGE_PATH

# karadul log seviyesini artir
karadul --log-level DEBUG analyze --binary /path/to/bin
```

---

## Bilinen Kisitlamalar

- TypeForge **sadece Linux/macOS** ELF ve Windows PE binary'lerini analiz eder.
  macOS Mach-O destegi Ghidra'nin Mach-O destegiyle sinirlidir.
- Ghidra headless her binary icin **10-120 saniye** kuruyor (otomatik analiz).
  Batch modda bunu amortize etmek icin karadul batch pipeline kullanin.
- TypeForge akademik prototipidir (S&P 2025): buyuk production binary'lerde
  yanlis pozitif struct gelebilir. `typeforge_min_confidence: 0.85` eşigi
  dusuk kaliteli sonuclari filtreler.
- LLM-assisted faz (TypeForge Phase 2) bu sprint'te entegre edilmedi;
  Phase 1 (Ghidra struct tahmini) yeterli.

---

## Test

```bash
# Sadece TypeForge testleri (kurulu degilse skip)
pytest tests/test_typeforge_adapter_integration.py -x --tb=short -v

# Mock'lu birim testleri (TypeForge kurulu olmadan calisir)
pytest tests/test_typeforge_adapter.py -x --tb=short -v
```
