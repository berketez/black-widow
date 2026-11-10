# Karadul Hızlı Başlangıç

Karadul (Black Widow), Ghidra'nın decompile çıktısını işleyen bir araştırma
hattıdır: fonksiyon ve değişken adı önerir, bazı tipleri kurtarmaya çalışır,
yorum ekler, rapor yazar. LLM ya da ML modeli kullanmaz. İsim kalitesinin
bugünkü ölçümü için depo kökündeki `README.md` dosyasının "Status" bölümüne
bakın; çıktıya güvenmeden önce okuyun.

Bu sayfa tek bir ikilinin analizini başlatmak için gereken en kısa yolu
anlatır. Buradaki her komut ve seçenek, CLI'ın kendi ayrıştırıcısıyla sınanır
(`tests/test_surum_oncesi_hatalar.py`).

## Kurulum

Gerekenler:

- Python 3.11 ya da daha yenisi.
- Yerel (native) ikililer için Ghidra 12.1.2. Sabitlenen sürüm budur
  (`karadul/config.py` içinde `GHIDRA_PINNED_VERSION`); başka sürümler uyarıyla
  kullanılır.
- Ghidra sürümünüzün desteklediği bir JDK.

```bash
git clone https://github.com/berketez/black-widow.git
cd black-widow
python -m venv .venv && source .venv/bin/activate

# Yerel ikililer: Ghidra köprüsü + ikili ayrıştırma + LMDB imza veritabanı desteği
pip install -e ".[ghidra,binary,perf]"

# Ghidra'nın yeri (yoksa birkaç yaygın konum ve PATH aranır)
export GHIDRA_INSTALL_DIR=/path/to/ghidra_12.1.2_PUBLIC
```

Yalnız `pip install -e .` komutu CLI'ı ve bütün aşamaların içe aktarılması
için gereken paketleri kurar; Ghidra köprüsü (`pyghidra`) ve ikili ayrıştırma
kütüphaneleri (`capstone`, `lief`) eklerle gelir. Eklerin tam listesi
`pyproject.toml` içindedir.

## İlk analiz: CLI

```bash
karadul --help
karadul analyze --help

# Yalnız tanıma: tür, dil, boyut, SHA-256 (Ghidra gerekmez)
karadul info /path/to/binary

# Tam hat: identify -> static (Ghidra) -> dynamic (--dynamic yoksa atlanır)
#          -> deobfuscate -> reconstruct -> report
karadul analyze /path/to/binary

# Aynısı; ayrıca temiz bir çıktı dizini yazar
karadul analyze /path/to/binary --output ./out

# Belirli bir aşamadan sonra dur (burada: Ghidra decompile'dan sonra)
karadul analyze /path/to/binary --stage static

# Makine tarafından okunur özet (stdout'ta yalnız JSON); --output ile birlikte verilebilir
karadul analyze /path/to/binary --json --output ./out

# Önceki analizler ve etkin yapılandırma
karadul list
karadul config show
karadul config validate
```

Bilinmesi gerekenler:

- `karadul analyze`, bulunduğunuz dizinde `./workspaces/` altına bir çalışma
  alanı yazar. `--output-dir DIR` bunu `DIR/workspaces/` altına taşır.
  `--output DIR` ise ayrı bir şeydir: çalışma alanından üretilen temiz çıktı
  dizinidir.
- Uzantısız bir dosya terminalden analiz edilirken "hesaplama tabanlı
  kurtarma" açılsın mı diye sorulur. Soruyu atlamak için
  `--no-compute-recovery` ya da `--compute-recovery` verin; `--json` ile ve
  terminal olmayan ortamda soru sorulmaz, kapalı sayılır.
- Ağ erişimi varsayılan olarak kapalıdır. `--enable-network` (eş adı
  `--online`) açar.
- Hedef program varsayılan olarak çalıştırılmaz. `--dynamic`, hedefi Frida
  altında çalıştırır; yalnız güvendiğiniz ikililerde kullanın.

Çalışma alanı:

```text
workspaces/<hedef>/<UTC zaman damgası>/
  raw/            # hedef bilgisi, çıkarılan girdiler
  static/         # statik analiz çıktısı (Ghidra'nınki dahil)
  dynamic/        # Frida çıktısı (yalnız --dynamic ile)
  deobfuscated/
  reconstructed/  # yeniden adlandırılmış ve yorumlanmış kaynaklar, naming_map.json
  reports/        # rapor dosyaları, pipeline_result.json
```

`--output DIR` ile temiz çıktı:

```text
DIR/
  src/
  naming_map.json
  dependency_graph.json
  report.json
  report.html
  README.md
```

## Python API

`karadul.analyze()`, CLI ile aynı aşamaları aynı sırayla koşturur.

```python
import karadul

result = karadul.analyze("/path/to/binary")
print(result.summary())
print("Başarılı:", result.success)
print("Çalışma alanı:", result.workspace_path)

for name, stage in result.stages.items():
    print(f"  {name}: success={stage.success} skipped={stage.skipped}")

for name, path in result.get_all_artifacts().items():
    print(f"  - {name}: {path}")
```

Özel yapılandırma ve aşama alt kümesiyle:

```python
from pathlib import Path

from karadul import Config, analyze

# Yol bir Path nesnesi olmalı. Dosya yoksa ./karadul.yaml, o da yoksa
# varsayılan ayarlar kullanılır.
cfg = Config.load(Path("karadul.yaml"))
cfg.project_root = Path("/tmp/karadul-out")   # çalışma alanı: /tmp/karadul-out/workspaces/

result = analyze("/path/to/binary", config=cfg, stages=["identify", "static"])
```

Aşama adları: `identify`, `static`, `dynamic`, `deobfuscate`, `reconstruct`,
`report`. `identify` dışındaki her aşama `identify`'a bağlıdır; alt kümeye onu
da ekleyin. Tanınmayan adlar uyarıyla atlanır.

## CLI komutları

| Komut | Amaç |
|-------|------|
| `karadul analyze <hedef>` | Tam hat (tanıma, Ghidra, yeniden kurma, rapor) |
| `karadul info <hedef>` | Yalnız tanıma: tür, dil, boyut |
| `karadul list` | Analiz edilmiş hedefleri listeler |
| `karadul clean <hedef>` | Hedefin çalışma alanını siler (onay ister) |
| `karadul config show` / `validate` / `path` | `karadul.yaml` yapılandırması |
| `karadul score <dizin>` | Yeniden kurulmuş C dizini için okunabilirlik puanı |
| `karadul rtti <ikili>` | C++ RTTI ve vtable bilgisi (Itanium ABI) |
| `karadul diff <ikili1> <ikili2>` | İki ikili arasındaki fonksiyon farkları |
| `karadul benchmark <ikili>` | İsim haritasını sembol tablosuyla karşılaştırır |
| `karadul run <hedef>` | Yeniden kurulmuş JavaScript projesini çalıştırır (hedeften türetilmiş kod koşar) |

`karadul batch analyze`, `karadul/batch.py` içine yazılmış sabit hedef
yollarını analiz eder; başka bir makinede işe yaramaz.

## Sonraki adımlar

- `README.md`: durum, gereksinimler, bilinen sorunlar
- `docs/API.md`: API başvurusu
- `docs/ARCHITECTURE.md`: hat mimarisi
- `docs/adr/`: karar kayıtları (ADR)
