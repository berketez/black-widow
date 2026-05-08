# Binary Ninja Adapter (Karadul v1.14 Dalga 2 — experimental)

`karadul/analyzers/binaryninja_adapter.py`, Vector35'in ticari Binary Ninja
RE platformuna **opsiyonel** bir kopru saglar. Lisanssiz makinelerde
sessizce devre disi kalir, pipeline diger adimlarla calismaya devam eder.

> **Onemli:** Bu adapter v1.14 icin bir **release blocker degildir**.
> Headless Binary Ninja lisansi olan gelistiricilerin yerel makinelerinde
> deneysel olarak kullanmasi icindir; CI'da daima `is_available() == False`
> dondurur. Pipeline entegrasyonu v1.15'te planlanmaktadir.

## Lisans ve Maliyet

Binary Ninja kapali kaynaktir, kullanim icin Vector35'ten lisans alinmasi
gerekir. Kasim 2025 fiyatlandirmasi (referans):

| Surum | Fiyat | Headless | Notlar |
|-------|-------|----------|--------|
| Personal | ~$300 | Sinirli | Sahsi/akademik kullanim, 2 makine |
| Commercial | ~$4000 | Tam | Ticari kullanim, takim lisanslari |
| Enterprise | Iletisim | Tam + sunucu | Onsite lisans sunucusu |
| Student / Non-Commercial | ucretsiz/indirimli | yok | Basvuru gerekli |

Headless analiz (Python SDK) **Personal'da kisitli** olabilir; karadul
adapter'i headless modda calisir, dolayisiyla Personal lisansta entry-point
imzasinin kabul edildigini dogrulayin.

Resmi sayfa: <https://binary.ninja/purchase/>

## Kurulum (yerel makine)

`binaryninja` Python paketi **PyPI'de yoktur**. Lisansli kurulum dizinindeki
yardimci script ile aktif Python yorumlayicisina baglanir:

### macOS

```bash
# Binary Ninja'yi /Applications altina kurduktan sonra
"/Applications/Binary Ninja.app/Contents/Resources/scripts/install_api.py"
```

### Linux

```bash
python3 /opt/binaryninja/scripts/install_api.py
```

### Windows

```powershell
python "C:\Program Files\Vector35\BinaryNinja\scripts\install_api.py"
```

Script, `binaryninja` paketini site-packages'a `.pth` veya benzer bir
mekanizmayla baglar. Sonra:

```bash
python -c "import binaryninja; print(binaryninja.core_version())"
# Beklenen: '4.x.xxxx ...'
```

Karadul adapter'i bu noktadan itibaren `is_available() == True` doner.

## API Ozeti

```python
from pathlib import Path
from karadul.analyzers.binaryninja_adapter import BinaryNinjaAdapter

adapter = BinaryNinjaAdapter(Path("foo.exe"), timeout=600)

if not adapter.is_available():
    # Lisanssiz makine -- pipeline diger adimlarla devam eder
    print("Binary Ninja yok, atlaniyor.")
else:
    print("BN surumu:", adapter.get_version())
    result = adapter.extract_all()

    print(f"Arch: {result.arch} / Platform: {result.platform}")
    print(f"{len(result.functions)} fonksiyon, {len(result.types)} tip")
    print(f"Sure: {result.duration_ms:.1f} ms")

    for fn in result.functions[:10]:
        print(f"  {hex(fn.address)} {fn.name} ({fn.size}B)")

    for t in result.types[:10]:
        print(f"  [{t.kind}] {t.name} (size={t.size})")
```

### Dataclass'lar

- `BNFunction`: `name`, `address`, `size`, `return_type`, `parameters`,
  `is_thunk`, `is_imported`
- `BNType`: `name`, `kind` (`struct`/`union`/`enum`/`typedef`/`function`/
  `unknown`), `size`, `fields`, `raw`
- `BNResult`: `binary_path`, `functions`, `types`, `arch`, `platform`,
  `bv_summary` (`function_count`, `type_count`, `imported_function_count`,
  `thunk_count`, `entry_point` ...), `duration_ms`

### Tek tek metodlar

- `is_available() -> bool` — `binaryninja` modulu import edilebiliyor mu?
- `get_version() -> str | None` — `binaryninja.core_version()`; modul
  yoksa `None`.
- `extract_functions() -> list[BNFunction]` — sadece fonksiyon listesi.
- `extract_types() -> list[BNType]` — sadece tip listesi.
- `extract_all() -> BNResult` — fonksiyon + tip + meta + sure.

Modul yoksa **tum extract metodlari** `RuntimeError("binaryninja module not
available -- license required")` firlatir.

### API uyumlulugu

Adapter, BN 3.x ve 4.x icin iki farkli yukleme yolunu sirayla dener:

1. `binaryninja.load(path, update_analysis=True)` (yeni API).
2. `binaryninja.BinaryViewType.get_view_of_file(path)` + manual
   `update_analysis_and_wait()` (eski API).

Boylece kullanici tarafinda BN surum kontrolu yapmaya gerek yoktur.

## Test Stratejisi

`tests/test_binaryninja_adapter.py`, **CI dahil her ortamda hermetik**
calisir:

- `_try_import_binaryninja` fonksiyonu test mock noktasidir; testler bunu
  `monkeypatch.setattr` ile sahte modulle (`SimpleNamespace`) degistirir.
- Sahte `BinaryView`, `Function`, `Type`, `Member` siniflari (`tests/`
  icindeki `_FakeBinaryView` vb.) yalnizca adapter'in kullandigi
  attribute'lari saglar.
- 15 hermetik test PASS + 1 gercek binary smoke testi (binaryninja yoksa
  SKIP).

Test komutu:

```bash
pytest tests/test_binaryninja_adapter.py -v
```

## Karadul ile Entegrasyon Plani (v1.15)

Adapter v1.14'te **standalone** kalir; pipeline'a entegrasyon v1.15'in
ilk dalgasinda planlanmaktadir:

- Yeni dosya: `karadul/pipeline/steps/binaryninja_analysis.py` (stage)
  - Cikti: `binaryninja_functions.json`, `binaryninja_types.json`
  - Skip if `not adapter.is_available()` (TRex/PDB ile ayni kalip)
- TypeForge / Bayesian source olarak BN tipleri:
  - `BNType` -> TypeForge fusion girdisi (struct field offset/type'lari
    Bayesian onceliklendirmeye katki saglar; LLM yok, deterministik
    skor uyumu).
- Decompiler komplement:
  - BN MLIL/HLIL ciktilari karadul'un CTREE/decompile asamasiyla
    karsilastirilarak field-name kurtarma kalitesi olculur (validation;
    BN ground-truth degil, baska bir veri kaynagi).
- Performans:
  - BN headless analizi yavas (orta boy PE icin 30-120 sn). Pipeline
    stage'i `--enable-binaryninja` flag'iyla opsiyonel olmali.

## Alternatifler (mevcut)

| Arac | Karadul adapter | Lisans | Mevcut sürüm |
|------|-----------------|--------|--------------|
| Ghidra | `karadul/integrations/ghidra/...` | Apache 2.0 | yerleşik (zorunlu) |
| TRex | `karadul/analyzers/trex_adapter.py` | BSD-3 | v1.13 D3 |
| PDB (llvm-pdbutil) | `karadul/analyzers/pdb_parser.py` | Apache 2.0 | v1.14 D1 |
| **Binary Ninja** | `karadul/analyzers/binaryninja_adapter.py` | **ticari** | **v1.14 D2 (bu dalga)** |

Karadul felsefesi (LLM yok, deterministik, CPU-only) Binary Ninja
entegrasyonuyla uyumludur: BN bir **veri kaynagi** olarak kullanilir,
adlandirma/decompile sonuclari karadul'un kendi hesapsal
rekonstruksiyonunu gectigi/yenildigi anlama gelmez — sadece TypeForge
icin ek bir Bayesian kaynak ve validasyon paneli olur.

## Sorun Giderme

### `is_available() == False` ama Binary Ninja kuruldu

- Aktif Python yorumlayicisi BN'in baglandigi yorumlayici mi?
  ```bash
  which python  # karsilastir: install_api.py'nin baglandigi
  ```
- `python -c "import binaryninja"` direk hata veriyorsa lisans dosyasi
  bozulmus olabilir; BN'i bir kere GUI'de acin, sonra tekrar deneyin.

### `RuntimeError: binaryninja.load None dondu`

- Dosya yolu kontrol edin (`Path` resolve sonucunu loglayin).
- BN dosya formatini destekliyor mu? (BN'de `binaryninja.open_view(path)`
  ile manuel deneyin.)

### Headless lisans hatasi

- Personal lisans bazi headless ozelliklerini kisitlar; Vector35 destek
  ekibiyle dogrulayin.

---

**Yazar:** Karadul gelistirme takimi
**Tarih:** v1.14 Dalga 2 — 2026-05-09
**Durum:** experimental, pipeline entegrasyonu v1.15'te
