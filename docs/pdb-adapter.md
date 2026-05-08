# PDB Adapter — `llvm-pdbutil` ile PDB Symbol/Type Yükleyici

**Sürüm:** v1.14 Dalga 1
**Modül:** `karadul/analyzers/pdb_parser.py`
**Bağımlılık:** [`llvm-pdbutil`](https://llvm.org/docs/CommandGuide/llvm-pdbutil.html) (LLVM toolkit, Apache-2.0 + LLVM Exception)

## Neden `llvm-pdbutil`?

PDB (Microsoft Program Database) Windows debug sembol formatıdır. Karadul'da native bir parser **yoktur** ve eklenmesi planlanmamaktadır:

- `pdbparse` Python kütüphanesi 2018'den beri bakımsız, eski Microsoft formatına takılı.
- LLVM toolkit'inin `llvm-pdbutil` aracı upstream'de aktif bakımdadır, MSF v7 + CodeView TPI/IPI dahil tüm modern PDB özelliklerini destekler.
- LLVM PDB kodu `llvm/lib/DebugInfo/PDB` altında olgun ve test kapsamlı.

Pattern: TRex (`trex_adapter.py`) ve TypeForge (`typeforge_adapter.py`) ile aynı **subprocess izolasyon** yaklaşımı.

---

## Kurulum

### macOS (Homebrew)

```bash
brew install llvm
# Binary: /opt/homebrew/opt/llvm/bin/llvm-pdbutil  (Apple Silicon)
# Binary: /usr/local/opt/llvm/bin/llvm-pdbutil      (Intel Mac)
```

Adapter bu yolları **otomatik** tarar; ek konfigürasyon gerekmez.

### Linux (apt / dnf)

```bash
# Debian / Ubuntu
sudo apt install llvm

# Fedora / RHEL
sudo dnf install llvm
```

Çoğu dağıtım `llvm-pdbutil`'i `/usr/bin/llvm-pdbutil` olarak yerleştirir; PATH üzerinden bulunur.

### Windows

LLVM Windows kurulumunda `llvm-pdbutil.exe` mevcuttur; PATH'e ekleyin veya `--llvm-pdbutil` flag'ı ile yolu verin.

### Manuel Override

Otomatik tespit yetmiyorsa env var ile sabitleyin:

```bash
export KARADUL_LLVM_PDBUTIL=/path/to/llvm-pdbutil
```

---

## Yol Çözüm Önceliği

Adapter `llvm-pdbutil` binary'sini şu sırayla arar (ilk bulduğunu kullanır):

1. **Constructor argümanı:** `PDBAdapter(pdb_path, llvm_pdbutil_path=...)`
2. **Env var:** `KARADUL_LLVM_PDBUTIL`
3. **Homebrew lokasyonları:**
   - `/opt/homebrew/opt/llvm/bin/llvm-pdbutil`
   - `/usr/local/opt/llvm/bin/llvm-pdbutil`
   - `/home/linuxbrew/.linuxbrew/opt/llvm/bin/llvm-pdbutil`
4. **PATH:** `shutil.which("llvm-pdbutil")`

Hiçbiri bulunamazsa `is_available() == False`, `extract_*()` çağrıları `RuntimeError` fırlatır. Pipeline graceful skip yapar.

---

## API Özeti

```python
from pathlib import Path
from karadul.analyzers.pdb_parser import PDBAdapter, PDBResult

adapter = PDBAdapter(pdb_path=Path("foo.pdb"))

if not adapter.is_available():
    print("llvm-pdbutil yok, atla.")
else:
    print(adapter.get_version())          # "LLVM version 22.1.3"
    result: PDBResult = adapter.extract_all()
    for sym in result.symbols:
        print(sym.kind, sym.name, hex(sym.address or 0))
    for t in result.types:
        print(t.type_id, t.kind, t.name, t.size)
```

### Sonuç Yapıları

| Dataclass | Alanlar |
|-----------|---------|
| `PDBSymbol` | `name`, `address`, `size`, `section`, `kind`, `type_index` |
| `PDBType` | `type_id`, `kind`, `name`, `size`, `fields[]`, `raw` |
| `PDBResult` | `symbols`, `types`, `pdb_path`, `pdb_version`, `raw_stdout`, `return_code`, `duration_ms` |

`PDBSymbol.kind` değerleri:
- `function` — `S_GPROC32` / `S_LPROC32` / `S_GPROC32_ID`
- `global` — `S_GDATA32`
- `static` — `S_LDATA32`
- `thread` — `S_GTHREAD32` / `S_LTHREAD32`
- `public` — `S_PUB32` (linker-emitted, mangled name'li)
- `thunk` — `S_THUNK32`

`PDBType.kind` değerleri (LF_* normalize edilmiş):
- `Struct`, `Class`, `Union`, `Enum`
- `Procedure`, `MemberFunction`, `Pointer`, `Array`
- `FieldList`, `ArgList`, `Bitfield`, `Modifier`, ...

### `PDBType.fields` formatı

`LF_FIELDLIST` tipinde, içindeki `LF_MEMBER` kayıtları:

```python
[
    {"name": "m_x",   "type_id": 0x0074, "offset": 0},
    {"name": "m_y",   "type_id": 0x0074, "offset": 4},
    {"name": "m_buf", "type_id": 0x0075, "offset": 8},
]
```

Diğer tip kayıtlarında `fields` boş kalır.

---

## Çalışan Komutlar

Adapter altta şu komutları çağırır (PDB yolu sona eklenir):

| Yöntem | Komut |
|--------|-------|
| `extract_symbols()` | `llvm-pdbutil dump --symbols --globals --publics <pdb>` |
| `extract_types()` | `llvm-pdbutil dump --types --ids <pdb>` |
| `extract_all()` | `llvm-pdbutil dump --symbols --globals --publics --types --ids <pdb>` |
| `get_version()` | `llvm-pdbutil --version` |

Subprocess izolasyonu `_run_subprocess` üzerindendir; testler `monkeypatch` ile mock'lar.

---

## Pipeline Entegrasyonu (v1.15 Plan)

Bu adapter **sadece I/O sarıcısıdır**. Pipeline tarafı ayrı stage olarak v1.15'te eklenecek:

**Yeni dosya:** `karadul/pipeline/steps/pdb_symbol_recovery.py`

**Akış:**

1. **Input:** PDB yolu — CLI flag `--pdb foo.pdb` veya workspace metadata (`workspace.json` içinde `pdb_path` alanı).
2. **Availability gate:** `PDBAdapter(pdb_path).is_available()` — `False` ise sessizce skip, log'a yaz.
3. **Extract:** `adapter.extract_all()` → `PDBResult`.
4. **Output JSON dosyaları (atomic write — tmp → rename):**
   - `static/pdb_symbols.json` — `[{name, address, size, section, kind, type_index}, ...]`
   - `static/pdb_types.json` — `[{type_id, kind, name, size, fields}, ...]`
5. **Fusion (Bayesian source):**
   - PDB sembolleri **high-confidence prior** (gerçek isim).
   - sigdb / FLIRT / TRex sonuçları ile bayes posterior'da kombine edilir.
   - Çakışma kuralı: PDB ismi varsa diğer kaynaklar override edemez.

### CLI flag teklifi

```bash
karadul analyze foo.exe --pdb foo.pdb
```

Workspace JSON'a `pdb_metadata` bloğu eklenir:

```json
{
  "pdb_metadata": {
    "path": "foo.pdb",
    "version": "20000404",
    "symbol_count": 1234,
    "type_count": 567
  }
}
```

---

## Test ve CI

- **Hermetik testler:** Tüm adapter testleri subprocess mock'lu, gerçek binary gerektirmez (`tests/test_pdb_parser.py`).
- **Real-binary smoke:** `test_real_pdbutil_version_smoke` — `@pytest.mark.skipif` ile binary yoksa atlar; CI runner'larda Homebrew LLVM kurulu olmalı.
- **Format değişikliği koruması:** `parse_dump()` regex tabanlı; LLVM çıktı formatı değişirse parser'ı güncellemek yeterli, `_run_subprocess` mock testleri etkilenmez.

---

## Referanslar

- LLVM `llvm-pdbutil` man: https://llvm.org/docs/CommandGuide/llvm-pdbutil.html
- Microsoft PDB Format (Microsoft-PDB repo): https://github.com/microsoft/microsoft-pdb
- CodeView Symbol/Type Records: `llvm/include/llvm/DebugInfo/CodeView/SymbolRecord.h`
