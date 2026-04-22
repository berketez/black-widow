# Signature DB Split / Lazy Loading Planı (v1.12.0)

Dosya: `karadul/analyzers/signature_db.py`
Plan tarihi: 2026-04-22
Hazırlayan: Architect agent (plan only, kod yok)
Hedef sürüm: v1.12.0 (Phase 2 hot-path #1)

---

## 1. Yönetici Özeti — KRİTİK BULGU

**LMDB backend ZATEN VAR.** v1.10.0 M1 T1 ile `karadul/analyzers/sigdb_lmdb.py` (824 satır) ve `scripts/build_sig_lmdb.py` (598 satır) implemente edilmiş. Feature flag `config.perf.use_lmdb_sigdb` (default `False`) ile çalışıyor. Fallback path test edilmiş (`test_sigdb_lmdb_fallback.py`).

**Sonuç:** v1.10.0 roadmap'te yazan "JSON lazy split, 104 dict → `karadul/resources/signatures/*.json`" planı LMDB çalışması ile **yarı yarıya gereksiz**. JSON split paralel bir yol açmak demektir; bu da **üç backend** (dict + LMDB + JSON) bakımı gerektirir.

**Önerilen yaklaşım — JSON'dan vazgeç, LMDB'yi default'a taşı:**

| Alternatif | RAM | Cold start | Bakım | Karar |
|-----------|-----|-----------|-------|-------|
| Status quo (dict) | 3 GB | 1.3 s (sonra 0.01 s cache) | Python kodu | Bırakıyoruz |
| JSON split + LRU | ~250 MB | ~200 ms ilk, sonra cache | JSON + loader + cache | **REDDEDİLDİ** |
| LMDB default | <250 MB | <50 ms | Zaten var, build script var | **SEÇİLDİ** |

JSON split yaklaşımının LMDB'ye karşı **hiçbir üstünlüğü yok**: hem daha yavaş (dict parse > mmap), hem daha fazla RAM (deserialize edilen JSON object), hem daha çok kod.

Bu plan artık **iki ayaklı:**
- **Ana iş (v1.12.0):** LMDB'yi default'a çekmek, dict'leri source-of-truth olmaktan çıkarmak.
- **Yedek (v1.12.0-alpha opsiyonel):** Dict'leri per-kategori modüllere **ayırmak** (JSON değil, `.py` modül). Böylece LMDB build girdisi olarak kalırlar ama tek 10K LOC dosya ortadan kalkar.

---

## 2. Durum Analizi

### 2.1 Dosya ölçümleri

| Metrik | Değer |
|--------|-------|
| Toplam satır | 10,242 |
| Toplam byte | 828,410 (809 KB) |
| Sınıf sayısı | 3 (`FunctionSignature`, `SignatureMatch`, `SignatureDB`) |
| Top-level `_XXX_SIGNATURES` dict | 81 |
| Top-level liste/diğer (`_STRING_REFERENCE_SIGNATURES`, `_CALL_PATTERN_SIGNATURES`, `_FINDCRYPT_CONSTANTS`) | 3 |
| Platform filtresi frozenset'leri (`_PE_ONLY_LIBS` vb.) | 6 |
| Toplam entry (tahmini, 82 dict ölçülen) | ~6,500 — docstring 10,000+ iddia ediyor (MEGA_BATCH_1/2 ve WIN32_EXT entry sayıları dahil edilirse yaklaşır) |

### 2.2 RAM footprint (docstring iddiası: 3 GB)

Gerçek ölçülmeli (halüsinasyon riski). 10K dict entry × ~200 B ≈ 2 MB "saf" data; 3 GB iddiası şunlardan gelebilir:

- Class-level `_full_cache` dict — key=project_root, her değer tüm symbol_db'nin shallow copy'si. Çok proje root'lu test suite'inde N× çoğalır.
- Import sırasında compile edilen 10K AST node.
- `msgspec`/`ujson`/`lmdb` bağımlılıkları varsa mmap cache.

**Aksiyon:** Migration öncesi `tracemalloc`+`memory_profiler` ile baseline ölç. "3 GB" iddiası doğrulanmadan hedef "300 MB" olamaz.

### 2.3 Mevcut LMDB backend (hazır)

Dosya: `karadul/analyzers/sigdb_lmdb.py`

- 5 named DB: `symbols`, `string_sigs`, `call_sigs`, `byte_sigs`, `meta`
- msgpack serialization
- blake3/blake2b hash key'leri (string ve call imzaları için)
- L1 cache: OrderedDict LRU (varsayılan 8192 entry, configurable `perf.lmdb_l1_cache_size`)
- L2: OS page cache (mmap)
- Graceful fallback: `lmdb` paketi yoksa veya dosya yoksa dict path'e düşer
- Version hash ile idempotent build (`scripts/build_sig_lmdb.py`)

### 2.4 Public API surface

**Dışa açık (korunacak):**
- `SignatureDB` (tüm metodları)
- `FunctionSignature` (dataclass)
- `SignatureMatch` (dataclass)
- `_infer_platform_from_filename` (bir test tarafından import ediliyor: `test_v192_fixes.py`)

**İç (özgürce değişebilir):**
- Tüm `_XXX_SIGNATURES` dict'leri — `grep` sonuçlarına göre `signature_db.py` dışında kullanılmıyor.

Bu izolasyon migration'ı büyük ölçüde basitleştiriyor: iç reorganizasyon dışarı sızmıyor.

---

## 3. Taksonomi

Docstring'deki kategori bilgisi (her dict entry'sindeki `category` field'ı) migration için hazır. 82 dict aşağıda 10 kategori altında gruplandı:

| # | Kategori | Dict sayısı | Entry (tahmini) | Temsilciler |
|---|----------|-------------|-----------------|-------------|
| 1 | **crypto** | 6 | ~630 | `_OPENSSL`, `_BORINGSSL`, `_LIBSODIUM`, `_MBEDTLS`, `_WINCRYPTO`, `_FINDCRYPT_CONSTANTS` (byte pattern) |
| 2 | **compression** | 5 | ~280 | `_ZLIB`, `_BZIP2`, `_LZ4`, `_ZSTD`, `_COMPRESSION_EXT` |
| 3 | **network / transport** | 10 | ~500 | `_LIBCURL`, `_POSIX_NETWORKING`, `_CARES`, `_NGHTTP2`, `_WEBSOCKET`, `_GRPC`, `_MACOS_NETWORKING`, `_APPLE_NETWORK_FRAMEWORK`, `_NETWORKING_EXT`, `_WIN32_WS2_32` |
| 4 | **database / storage** | 3 | ~290 | `_SQLITE`, `_DATABASE_EXT`, `_APPLE_COREDATA` |
| 5 | **serialization / parsing** | 5 | ~500 | `_PROTOBUF`, `_JSON`, `_XML`, `_SERIALIZATION`, `_REGEX` |
| 6 | **system / POSIX / Win API** | 14 | ~1400 | `_POSIX_FILE_IO`, `_PROCESS`, `_PTHREAD`, `_MEMORY`, `_STRING_STDLIB`, `_TIME`, `_DYNLOAD`, `_ERROR_LOCALE_MISC`, `_IPC_XPC`, `_LINUX_SYSCALL`, `_LINUX_SYSCALL_EXT`, `_WIN32_KERNEL32`, `_WIN32_ADVAPI32`, `_WIN32_USER32_GDI32`, `_WIN32_NTDLL`, `_WIN32_EXT`, `_MSGQUEUE` |
| 7 | **macOS / Apple frameworks** | 12 | ~1100 | `_MACOS_SYSTEM`, `_MACOS_EXT`, `_APPLE_*` (9 dict), `_COREGRAPHICS`, `_COREIMAGE_COREML` |
| 8 | **graphics / media / game** | 8 | ~750 | `_OPENGL_METAL_GPU`, `_IMAGE_LIB`, `_AUDIO`, `_FFMPEG`, `_SDL2`, `_GRAPHICS_EXT`, `_GAME_ENGINE`, `_ML_COMPUTE` |
| 9 | **language runtimes / STL** | 11 | ~1000 | `_CPP_STL`, `_BOOST`, `_ABSEIL`, `_FOLLY`, `_RUST_STDLIB`, `_RUST_EXT`, `_GO_RUNTIME`, `_GO_EXT`, `_PYTHON_CAPI`, `_JAVA_JNI`, `_DOTNET_CLR`, `_LUA`, `_RUBY`, `_V8_NODE`, `_LIBC_EXT` |
| 10 | **event loop / util / misc** | 8 | ~400 | `_LIBUV`, `_LIBEVENT`, `_ICU`, `_MATH`, `_QT`, `_TESTING`, `_LOGGING`, `_LOGGING_EXT`, `_ANTI_ANALYSIS`, `_MISC` |
| — | **meta: aggregators** | 3 | — | `_STRING_REFERENCE_SIGNATURES`, `_CALL_PATTERN_SIGNATURES` (multi-category, tek tutulacak), `_MEGA_BATCH_1/2` (dağıtılacak, bkz. §4.3) |

**Not:** `_MEGA_BATCH_1_SIGNATURES` ve `_MEGA_BATCH_2_SIGNATURES` kategori bazlı değil — içleri multi-section (Windows CRT, POSIX extended, C++ ABI, ...). Migration sırasında **section-by-section parçalanmalı** ve kategori isimlerine göre dağıtılmalı. Her entry'de zaten `category` field'ı var, bu otomatikleştirilebilir.

---

## 4. Hedef Yapı

### 4.1 Fiziksel dosya düzeni (v1.12.0 sonrası)

```
karadul/analyzers/
├── signature_db.py                  # ~500 satır: sadece API sınıfları + loader
├── sigdb_lmdb.py                    # değişmedi, 824 satır
└── sigdb_builtin/                   # YENİ — dict source-of-truth, her biri ~500-800 LOC
    ├── __init__.py                  # aggregator: ALL_BUILTIN_DICTS = (..., ...)
    ├── crypto.py                    # _OPENSSL + _BORINGSSL + _LIBSODIUM + _MBEDTLS + _WINCRYPTO
    ├── crypto_constants.py          # _FINDCRYPT_CONSTANTS (byte pattern)
    ├── compression.py               # _ZLIB + _BZIP2 + _LZ4 + _ZSTD + _COMPRESSION_EXT
    ├── network.py                   # 10 network dict
    ├── database.py                  # _SQLITE + _DATABASE_EXT + _APPLE_COREDATA
    ├── serialization.py             # _PROTOBUF + _JSON + _XML + _SERIALIZATION + _REGEX
    ├── posix_system.py              # _POSIX_*, _PTHREAD, _MEMORY, _STRING_STDLIB, _TIME, ...
    ├── linux_system.py              # _LINUX_SYSCALL + _LINUX_SYSCALL_EXT + _IPC_XPC + _MSGQUEUE
    ├── windows_api.py               # _WIN32_* dict'leri + _WIN32_EXT
    ├── macos_apple.py               # _MACOS_SYSTEM + _MACOS_EXT + _APPLE_*
    ├── graphics_media.py            # _OPENGL + _IMAGE + _AUDIO + _FFMPEG + _SDL2 + _GRAPHICS_EXT
    ├── languages.py                 # _CPP_STL + _BOOST + _ABSEIL + _FOLLY + _RUST + _GO + ...
    ├── runtimes.py                  # _PYTHON_CAPI + _JAVA_JNI + _DOTNET_CLR + _V8_NODE + _LUA + _RUBY
    ├── event_utils.py               # _LIBUV + _LIBEVENT + _ICU + _MATH + _QT + _TESTING + _MISC
    ├── game_ml.py                   # _GAME_ENGINE + _ML_COMPUTE + _ANTI_ANALYSIS
    ├── logging_.py                  # _LOGGING + _LOGGING_EXT
    ├── strings.py                   # _STRING_REFERENCE_SIGNATURES (tek)
    └── calls.py                     # _CALL_PATTERN_SIGNATURES (tek)
```

**Neden `.py` modül, JSON değil:**
1. JSON'da `frozenset` ve `bytes` doğrudan serialize edilemez. `_STRING_REFERENCE_SIGNATURES` key'i `frozenset[str]`, `_CALL_PATTERN_SIGNATURES` ilk elemanı da `frozenset`. JSON'a yazmak her query'de `frozenset(json_list)` dönüşümü demek — LMDB zaten msgpack+blake3 ile çözmüş durumda.
2. `.py` modül = type checker (mypy) ve IDE dostu. JSON = stringly-typed.
3. Static import = Python'un kendi bytecode cache'i (`__pycache__`), ayrı loader yazma ihtiyacı yok.
4. Git diff = satır bazlı okunur. Tek 10K LOC dosya ≠ 20× 500 LOC dosya.
5. LMDB build script'i `sigdb_builtin` modüllerini import edip serialize edecek — JSON intermediate adım fazla.

### 4.2 Runtime data path'i (v1.12.0)

```
                 ┌──────────────────────────────────────────┐
                 │  SignatureDB.__init__(config)            │
                 └──────────────────────────────────────────┘
                          │
          ┌───────────────┼───────────────┐
          │ use_lmdb_sigdb=True (default) │ False (legacy)
          ▼                               ▼
┌──────────────────────┐      ┌────────────────────────────┐
│ sigdb_lmdb.py        │      │ sigdb_builtin/*.py         │
│ mmap .lmdb dosyası   │      │ Python dict import (eager) │
│ L1 LRU (8K entry)    │      │ ALL_BUILTIN_DICTS merge    │
│ <250MB RSS           │      │ ~500MB-3GB RSS             │
└──────────────────────┘      └────────────────────────────┘
          │                               │
          └───────────────┬───────────────┘
                          ▼
                  Tek public API: SignatureDB.match_all(...)
```

### 4.3 `_MEGA_BATCH_*` dağıtım algoritması

`_MEGA_BATCH_1_SIGNATURES` (7034-7378) ve `_MEGA_BATCH_2_SIGNATURES` (7386-7658) entry sayısı büyük ve her entry'nin `category` field'ı var. Migration script'i (one-shot, kalıcı değil):

```text
for entry in MEGA_BATCH_1 | MEGA_BATCH_2:
    dest_module = CATEGORY_TO_MODULE[entry['category']]
    append_to_module(dest_module, entry)
    remove_from_mega_batch(entry)
```

`CATEGORY_TO_MODULE` mapping'i manuel tanımlanır (10 kategori × ~30 category string → 1 module). Script çıktısı PR'da review edilir, otomatik merge edilmez.

---

## 5. API Önerisi

Public yüzey **değişmiyor** (geriye dönük uyum şart). İç değişiklikler:

```python
# karadul/analyzers/signature_db.py (v1.12.0 sonrası, ~500 LOC)

from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from karadul.config import Config


@dataclass
class FunctionSignature: ...  # AYNI
@dataclass
class SignatureMatch: ...      # AYNI


class SignatureDB:
    """Public API aynı kalır. İç backend seçimi config'e göre."""

    _full_cache: dict[str, tuple[...]] = {}  # dict path için

    def __init__(self, config: Optional[Config] = None,
                 target_platform: str | None = None) -> None:
        self._config = config or Config()
        self._target_platform = target_platform
        self._byte_signatures: list[FunctionSignature] = []
        self._symbol_db: dict[str, dict[str, str]] = {}
        self._string_sigs: dict[frozenset[str], tuple[str, str, str]] = {}
        self._call_sigs: list[...] = []
        self._lmdb_backend: Any = None

        # --- YENİ: backend seçimi ---
        if self._should_use_lmdb():
            self._init_lmdb_backend()
            # LMDB aktifse symbol_db dict'i hiç doldurulmaz;
            # match_all LMDB backend'e delege eder
        else:
            self._load_builtin_signatures_from_modules()

        self._load_findcrypt_constants()

    def _should_use_lmdb(self) -> bool:
        """v1.12.0: default True if LMDB available + file exists; else False."""
        perf = getattr(self._config, "perf", None)
        explicit = getattr(perf, "use_lmdb_sigdb", None)
        if explicit is not None:
            return bool(explicit)
        # Auto-detect: v1.12.0'da default True
        from karadul.analyzers.sigdb_lmdb import is_lmdb_available, default_lmdb_path
        if not is_lmdb_available():
            return False
        return Path(default_lmdb_path()).exists()

    def _load_builtin_signatures_from_modules(self) -> None:
        """Legacy dict path — sigdb_builtin paketinden yükler."""
        from karadul.analyzers.sigdb_builtin import (
            ALL_SYMBOL_DICTS,    # tuple of dicts
            STRING_SIGNATURES,
            CALL_SIGNATURES,
        )
        cache_key = str(self._config.project_root)
        if cache_key in SignatureDB._full_cache:
            cached = SignatureDB._full_cache[cache_key]
            self._symbol_db = dict(cached[0])
            self._string_sigs = dict(cached[1])
            self._call_sigs = list(cached[2])
            return

        for db in ALL_SYMBOL_DICTS:
            self._symbol_db.update(db)
        self._string_sigs = dict(STRING_SIGNATURES)
        self._call_sigs = list(CALL_SIGNATURES)

        self._load_external_auto(target_platform=self._target_platform)

        SignatureDB._full_cache[cache_key] = (
            dict(self._symbol_db),
            dict(self._string_sigs),
            list(self._call_sigs),
        )

    # --- mevcut _load_findcrypt_constants, match_all, load_external_signatures
    # --- load_flirt_signatures, _load_external_auto, _load_json metotları AYNI kalır
```

### `sigdb_builtin/__init__.py` önerisi

```python
"""Builtin signature dictionaries — per-category modules."""

from karadul.analyzers.sigdb_builtin.crypto import (
    OPENSSL, BORINGSSL, LIBSODIUM, MBEDTLS, WINCRYPTO,
)
from karadul.analyzers.sigdb_builtin.compression import (
    ZLIB, BZIP2, LZ4, ZSTD, COMPRESSION_EXT,
)
# ... diğer modüller

ALL_SYMBOL_DICTS: tuple[dict[str, dict[str, str]], ...] = (
    # crypto
    OPENSSL, BORINGSSL, LIBSODIUM, MBEDTLS, WINCRYPTO,
    # compression
    ZLIB, BZIP2, LZ4, ZSTD, COMPRESSION_EXT,
    # ... toplam ~80 dict
)

from karadul.analyzers.sigdb_builtin.strings import STRING_SIGNATURES
from karadul.analyzers.sigdb_builtin.calls import CALL_SIGNATURES

# Platform filtresi (mevcut _PE_ONLY_LIBS vb. bunlarla kalır)
from karadul.analyzers.sigdb_builtin._platform import (
    PE_ONLY_LIBS, MACHO_ONLY_LIBS, ELF_ONLY_LIBS,
    PE_ONLY_CATEGORY_PREFIXES, MACHO_ONLY_CATEGORY_PREFIXES,
    ELF_ONLY_CATEGORY_PREFIXES,
)
```

**Not:** Dict isimlerinden `_` prefix kaldırılmasını öneriyorum (`_OPENSSL_SIGNATURES` → `OPENSSL`), çünkü artık modül-private değiller, paket-private'lar. Suffix `_SIGNATURES` gereksiz tekrar — modül adı (`crypto.py`) zaten context veriyor.

---

## 6. Migration Stratejisi

### 6.1 Sürüm aşamaları

| Sürüm | Yapılan | Breaking? |
|-------|---------|-----------|
| **v1.11.x** (mevcut) | Her şey status quo, LMDB default False | — |
| **v1.12.0-alpha** | `sigdb_builtin/` paketi oluşturulur; `signature_db.py` içindeki dict'ler **kopyalanıp** modüllere taşınır; `signature_db.py` dict'leri `sigdb_builtin`'den re-export eder (geçici alias) | Hayır |
| **v1.12.0-beta** | `signature_db.py` içindeki dict tanımları tamamen silinir; sadece re-export kalır. `scripts/build_sig_lmdb.py` yeni modüllerden okuyacak şekilde güncellenir | Hayır (public API aynı) |
| **v1.12.0** | LMDB default `True` (auto-detect ile). İlk açılışta `~/.karadul/signatures.lmdb` yoksa uyarı + fallback + otomatik build önerisi | Hayır (graceful fallback) |
| **v1.13.0** | `signature_db.py`'deki dict re-export alias'ları kaldırılır. `from karadul.analyzers.signature_db import _OPENSSL_SIGNATURES` artık ImportError | **EVET, minor** (ama dış consumer yok — audit doğruladı) |
| **v1.14.0** (opsiyonel) | Legacy dict path kaldırılır. Sadece LMDB. Bu radikal — şu an önerilmiyor. | Major |

### 6.2 Geri dönüş (rollback) planı

- **Aşama 1 (1.12.0-alpha):** `sigdb_builtin/` ve `signature_db.py` aynı anda var, dict tanımları her ikisinde duplicate. Geri dönüş = `sigdb_builtin/` paketini silip import'ları kaldırmak. Tek commit revert.
- **Aşama 2 (1.12.0-beta):** Dict tanımları sadece `sigdb_builtin/`'de. Geri dönüş = git revert + `signature_db.py`'yi eski haline getir.
- **Aşama 3 (1.12.0 LMDB default):** Feature flag zaten var. `config.perf.use_lmdb_sigdb = False` set edilirse eski yol çalışır. Rollback config değişikliği.

### 6.3 Dict taşıma script'i (bir kerelik)

`scripts/migrate_signature_db_split.py` (yazılacak, plan içinde değil):

- Input: `karadul/analyzers/signature_db.py`
- AST-based:
  1. `ast.parse` ile dosyayı oku.
  2. `_XXX_SIGNATURES` assignment'larını bul.
  3. Her assignment'ı **değeri değiştirmeden** string olarak çıkar (`ast.get_source_segment`).
  4. Category mapping tablosuna göre doğru `sigdb_builtin/<category>.py` dosyasına append.
  5. `_MEGA_BATCH_*` için entry-by-entry dağıtım (her entry'nin `category` field'ına bak).
- Output: Yeni modül dosyaları + `signature_db.py`'den temizlenmiş versiyon.
- Doğrulama: Script sonrası `pytest tests/test_binary_reconstruction.py test_sigdb_lmdb.py test_signature_db_empty_name.py test_v180_platform_filter.py test_v192_fixes.py` geçmeli.

### 6.4 Commit sıralaması (v1.12.0-alpha sprint)

1. `sigdb_builtin/` iskelet (boş modüller + `__init__.py`)
2. `_platform.py` — platform filtresi taşı (en küçük, düşük risk)
3. Tek kategori taşıma — örn: `compression.py` (5 dict, ~280 entry). Testler geçiyor mu?
4. Sıradaki kategoriler (crypto, database, serialization, ...)
5. MEGA_BATCH dağıtımı (en riskli — ayrı PR)
6. `signature_db.py` re-export cleanup
7. LMDB default `True` flip (ayrı PR, kolay revert)

---

## 7. Risk Matrisi

| # | Risk | Önem | Olasılık | Mitigation |
|---|------|------|----------|-----------|
| 1 | MEGA_BATCH dağıtımında entry kaybı (script bug) | Yüksek | Orta | Taşıma öncesi/sonrası `len(ALL_SYMBOL_DICTS flatten)` eşit mi hash-check; her entry'nin unique symbol_name'i var mı audit |
| 2 | Dict formatında gizli heterojenlik (bazı entry'lerde param veya version field'ı vb.) | Orta | Orta | AST parse sırasında her value'nun keys'lerini topla, mismatch varsa raporla |
| 3 | `_STRING_REFERENCE_SIGNATURES` key'i `frozenset[str]` — JSON yap(a)mayız | Yüksek | Kesin | **Zaten JSON'dan kaçınıyoruz**, `.py` modül kalıyor. LMDB'de blake hash key |
| 4 | Test suite'inde `from ... import _OPENSSL_SIGNATURES` varsa kırılır | Yüksek | Düşük | Audit yapıldı: tek consumer `signature_db.py` ve testler sadece `SignatureDB`/`FunctionSignature` kullanıyor. Bkz. §2.4 |
| 5 | LMDB auto-detect yanlış çalışır (mesela dosya var ama eski versiyon) | Yüksek | Orta | `meta` DB'deki version hash check. Uyumsuzsa fallback + build önerisi |
| 6 | LMDB build script yeni modül yapısını bilmez | Yüksek | Kesin | `scripts/build_sig_lmdb.py` migration'ın parçası olarak güncellenir (aynı PR) |
| 7 | Class-level `_full_cache` farklı path'lerde şişer | Düşük | Düşük | Mevcut davranış değişmiyor, LMDB'de cache zaten yok |
| 8 | Git diff anlamsız görünür (10K satır silinip 10K yeni dosyada görünür) | Düşük | Kesin | `git log --follow` yine çalışır; PR mesajında "mekanik taşıma, içerik değişmedi" |
| 9 | RAM 3 GB iddiası doğrulanmamış — hedef yanlış olabilir | Orta | Yüksek | Migration öncesi `tracemalloc` baseline zorunlu |
| 10 | CI build süresi artar (82 modül import) | Düşük | Düşük | Python bytecode cache + lazy attr ile toleranslı; ölç |
| 11 | Jython/PyGhidra scriptlerinin `_OPENSSL_SIGNATURES` gibi internal'a erişimi | Orta | Düşük | Gemini 3.1 uyarısı — `ghidra_scripts/` audit edildi, internal import yok (sadece subprocess) |
| 12 | LMDB binary artifact git'e girerse repo şişer | Yüksek | Orta | `~/.karadul/signatures.lmdb` user home'da; repo'da binary yok. CI'da build adımı |
| 13 | Tester/benchmark suite'i LMDB file oluşturmayı beklemiyor | Orta | Yüksek | `conftest.py`'de autouse fixture ile `use_lmdb_sigdb=False` zorla (mevcut test davranışı korunur), yeni LMDB testleri ayrı fixture |

---

## 8. Test Stratejisi

### 8.1 Mevcut testler (değişmemeli)

- `test_binary_reconstruction.py` — public API
- `test_signature_db_empty_name.py` — FunctionSignature edge case
- `test_sigdb_lmdb.py` — LMDB backend
- `test_sigdb_lmdb_fallback.py` — graceful degradation
- `test_sigdb_lmdb_longname.py`, `test_sigdb_lmdb_metadata.py`, `test_sigdb_lmdb_misc.py` — LMDB detayları
- `test_sig_params_bridge.py` — params bridge
- `test_v180_platform_filter.py` — `_infer_platform_from_filename`
- `test_v192_fixes.py` — v1.9.2 güvenlik fixleri
- `test_flirt_parser.py` — flirt entegrasyonu
- `test_computation_integration.py` — SignatureMatch
- `test_signature_fusion.py` — fusion layer

**Hepsi geçmeli, regression=0 şart.**

### 8.2 Yeni testler (v1.12.0-alpha)

1. `test_sigdb_builtin_coverage.py` — her kategori modülü en az 1 dict export ediyor mu
2. `test_sigdb_builtin_no_duplicates.py` — aynı symbol name iki dict'te olmamalı (mevcut olanlar için de tutuyor olmalı — baseline oluştur)
3. `test_sigdb_builtin_category_consistency.py` — her entry'nin `category` field'ı docstring kategorisiyle tutarlı mı (örn `crypto.py`'deki tüm entry'lerde `category in {"crypto", "crypto_asymmetric", ...}`)
4. `test_sigdb_builtin_parity.py` — `ALL_SYMBOL_DICTS` merge'i eski `_full_cache[cache_key][0]`'a bit-by-bit eşit mi (migration doğrulaması)
5. `test_sigdb_lmdb_build_from_modules.py` — `build_sig_lmdb.py` yeni modüllerden okuyup doğru LMDB üretiyor mu
6. `test_sigdb_lmdb_auto_detect.py` — `_should_use_lmdb` dosya var/yok durumlarında doğru seçim

### 8.3 Benchmark (Tester 04-22 raporuyla uyumlu)

- **Baseline (mevcut):** ilk `SignatureDB()` init süresi, RSS, `match_all` p50/p95 latency
- **Post-migration (dict path, v1.12.0-alpha):** aynı değerler, %5+ regresyon = hard fail
- **Post-migration (LMDB path, v1.12.0):** cold-start <100 ms, RSS <300 MB hedef, `match_all` p50/p95 eşit veya daha iyi

CI gate (Gemini 3.1 önerisi): `pytest --benchmark-autosave --benchmark-compare-fail=min:5%`

### 8.4 Integration testler (scope=full pipeline)

- `examples/simple_math` binary üzerinde full pipeline dict path ve LMDB path ile ayrı ayrı çalıştır, F1 ve recovery metriklerini karşılaştır. %1'den fazla fark = bug.

---

## 9. Zaman Tahmini

| Faz | İş | Süre | Paralel ajan sayısı |
|-----|----|------|---------------------|
| **Hazırlık** | `tracemalloc` baseline + dict audit + migration script iskelet | 0.5 gün | 1 (architect + developer 1) |
| **Taşıma 1** | `_platform.py` + `compression.py` + `crypto.py` + `database.py` + `serialization.py` (5 küçük kategori) | 1 gün | 1 (developer) |
| **Taşıma 2** | `posix_system.py` + `linux_system.py` + `windows_api.py` | 1 gün | 1 |
| **Taşıma 3** | `macos_apple.py` + `graphics_media.py` | 0.5 gün | 1 |
| **Taşıma 4** | `languages.py` + `runtimes.py` + `event_utils.py` + `game_ml.py` + `logging.py` + `strings.py` + `calls.py` | 1 gün | 1 |
| **MEGA_BATCH** | Entry-by-entry dağıtım + audit + parity testleri | 1.5 gün | 1 (dikkat gerektirir) |
| **LMDB wiring** | `build_sig_lmdb.py` güncelle + `_should_use_lmdb` + auto-detect + CI yapılandırma | 1 gün | 1 |
| **Testler** | 6 yeni test dosyası + benchmark baseline + integration | 1.5 gün | 1 (tester) |
| **Docs** | Migration guide + CHANGELOG + `docs/decompiler_backends.md` güncelleme + deprecation warning | 0.5 gün | 1 |
| **Buffer** | Regresyon fix + review iterasyonu | 1 gün | — |
| **TOPLAM** | | **~9.5 gün** (≈2 hafta, 1 full-time developer) | — |

**Gemini 3.1 uyarısı:** MAX 3 paralel ajan. Bu plan sıralı çalışmaya göre hesaplandı, paralel hızlandırma önerilmez (aynı import tree'ye yazıyor olacağız).

---

## 10. Açık Sorular

1. **LMDB dosyası nereden gelecek?** User'ın `~/.karadul/signatures.lmdb` build etmesi gerekiyor. Pip install sonrası otomatik build mı (yavaş install), yoksa release asset olarak CDN'den çekim mi? Karar: v1.12.0 release notes'ta manuel `python scripts/build_sig_lmdb.py` talimatı. v1.13.0'da auto-build on first use.
2. **3 GB RAM iddiası gerçek mi?** Migration öncesi ölç. Eğer 3 GB yanlışsa (örn gerçekten 500 MB), LMDB default'a geçmek 10× kazanç değil, 2× kazanç — bu durumda öncelik düşer.
3. **Test süresi regresyonu?** 82 modül import = N kat `conftest.py` warm-up. Ölçülmeli.
4. **BSim (Gemini önerisi — dark launch)** bu plana etki ediyor mu? Hayır, BSim signature_db'yi tüketir, içinde değil.
5. **Kategori modülü boyutları (<800 LOC target)** — `_MACOS_EXT_SIGNATURES` tek başına 755 satır. `macos_apple.py` hedefini aşabilir → `macos_apple_ext.py` ikinci dosya.

---

## 11. Karar Özeti (Architect görüşü)

**v1.10.0 roadmap'teki "JSON lazy split" kısmen geçersiz — LMDB backend zaten var ve daha iyi bir çözüm.**

**Önerilen plan:**
1. **Dict'leri kategori modüllerine ayır** (`.py`, JSON değil) — tek 10K LOC dosya yok olsun, source-of-truth yapısal kalsın.
2. **LMDB'yi default backend yap** (auto-detect + fallback ile) — RAM iddia edilen 3 GB → <300 MB hedefini LMDB çözer.
3. **JSON dosyası üretmeyi reddet** — hem `frozenset`/`bytes` deserialize sorunu var, hem LMDB'nin önünde gereksiz bir katman.

**Bu plan Gemini 3.1'in "hafta 1'de refaktör, yeni özellik yok" önerisiyle uyumlu.** Scope sıkı tutuldu: sadece signature_db iç reorganizasyonu + LMDB default flip, yeni feature eklenmiyor.

**Berke'nin onayı bekleniyor:** (a) JSON yaklaşımından vazgeçip `.py` modül + LMDB default yoluna gitmek kabul mü? (b) 9.5 gün sprint kabul mü? (c) v1.13.0'da eski dict yolunun tamamen kaldırılması yerine v1.14.0+'a ertelenmesi uygun mu?
