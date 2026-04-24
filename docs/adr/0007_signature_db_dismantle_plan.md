# ADR 0007: signature_db.py Dismantle Planı

**Durum:** Önerildi (2026-04-23)
**Karar verici:** Berke (nihai), Architect (plan sahibi)
**Önceki ADR'ler:** ADR-003 (LMDB sigdb), ADR-002 (Binary name recovery)
**İlgili sürümler:** v1.11.0 (aktif geliştirme) → v1.15 (hedef son durum)

---

## 1. Bağlam

### 1.1 Mevcut Durum (2026-04-23 itibarıyla)

`karadul/analyzers/signature_db.py` tek dosya, **10 450 LOC**, **96 adet `*_SIGNATURES` dict'i**, 3 dataclass, 2 modül-seviye platform filtre fonksiyonu, 1 `SignatureDB` koordinatör sınıfı (~1 415 LOC, 24 metod) içeriyor.

Dosya, v1.9.x dönemi boyunca "tek büyük register" olarak büyüdü. v1.11.0'da "sig_db Faz 2/3" kapsamında 5 kategori (kısmen) `karadul/analyzers/sigdb_builtin/` altındaki alt modüllere **taşındı (override pattern)**:

| Kategori | Entry | Modül | Durum |
|---|---|---|---|
| crypto | 621 | `sigdb_builtin/crypto.py` (755 LOC) | Override aktif, legacy dict in-place |
| compression | 214 | `sigdb_builtin/compression.py` (300 LOC) | Override aktif, legacy dict in-place |
| network | 340 | `sigdb_builtin/network.py` (454 LOC) | Override aktif, legacy dict in-place |
| pe_runtime | 246 | `sigdb_builtin/pe_runtime.py` (461 LOC) | Override aktif, legacy dict in-place |
| windows_gui | 566 | `sigdb_builtin/windows_gui.py` (694 LOC) | Override aktif, legacy dict in-place |
| **Toplam migrate** | **~1 987** | | — |

Kalan 16 alt modül iskelet (13 LOC her biri, sadece `SIGNATURES: dict = {}` stub) — yani **veri hâlâ `signature_db.py` içinde**. Override pattern legacy dict'i silmediği için dosya hiç küçülmedi.

### 1.2 Dismantle Hedefi Olan Kalan Kategoriler

`_load_builtin_signatures` içinde merge edilen 96 dict'in kategori bazlı dökümü (satır numaraları signature_db.py):

**Apple / macOS ailesi (11 dict):**
- `_MACOS_SYSTEM_SIGNATURES` (L299) — libdispatch, libSystem
- `_MACOS_NETWORKING_SIGNATURES` (L2655)
- `_IPC_XPC_SIGNATURES` (L2713)
- `_APPLE_COREDATA_SIGNATURES` (L3345)
- `_APPLE_WEBKIT_SIGNATURES` (L3369)
- `_APPLE_CORELOCATION_SIGNATURES` (L3390)
- `_APPLE_COREBLUETOOTH_SIGNATURES` (L3407)
- `_APPLE_STOREKIT_SIGNATURES` (L3426)
- `_APPLE_USERNOTIFICATIONS_SIGNATURES` (L3444)
- `_APPLE_NETWORK_FRAMEWORK_SIGNATURES` (L3463)
- `_APPLE_ENDPOINT_SECURITY_EXT_SIGNATURES` (L3510)
- `_APPLE_SYSTEMEXTENSIONS_SIGNATURES` (L3532)
- `_APPLE_APPKIT_SIGNATURES` (L3543)
- `_MACOS_EXT_SIGNATURES` (L7097)
- Not: Obj-C / Swift runtime bu dict'ler içinde dağınık (Grup D düzeltmesi `_MACOS_EXT` içinde).

**POSIX / Linux / libc ailesi (7 dict):**
- `_POSIX_FILE_IO_SIGNATURES` (L2051)
- `_PROCESS_SIGNATURES` (L2133)
- `_PTHREAD_SIGNATURES` (L2198)
- `_POSIX_NETWORKING_SIGNATURES` (L2459) — epoll, kqueue, socket
- `_LINUX_SYSCALL_SIGNATURES` (L4265)
- `_LINUX_SYSCALL_EXT_SIGNATURES` (L4533)
- `_LIBC_EXT_SIGNATURES` (L5628)

**C stdlib / standart servisler (5 dict):**
- `_MEMORY_SIGNATURES` (L2258)
- `_STRING_STDLIB_SIGNATURES` (L2304)
- `_TIME_SIGNATURES` (L2365)
- `_DYNLOAD_SIGNATURES` (L2398)
- `_ERROR_LOCALE_MISC_SIGNATURES` (L2421)

**Crypto detay (çoğu crypto.py override altında ama 3 dict legacy kalıntısı):**
- `_OPENSSL_SIGNATURES` (L664) — **override altında değil** (crypto.py'da `openssl_signatures` var mı doğrulanmalı)
- `_BORINGSSL_SIGNATURES` (L1050), `_LIBSODIUM_SIGNATURES` (L1092), `_MBEDTLS_SIGNATURES` (L1156), `_WINCRYPTO_SIGNATURES` (L1210) — muhtemelen crypto.py'da
- Not: Faz A başlangıcında her birinin override kapsamında olup olmadığı `_BUILTIN_CRYPTO_SIGNATURES.get(...)` çağrılarıyla doğrulanmalı.

**Network detay (mostly network.py override ama 4 dict var):**
- `_LIBCURL_SIGNATURES` (L1454), `_CARES_SIGNATURES` (L2512), `_NGHTTP2_SIGNATURES` (L2546), `_WEBSOCKET_SIGNATURES` (L2582), `_GRPC_SIGNATURES` (L2608), `_NETWORKING_EXT_SIGNATURES` (L5802)

**Kompresyon detay:**
- `_ZLIB_SIGNATURES` (L1280), `_BZIP2_SIGNATURES` (L1346), `_LZ4_SIGNATURES` (L1371), `_ZSTD_SIGNATURES` (L1404), `_COMPRESSION_EXT_SIGNATURES` (L6307) — compression.py override kapsamında

**Serileştirme / veritabanı / format (5 dict):**
- `_PROTOBUF_SIGNATURES` (L1529) — *özel: namespace'li isim*
- `_SQLITE_SIGNATURES` (L1658), `_DATABASE_EXT_SIGNATURES` (L5919)
- `_JSON_SIGNATURES` (L1812), `_XML_SIGNATURES` (L1939)
- `_SERIALIZATION_SIGNATURES` (L3880)

**C++ standart kütüphane & third-party (5 dict):**
- `_CPP_STL_SIGNATURES` (L2772)
- `_BOOST_SIGNATURES` (L3636), `_ABSEIL_SIGNATURES` (L3711), `_FOLLY_SIGNATURES` (L3770)
- `_LOGGING_SIGNATURES` (L3820), `_LOGGING_EXT_SIGNATURES` (L6469)

**Grafik / medya (7 dict):**
- `_OPENGL_METAL_GPU_SIGNATURES` (L2995)
- `_COREGRAPHICS_SIGNATURES` (L3060), `_COREIMAGE_COREML_SIGNATURES` (L3102)
- `_IMAGE_LIB_SIGNATURES` (L3120), `_AUDIO_SIGNATURES` (L3183)
- `_FFMPEG_SIGNATURES` (L3246), `_SDL2_SIGNATURES` (L3297)
- `_GRAPHICS_EXT_SIGNATURES` (L6527)

**Windows API (5 legacy dict, 3 stub):**
- `_WIN32_KERNEL32_SIGNATURES` (L3937), `_WIN32_WS2_32_SIGNATURES` (L4026)
- `_WIN32_ADVAPI32_SIGNATURES` (L4065), `_WIN32_USER32_GDI32_SIGNATURES` (L4101)
- `_WIN32_NTDLL_SIGNATURES` (L4146), `_MSVC_CRT_SIGNATURES` (L4178 — artık `{}`, pe_runtime override altında)
- Stub'lar: `_WIN32_USER32_SIGNATURES`, `_WIN32_ADVAPI32_FULL_SIGNATURES`, `_WIN32_GDI32_SIGNATURES` (windows_gui override altında)
- `_WIN32_EXT_SIGNATURES` (L4797)

**Modern diller / runtime (6 dict):**
- `_RUST_STDLIB_SIGNATURES` (L4335), `_RUST_EXT_SIGNATURES` (L5238)
- `_GO_RUNTIME_SIGNATURES` (L4441), `_GO_EXT_SIGNATURES` (L5353)
- `_PYTHON_CAPI_SIGNATURES` (L6033), `_JAVA_JNI_SIGNATURES` (L6135)
- `_DOTNET_CLR_SIGNATURES` (L6195)

**Scripting / dynamic (4 dict):**
- `_V8_NODE_SIGNATURES` (L6649), `_LUA_SIGNATURES` (L6734), `_RUBY_SIGNATURES` (L6794)

**Event loop / regex / math / UI / misc (8 dict):**
- `_LIBUV_SIGNATURES` (L7852), `_LIBEVENT_SIGNATURES` (L7944)
- `_REGEX_SIGNATURES` (L7981), `_ICU_SIGNATURES` (L8007)
- `_MATH_SIGNATURES` (L8056), `_QT_SIGNATURES` (L8145)
- `_TESTING_SIGNATURES` (L8171), `_MISC_SIGNATURES` (L8188)

**Özel amaç (5 dict):**
- `_ANTI_ANALYSIS_SIGNATURES` (L6269) — packer/AV
- `_MSGQUEUE_SIGNATURES` (L6833), `_ML_COMPUTE_SIGNATURES` (L6910), `_GAME_ENGINE_SIGNATURES` (L7002)
- `_MEGA_BATCH_1_SIGNATURES` (L7225), `_MEGA_BATCH_2_SIGNATURES` (L7577) — karma

**String/call bazlı pattern'ler (2 koleksiyon, dismantle Faz C'ye bağlı):**
- `_STRING_REFERENCE_SIGNATURES` (L8242) — `frozenset[str] -> tuple`
- `_CALL_PATTERN_SIGNATURES` (L8570) — `list[tuple]`

### 1.3 Platform Filtre Katmanı

`signature_db.py` L192-L272:
- `_PE_ONLY_LIBS`, `_MACHO_ONLY_LIBS`, `_ELF_ONLY_LIBS` (frozenset)
- `_PE_ONLY_CATEGORY_PREFIXES`, `_MACHO_ONLY_CATEGORY_PREFIXES`, `_ELF_ONLY_CATEGORY_PREFIXES`
- `_is_platform_compatible(lib, category, target_platform, platforms)`
- `_infer_platform_from_filename(filename)`

Bu katman test tarafında **doğrudan public API** gibi kullanılıyor: `tests/test_v180_platform_filter.py` ve `tests/test_v192_fixes.py` `_infer_platform_from_filename`'ı import ediyor. Yani extract sırasında `signature_db.py`'da public re-export tutulmalı.

### 1.4 Match Logic Katmanı

`SignatureDB` sınıfı içinde (L9035-L10450):
- `_load_builtin_signatures` (L9155)
- `_load_findcrypt_constants` (L9305)
- `_load_external_auto` (L9363)
- `_match_by_symbol` (L9526), `_match_by_bytes` (L9667), `_match_by_strings` (L9786), `_match_by_calls` (L9866)
- `match_function` (L9935), `match_all` (L10009)
- `load_external_signatures`, `load_flirt_signatures`
- Class-level: `_full_cache` (shared), `_lmdb_backend`

Match logic 1 415 LOC. Tests onlarca testte doğrudan `SignatureDB()` çağırıyor (20+ test dosyası). Bu yüzden **match logic extract kapsam dışı, sadece veri dismantle yapıyoruz**.

### 1.5 Problem İfadesi

1. **10 450 LOC tek dosya okunamaz** (Hex-Rays'in `decompiler.cpp`'sinden 2 kat büyük).
2. Override pattern işini gördü ama **legacy dict silinmedi**, dosya küçülmedi.
3. Her kategoriye yeni entry ekleme iki yerde değişiklik gerektiriyor (builtin modül + override'ı bozmayacak şekilde).
4. PR diff'leri anlamsızca büyük — 10K+ satırlık dosyada 20 satırlık değişiklik görünmez oluyor.
5. Test suite'i `SignatureDB` sınıfına sıkı bağlı, match logic'i ayıramıyoruz ama veri katmanını ayırabiliriz.

---

## 2. Karar

Dismantle **4 faz** halinde, **v1.11.0 → v1.15** yaklaşık 5 sürüm penceresinde yapılacak. Her faz kendi içinde **identity parity + coverage parity + match parity** testleriyle kilitlenecek.

Faz sırası:

- **Faz A** — Veri dismantle (kalan 16 kategori alt modül + legacy dict silme).
- **Faz B** — Platform filtre katmanı extract (`_platform_filter.py`).
- **Faz C** — Match logic extract (`sigdb_match.py`) — **isteğe bağlı, riskli**.
- **Faz D** — `signature_db.py` final slim (~500 LOC hedef).

**Temel pattern ilke:** "önce override, sonra silme" — her alt modül migrate edildikten sonra **1 sürüm boyunca** legacy dict in-place kalır (deprecation warning ile), **bir sonraki sürümde silinir**. Bu, rollback'i 1 import değişikliğine indirir.

---

## 3. Faz A — Kalan Kategori Migrasyon (v1.11.0-rc → v1.12)

### 3.1 Amaç

Şu an `signature_db.py` içinde duran **91 dict'i** (96 toplam - 5 migrate edilmiş) kategori bazlı alt modüllere taşımak. Her alt modül `SIGNATURES: dict[str, dict[str, dict[str, str]]]` export eder; signature_db.py `try: from ... import SIGNATURES as _BUILTIN_X_SIGNATURES` pattern'iyle override eder.

### 3.2 Migrasyon Paketleri

Her paket ~200-600 entry hedef, 1 faz = 1 PR = 1 migrasyon testi.

| Faz | Hedef modül | Kaynak dict'ler | Tahmini entry | Sürüm |
|---|---|---|---|---|
| A1 | `sigdb_builtin/posix_system.py` | POSIX_FILE_IO, PROCESS, PTHREAD, MEMORY, STRING_STDLIB, TIME, DYNLOAD, ERROR_LOCALE_MISC | ~600 | v1.11.0-rc |
| A2 | `sigdb_builtin/linux_system.py` | LINUX_SYSCALL, LINUX_SYSCALL_EXT, LIBC_EXT, POSIX_NETWORKING | ~700 | v1.11.0-rc |
| A3 | `sigdb_builtin/macos_apple.py` | MACOS_SYSTEM, MACOS_NETWORKING, IPC_XPC, 10× APPLE_*, MACOS_EXT | ~800 | v1.11.0-rc |
| A4 | `sigdb_builtin/windows_api.py` (genişletme) | WIN32_KERNEL32, WS2_32, NTDLL, WIN32_EXT (mevcut override ile birleştir) | ~500 | v1.11.0 |
| A5 | `sigdb_builtin/runtimes.py` | RUST_STDLIB, RUST_EXT, GO_RUNTIME, GO_EXT, PYTHON_CAPI, JAVA_JNI, DOTNET_CLR | ~700 | v1.11.0 |
| A6 | `sigdb_builtin/languages.py` | V8_NODE, LUA, RUBY | ~200 | v1.11.0 |
| A7 | `sigdb_builtin/database.py` | SQLITE, DATABASE_EXT, PROTOBUF, JSON, XML, SERIALIZATION | ~600 | v1.12 |
| A8 | `sigdb_builtin/graphics_media.py` | OPENGL_METAL_GPU, COREGRAPHICS, COREIMAGE_COREML, IMAGE_LIB, AUDIO, FFMPEG, SDL2, GRAPHICS_EXT | ~600 | v1.12 |
| A9 | `sigdb_builtin/event_utils.py` | LIBUV, LIBEVENT, REGEX, ICU, MATH, QT, TESTING, MISC, MSGQUEUE | ~500 | v1.12 |
| A10 | `sigdb_builtin/game_ml.py` | ML_COMPUTE, GAME_ENGINE, ANTI_ANALYSIS, MEGA_BATCH_1, MEGA_BATCH_2 | ~700 | v1.12 |
| A11 | `sigdb_builtin/logging.py` | LOGGING, LOGGING_EXT | ~150 | v1.12 |
| A12 | `sigdb_builtin/strings_module.py` | CPP_STL, BOOST, ABSEIL, FOLLY | ~400 | v1.12 |
| A13 | `sigdb_builtin/calls.py` | STRING_REFERENCE, CALL_PATTERN (özel yapı!) | ~150 | v1.12 |

**Toplam hedef:** ~6 000 entry, 13 alt modül, signature_db.py veri bölümü **~6 500 LOC azalma** (10 450 → ~3 800).

### 3.3 Migrasyon Prosedürü (Her Faz A-N İçin)

1. **Kaynak oku, taşı:** İlgili dict'leri signature_db.py'dan al, hedef modüle `SIGNATURES = {"<dict_adı>": {...}}` şeklinde kopyala.
2. **Override block ekle:** signature_db.py'nın sonunda (ya da legacy dict'lerin hemen ardında) crypto/network pattern'iyle aynı `try/except ImportError` override bloğu ekle.
3. **Legacy dict'e `# DEPRECATED — kaldırılacak: vX.Y` yorumu ekle** (silinmiyor henüz).
4. **Parity testi yaz:** `tests/test_sigdb_<alan>_migration.py`
   - `test_identity_parity`: her taşınan dict'in her key'i için `lib, purpose, category` alanları eşleşmeli.
   - `test_coverage_count`: `len(migrated) == len(legacy)`.
   - `test_no_duplicate_keys`: paket içi key çakışması yok.
5. **Full suite run:** `pytest tests/ -x --tb=short` — 3 500+ test PASS olmalı.
6. **SignatureDB init benchmark:** `_full_cache` hit/miss timings ~%5 sapma içinde.
7. **PR commit mesajı:** `v<ver>: sig_db Faz A-N <alan> migration (<N> entry)` formatı (mevcut commit pattern'iyle uyumlu).

### 3.4 Silme Alt-Fazı (Faz A-DELETE, v1.13)

v1.11.0 + v1.12 sürümlerinde toplam 13 alt modül migrate tamamlandıktan **bir sürüm sonra** (v1.13):

1. Tüm `_*_SIGNATURES: dict[str, dict[str, str]] = { ... inline data ... }` blokları **silinir**.
2. Override try/except de silinir; onun yerine **doğrudan import** yapılır:
   ```
   from karadul.analyzers.sigdb_builtin.posix_system import SIGNATURES as _POSIX_SIGS
   _POSIX_FILE_IO_SIGNATURES = _POSIX_SIGS["posix_file_io"]
   ```
3. `_load_builtin_signatures` içindeki büyük tuple merge listesi daraltılır (tek büyük `for db in merged:` → tek `self._symbol_db.update(_merged_builtin_all())`).
4. Beklenen azalma: signature_db.py ~3 800 LOC → ~1 200 LOC (class + filter + 150 satır import/alias).

### 3.5 Faz A Giriş / Çıkış Kriterleri

**Giriş:** v1.11.0'daki 5 override bloğu çalışıyor, test suite yeşil.
**Çıkış (v1.12 sonu):** 13 yeni alt modül dosyası +/- tests, signature_db.py ≤ 3 800 LOC, 96 → 96 dict registered (hiçbiri kaybolmamış), full suite PASS, SignatureDB init < 1.5s (warm cache < 0.05s).

### 3.6 Faz A Riskleri

| Risk | Olasılık | Etki | Önlem |
|---|---|---|---|
| Identity parity kırılır (yazım hatası) | Orta | Yüksek (yanlış naming) | `test_identity_parity` (her entry için deep equal) |
| Key çakışması (iki modülde aynı fonksiyon adı) | Düşük | Orta (son update kazanır) | `test_no_duplicate_keys_across_modules` (A-DELETE öncesi) |
| Protobuf özel yol kırılır (namespace'li, `_` yok) | Düşük | Yüksek | Ayrı bir A7 içi test: `test_protobuf_namespace_preserved` |
| Mega batch karma içerikli, hangi modüle ait belli değil | Yüksek | Düşük | A10'da önce entry-by-entry grupla; gerekirse `sigdb_builtin/misc_batch.py` geçici modülü aç |
| LMDB cache stale (v1.9.x DB'leri kullanılmaya devam ediyor) | Orta | Orta | Release note: "LMDB cache'i regen edin" + `_load_findcrypt_constants` versiyon bump |

### 3.7 Faz A Rollback Stratejisi

- **Migrasyon anında hata:** PR revert. Override try/except zaten fallback içeriyor, legacy dict dokunulmadığı için import kırılırsa eski davranış döner.
- **Silme anında hata (v1.13):** v1.13 → v1.13.1 patch; silinen legacy dict'i geri yükle (git revert `_delete_legacy_dicts` commit).
- **LMDB stale:** `karadul sigdb rebuild` CLI komutu (ADR-003'teki rebuild pattern'i).

---

## 4. Faz B — Platform Filtre Katmanı Extract (v1.14)

### 4.1 Amaç

Platform filtre katmanını (`_is_platform_compatible`, `_infer_platform_from_filename`, 3 frozenset, 3 prefix tuple) `signature_db.py`'dan `karadul/analyzers/sigdb_builtin/_platform_filter.py`'a taşımak. signature_db.py sadece re-export tutar (backward compat için).

### 4.2 Hedef Dosya Yapısı

```
karadul/analyzers/sigdb_builtin/
├── _platform_filter.py          ← YENİ (~100 LOC)
│   ├── PE_ONLY_LIBS, MACHO_ONLY_LIBS, ELF_ONLY_LIBS
│   ├── PE_ONLY_CATEGORY_PREFIXES, ...
│   ├── is_platform_compatible(...)
│   └── infer_platform_from_filename(...)
├── __init__.py  ← re-export
```

`signature_db.py` top-level:
```
from karadul.analyzers.sigdb_builtin._platform_filter import (
    is_platform_compatible as _is_platform_compatible,
    infer_platform_from_filename as _infer_platform_from_filename,
    PE_ONLY_LIBS as _PE_ONLY_LIBS,
    # ...
)
```

### 4.3 Prosedür

1. Yeni dosya oluştur, fonksiyonları / sabitleri kopyala (leading underscore → public).
2. signature_db.py'da re-export alias'ları ekle (test'ler ve stages.py etkilenmesin).
3. Parity test: `tests/test_sigdb_platform_filter.py`
   - Her (platform, lib, category) kombinasyonu için eski ve yeni davranış AYNI.
   - Özellikle: `win32`, `libSystem`, `libdispatch`, `libc`, `libcrypto`, `libcurl` lib'leri × `pe/macho/elf` target × `None` target matrisi.
4. Full suite PASS, özellikle `test_v180_platform_filter.py` ve `test_v192_fixes.py` (bunlar `_infer_platform_from_filename` import ediyor).

### 4.4 Faz B Çıkış Kriterleri

- Yeni modül < 120 LOC.
- signature_db.py top-level 20-30 LOC azalma.
- Mevcut `from signature_db import _infer_platform_from_filename` çağrıları kırılmadı (alias korundu).

### 4.5 Faz B Riskleri

| Risk | Olasılık | Etki | Önlem |
|---|---|---|---|
| Private underscore name'e sıkı bağımlı test | Orta | Düşük | Alias stratejisi; direkt rename yok |
| Circular import (`_platform_filter` ↔ `signature_db`) | Düşük | Yüksek | `_platform_filter` saf veri + fonksiyon, hiçbir sigdb import'u YAPMAZ |

### 4.6 Rollback

Tek commit'lik değişim → git revert yeterli. Parity testi bozulursa CI yakalar.

---

## 5. Faz C — Match Logic Extract (v1.15, İSTEĞE BAĞLI)

### 5.1 Karar: Riskli, ertelenebilir

Match logic 1 415 LOC, 20+ test dosyasıyla sıkı bağlı. Bu fazı ertelemek **savunulabilir** — signature_db.py Faz A+B sonrası ~1 200 LOC'ya inerse zaten çoğunluğu class kodu olur, bu okunabilir.

**Öneri:** Faz C'yi Berke'nin v1.15 için onayına bırak. Faz A+B sonrası yeniden değerlendir.

### 5.2 Amaç (yapılırsa)

`match_function`, `match_all`, `_match_by_symbol`, `_match_by_bytes`, `_match_by_strings`, `_match_by_calls`'u `karadul/analyzers/sigdb_match.py`'a ayır. `SignatureDB` bunları delegate eder:

```
class SignatureDB:
    def match_function(self, fn_info, ...):
        from karadul.analyzers.sigdb_match import match_function
        return match_function(self, fn_info, ...)
```

### 5.3 Prosedür (yapılırsa)

1. Match fonksiyonlarını **serbest fonksiyon** olarak yeni dosyaya kopyala. İlk parametre `db: SignatureDB` ol.
2. `SignatureDB` metodları 1 satırlık delegate olsun.
3. Full suite PASS — özellikle:
   - `test_binary_reconstruction.py`
   - `test_flirt_parser.py`
   - `test_sigdb_lmdb.py`
   - `test_signature_db_empty_name.py`
4. Perf regresyon testi: `match_all` üzerinde 1000-fonksiyonluk sample binary — her biri < %3 sapma.

### 5.4 Faz C Riskleri (yapılırsa)

| Risk | Olasılık | Etki | Önlem |
|---|---|---|---|
| Class-level state (`_full_cache`, `_lmdb_backend`) delegate sırasında kaybolur | Orta | Yüksek | Serbest fonksiyon ilk param `db: SignatureDB` → class attr'lara erişim aynen korunur |
| Perf regresyon (extra dispatch) | Düşük | Düşük | Delegate overhead < 100ns/çağrı (ihmal) |
| Circular import (`sigdb_match` signature_db import eder, signature_db sigdb_match) | Yüksek | Yüksek | Function-level lazy import (`def match_function: from ... import ...`) |

### 5.5 Rollback

- Yeni dosyayı sil, SignatureDB metodlarını eski body'leriyle restore et. Git revert.

---

## 6. Faz D — signature_db.py Final Slim (v1.15 sonu)

### 6.1 Hedef Son Durum

Faz A + B (+ isteğe bağlı C) sonrası `signature_db.py` içeriği:

```
# Imports
# FunctionSignature dataclass (~25 LOC)
# SignatureMatch dataclass (~50 LOC)
# Re-export platform filter (~15 LOC)
# Re-export sigdb_match (opsiyonel, Faz C'deyse) (~10 LOC)
# class SignatureDB:
#   __init__, _init_lmdb_backend, _load_builtin_signatures (slim),
#   _load_findcrypt_constants, _load_external_auto,
#   add_* helpers,
#   matches_as_naming_map, stats, save_matches,
#   load_external_signatures, load_flirt_signatures
#   (veya tüm match_* metodları Faz C'de extract edildiyse 1-satırlık delegate)
```

### 6.2 LOC Hedefi

| Durum | LOC |
|---|---|
| Başlangıç (2026-04-23) | 10 450 |
| Faz A sonu (v1.12) | ~3 800 |
| Faz A-DELETE sonu (v1.13) | ~1 200 |
| Faz B sonu (v1.14) | ~1 150 |
| Faz C sonu (v1.15, opsiyonel) | ~500 |
| Faz C yapılmazsa final | ~1 150 |

**Nominal hedef:** 500 LOC (tüm fazlar).
**Kabul edilebilir:** 1 200 LOC (Faz A+B, Faz C ertelenirse).

### 6.3 Doğrulama

- `wc -l karadul/analyzers/signature_db.py` ≤ hedef.
- `grep -c "^_.*_SIGNATURES" karadul/analyzers/signature_db.py` == 0 (inline dict kalmamış).
- `pytest tests/ -x` → 3 500+ PASS (regresyon 0).
- SignatureDB cold init < 1.5s, warm init < 0.05s (benchmark baseline).
- Full binary reconstruction on sample binary: match sayısı identical (hash compare).

---

## 7. Parity Test Stratejisi (Tüm Fazlar İçin)

Her faz için **4 parity katmanı** zorunlu:

### 7.1 Identity Parity
Taşınan her entry için `lib`, `purpose`, `category` ve varsa `confidence`, `version` alanları **bit-bit eşit**. Test:
```
def test_identity_parity():
    for name, legacy in _LEGACY_DICT.items():
        assert MIGRATED[name] == legacy, f"drift: {name}"
```

### 7.2 Coverage Parity
`len(SignatureDB().all_signatures())` migrasyon öncesi ve sonrası **aynı sayı**. Test fixture: sürüm bump öncesi `pickle.dump(db._symbol_db)`, sonrası `pickle.load` + deep equal.

### 7.3 Match Parity
Sample binary (`tests/fixtures/sample_elf_stripped.bin` varsa; yoksa oluştur) için `match_all()` çıktısının **hash'i değişmesin**:
```
baseline_hash = "abc123..."  # commit öncesi hesaplandı
assert hash(json.dumps(db.match_all(fn_list), sort_keys=True)) == baseline_hash
```

### 7.4 Platform Filter Parity
Her (target_platform, lib, category) matrisi için `is_platform_compatible` çıktısı **eski ile aynı**. Tablo-güdümlü test: ~300 kombinasyon.

---

## 8. Sürüm Planı Özet

| Sürüm | Faz | Beklenen | Test çıkışı |
|---|---|---|---|
| v1.11.0 (şu an) | A1-A6 migrasyon (POSIX, Linux, macOS, WinAPI, runtimes, languages) | ~3 500 entry taşındı, override pattern | 3 500+ PASS |
| v1.12 | A7-A13 migrasyon (DB, graphics, event_utils, game_ml, logging, strings, calls) | Kalan ~2 500 entry taşındı | 3 500+ PASS |
| v1.13 | A-DELETE | Legacy dict'ler silinir, signature_db.py ~1 200 LOC | 3 500+ PASS |
| v1.14 | B | Platform filter extract | 3 500+ PASS |
| v1.15 | C (opsiyonel) + D | Match logic extract + final slim (≤ 500 LOC) | 3 500+ PASS, perf ±3% |

Roadmap uyumu: v1.11 → v1.20.5 ana roadmap'te dismantle mevcut fazları **paralel yürür**; ayrı PR akışı, yeni feature eklemeyi bloke etmez (override pattern sayesinde).

---

## 9. Riskler (Genel)

| Risk | Olasılık | Etki | Önlem |
|---|---|---|---|
| 3 500+ test'in yavaşlaması (her faz -> full run) | Yüksek | Orta | `pytest -x --lf` ilk; sonra full; CI paralelleştirme (pytest-xdist) |
| Berke'nin kapsam genişletmesi (her fazda yeni kategori ekle) | Yüksek | Yüksek | Faz kilidi: her faz için entry listesi PR açılırken DONDURULUR |
| Codex / AI asistanın override pattern'i bozması (legacy dict'i yanlış silmesi) | Orta | Kritik | A-DELETE ayrı sürüm, PR review Berke+reviewer çift onay |
| Mega batch dict'lerin kategori ataması keyfi | Yüksek | Düşük | A10'da pre-analiz: her entry'nin lib/category alanına bakıp doğru modüle yönlendir; belirsiz olanlar `sigdb_builtin/misc.py` (geçici) |
| External FLIRT / LMDB DB schema drift | Düşük | Kritik | `_load_findcrypt_constants` içindeki schema_version arttır, DB rebuild zorla |
| Naming convention tutarsızlığı (builtin modüllerde `SIGNATURES = {...}` vs farklı) | Orta | Düşük | Mevcut 5 modülün pattern'iyle zorunlu uyum (architect review) |

---

## 10. Açık Sorular (Berke Kararı Gerekli)

1. **Faz A sırası:** A1-A6 paralel PR'lar mı (hızlı ama merge conflict), yoksa seri mi (yavaş ama temiz)? Öneri: **seri**, her faz 2-3 gün.
2. **A-DELETE zamanlaması:** v1.13'e atlayalım mı, yoksa v1.12 sonu da olabilir mi? Öneri: **v1.13**, 1 sürüm koruma band'ı.
3. **Faz C yapılacak mı:** 1 415 LOC match logic extract değer mi, yoksa 1 200 LOC'da kalalım mı? Öneri: **v1.15 başında karar ver**, Faz A+B sonrası okunabilirlik değerlendir.
4. **LMDB schema bump:** Migrasyonla birlikte yapılsın mı, yoksa ayrı? Öneri: **ayrı** (ADR-003 scope).
5. **Yeni alt modül isimleri:** `sigdb_builtin/` içindeki 16 stub dosya mevcut iskelet isimlendirmesiyle uyumlu (Faz A tablosunda korundu). Ek isim değişikliği **yok**.

---

## 11. Onay

- [ ] Berke onayı
- [ ] Reviewer incelemesi
- [ ] Tester parity test strateji kabulü

Plan kabul edilirse Faz A1 (POSIX system) ilk PR açılır.
