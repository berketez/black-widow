# ADR 0008: signature_db.py Kalan Kategori Migrasyonu — Faz 9–N Planı

**Durum:** Önerildi (2026-04-26)
**Karar verici:** Berke (nihai), Architect (plan sahibi)
**Önceki ADR:** [ADR 0007 — signature_db.py Dismantle Planı](0007_signature_db_dismantle_plan.md) (2026-04-23)
**İlgili sürümler:** v1.12 (aktif geliştirme) → v1.15 (hedef son durum)
**Süperseder:** ADR 0007 §3 (Faz A) — bu doküman ölçülmüş gerçeklerle yeniden numaralandırıyor; ADR 0007 §4–§10 hâlâ geçerli.

---

## 1. Bağlam — 2026-04-26 ölçülmüş durum

ADR 0007 yazıldıktan (2026-04-23) sonra v1.11.0 Dalga 4–7 ve Faz 6–8 tamamlandı. Şu an `karadul/analyzers/signature_db.py` dosyasının **gerçek** anlık görüntüsü:

| Metrik | Değer |
|---|---|
| Toplam satır | **10 578 LOC** |
| `_*_SIGNATURES` dict tanımı (top-level) | **102** |
| Dolu (legacy verisi hâlâ in-place) | **92** |
| Boş `{}` (override edildi, legacy silindi) | **10** |
| Toplam dolu entry (üst seviye anahtar sayımı) | **~5 950** |
| Toplam dolu dict satır kütlesi (gövde) | **~7 040 LOC** |

Bu sayılar, 102 dict'in tam taranmasıyla (`{`/`}` derinlik dengelemesi + üst seviye `"key":` sayımı) elde edildi. ADR 0007'deki "96 dict" tahmini daha eski bir anlık görüntüye karşılık geliyordu; gerçek sayı 102 (+ Mega Batch ve EXT dict'leri ayrı sayıldığı için).

### 1.1 Tamamlanan override migrasyonları (8 modül)

`karadul/analyzers/sigdb_builtin/` altında **dolu** alt modüller (boyut + override hedefi):

| # | Alt modül | LOC | Override ettiği `_*_SIGNATURES` | Faz / sürüm |
|---|---|---:|---|---|
| 1 | `crypto.py` | 78 117 char (pilot) | `OPENSSL`, `BORINGSSL`, `LIBSODIUM`, `MBEDTLS`, `WINCRYPTO` | Faz 2, v1.11.0 |
| 2 | `compression.py` | 26 306 char | `ZLIB`, `BZIP2`, `LZ4`, `ZSTD`, `COMPRESSION_EXT` | Dalga 4 |
| 3 | `network.py` | 41 989 char | `LIBCURL`, `POSIX_NETWORKING`, `NGHTTP2`, `WEBSOCKET`, `MACOS_NETWORKING`, `APPLE_NETWORK_FRAMEWORK`, `NETWORKING_EXT` (+`CARES`, `GRPC` muhtemelen) | Dalga 5 |
| 4 | `pe_runtime.py` | 39 120 char | `WIN32_KERNEL32`, `WIN32_NTDLL`, `MSVC_CRT` | Dalga 5–6 |
| 5 | `windows_gui.py` | 67 389 char | `WIN32_USER32`, `WIN32_ADVAPI32_FULL`, `WIN32_GDI32`, `WIN32_USER32_GDI32`, `WIN32_ADVAPI32` (alias) | Dalga 7 |
| 6 | `apple_runtime.py` | 69 783 char | `APPLE_OBJC_RUNTIME`, `APPLE_SWIFT_RUNTIME`, `APPLE_COREFOUNDATION` | Faz 6 |
| 7 | `modern_runtime.py` | 53 970 char | `MODERN_RUST_RUNTIME`, `MODERN_GO_RUNTIME` (Rust + Go birleşik) | Faz 7 |
| 8 | `vm_runtime.py` | 52 584 char | `JAVA_JNI`, `PYTHON_CAPI` | Faz 8 |

**Önemli detay (override semantiği):** Migrasyon iki türlü gerçekleşmiş:

- **Tip A — yumuşak override:** Crypto, compression, network, vb. modüllerde legacy in-place dict **hâlâ duruyor**, override block runtime'da değişkeni `sigdb_builtin/*` içinden gelen dict ile *yeniden bağlıyor*. Yani `_OPENSSL_SIGNATURES` 329 entry'lik gövdesini hâlâ taşıyor (~378 LOC).
- **Tip B — sert override:** Apple ObjC/Swift/CoreFoundation, Modern Rust/Go, VM JNI/Python C API, PE/MSVC user32/advapi32/gdi32 dict'leri **`{}`** olarak boşaltılmış. Override import başarısız olursa o kategori boş döner — geriye dönük uyum kalmadı, ancak bu modüller v1.11.0'da yeni eklenmiş kategoriler olduğu için legacy yoktu.

Toplam **8 modül × ortalama 50 KB = ~400 KB sigdb_builtin/** verisi taşındı. Yine de signature_db.py **küçülmedi**, çünkü çoğunluk Tip A (yumuşak) override. Bu, ADR 0007 §3.4'te (A-DELETE, v1.13) ele alınan plan dahilindedir.

### 1.2 Kalan iş — kategori bazlı kalan dolu dict sayımı

Aşağıdaki tablo, `signature_db.py` içinde **hâlâ dolu** olan 92 dict'i Faz 9–N için planlanan hedef alt modüle göre gruplar.

#### Grup 1 — POSIX / libc / stdlib (8 dict, 247 entry, ~351 LOC)

| Dict | Entry | LOC | Hedef modül |
|---|---:|---:|---|
| `_POSIX_FILE_IO_SIGNATURES` (L2051) | 57 | 75 | `posix_system.py` |
| `_PROCESS_SIGNATURES` (L2133) | 40 | 58 | `posix_system.py` |
| `_PTHREAD_SIGNATURES` (L2198) | 37 | 53 | `posix_system.py` |
| `_MEMORY_SIGNATURES` (L2258) | 27 | 39 | `posix_system.py` |
| `_STRING_STDLIB_SIGNATURES` (L2304) | 42 | 54 | `posix_system.py` |
| `_TIME_SIGNATURES` (L2365) | 16 | 26 | `posix_system.py` |
| `_DYNLOAD_SIGNATURES` (L2398) | 10 | 16 | `posix_system.py` |
| `_ERROR_LOCALE_MISC_SIGNATURES` (L2421) | 18 | 30 | `posix_system.py` |

**Bağımlılık:** Yok. **Risk:** Düşük (saf POSIX, platform filtresi sade).

#### Grup 2 — Linux / glibc / kernel (3 dict, 399 entry, 481 LOC)

| Dict | Entry | LOC | Hedef modül |
|---|---:|---:|---|
| `_LINUX_SYSCALL_SIGNATURES` (L4358) | 36 | 60 | `linux_system.py` |
| `_LINUX_SYSCALL_EXT_SIGNATURES` (L4626) | 213 | 255 | `linux_system.py` |
| `_LIBC_EXT_SIGNATURES` (L5721) | 150 | 166 | `linux_system.py` |

**Bağımlılık:** Yok. **Risk:** Düşük. **Not:** ADR 0007'de `POSIX_NETWORKING` bu gruba alınmıştı, ancak network.py override'a girmiş durumda — düzeltildi.

#### Grup 3 — macOS / Apple framework verisi (12 dict, 696 entry, ~852 LOC)

| Dict | Entry | LOC | Hedef modül |
|---|---:|---:|---|
| `_MACOS_SYSTEM_SIGNATURES` (L299) | 310 | 358 | `macos_apple.py` |
| `_IPC_XPC_SIGNATURES` (L2713) | 51 | 52 | `macos_apple.py` |
| `_APPLE_COREDATA_SIGNATURES` (L3345) | 16 | 17 | `macos_apple.py` |
| `_APPLE_WEBKIT_SIGNATURES` (L3369) | 13 | 14 | `macos_apple.py` |
| `_APPLE_CORELOCATION_SIGNATURES` (L3390) | 9 | 10 | `macos_apple.py` |
| `_APPLE_COREBLUETOOTH_SIGNATURES` (L3407) | 11 | 12 | `macos_apple.py` |
| `_APPLE_STOREKIT_SIGNATURES` (L3426) | 10 | 11 | `macos_apple.py` |
| `_APPLE_USERNOTIFICATIONS_SIGNATURES` (L3444) | 11 | 12 | `macos_apple.py` |
| `_APPLE_ENDPOINT_SECURITY_EXT_SIGNATURES` (L3510) | 14 | 15 | `macos_apple.py` |
| `_APPLE_SYSTEMEXTENSIONS_SIGNATURES` (L3532) | 3 | 4 | `macos_apple.py` |
| `_APPLE_APPKIT_SIGNATURES` (L3543) | 77 | 86 | `macos_apple.py` |
| `_MACOS_EXT_SIGNATURES` (L7218) | 99 | 119 | `macos_apple.py` |

**Bağımlılık:** apple_runtime.py (ObjC/Swift) zaten taşındı. Bu grup **framework API verisi**, runtime metaclass'ları değil — net ayrım. **Risk:** Düşük-orta (12 küçük dict, hepsi tek modüle birleştirilebilir).

#### Grup 4 — Windows API geri kalanı (3 dict, 412 entry, 492 LOC)

| Dict | Entry | LOC | Hedef modül |
|---|---:|---:|---|
| `_WIN32_WS2_32_SIGNATURES` (L4026) | 19 | 31 | `windows_api.py` |
| `_WIN32_ADVAPI32_SIGNATURES` (L4065) | 20 | 28 | `windows_api.py` |
| `_WIN32_EXT_SIGNATURES` (L4890) | 373 | 433 | `windows_api.py` |

**Bağımlılık:** pe_runtime.py + windows_gui.py taşındı. Bu grup geriye kalan **kernel-mode dışı sistem servisleri**: WS2_32 = winsock, ADVAPI32 = registry/svc, WIN32_EXT = misc. **Risk:** Orta (`WIN32_EXT` 373 entry, kategorize edilirken yanlış lib ataması olasılığı).

#### Grup 5 — Modern dil ekleri (4 dict, 397 entry, 523 LOC)

| Dict | Entry | LOC | Hedef modül |
|---|---:|---:|---|
| `_RUST_STDLIB_SIGNATURES` (L4428) | 47 | 97 | `runtimes.py` (extension) |
| `_GO_RUNTIME_SIGNATURES` (L4534) | 53 | 83 | `runtimes.py` (extension) |
| `_RUST_EXT_SIGNATURES` (L5331) | 75 | 107 | `runtimes.py` (extension) |
| `_GO_EXT_SIGNATURES` (L5446) | 209 | 267 | `runtimes.py` (extension) |
| `_DOTNET_CLR_SIGNATURES` (L6288) | 58 | 66 | `runtimes.py` (extension) |

**Bağımlılık:** modern_runtime.py taşındı (sadece *runtime* kısmı — `MODERN_RUST_RUNTIME`, `MODERN_GO_RUNTIME`). Bu beş dict **stdlib + ext** → ayrı kategori, modern_runtime.py'ye eklenecek. **Risk:** Düşük (zaten net pattern). **Not:** .NET CLR ayrı bir VM ailesi ama logical olarak modern runtime'lara girer; `runtimes.py` artık genişler.

#### Grup 6 — Scripting dilleri (3 dict, 155 entry, 161 LOC)

| Dict | Entry | LOC | Hedef modül |
|---|---:|---:|---|
| `_V8_NODE_SIGNATURES` (L6770) | 73 | 77 | `languages.py` |
| `_LUA_SIGNATURES` (L6855) | 52 | 53 | `languages.py` |
| `_RUBY_SIGNATURES` (L6915) | 30 | 31 | `languages.py` |

**Bağımlılık:** Yok. **Risk:** Çok düşük (tek modül, 3 küçük dict).

#### Grup 7 — Veritabanı / serileştirme / format (6 dict, 581 entry, 617 LOC)

| Dict | Entry | LOC | Hedef modül |
|---|---:|---:|---|
| `_PROTOBUF_SIGNATURES` (L1529) | 87 | 91 | `serialization.py` |
| `_SQLITE_SIGNATURES` (L1658) | 145 | 147 | `database.py` |
| `_DATABASE_EXT_SIGNATURES` (L6012) | 96 | 106 | `database.py` |
| `_JSON_SIGNATURES` (L1812) | 116 | 120 | `serialization.py` |
| `_XML_SIGNATURES` (L1939) | 93 | 105 | `serialization.py` |
| `_SERIALIZATION_SIGNATURES` (L3880) | 44 | 48 | `serialization.py` |

**Bağımlılık:** Yok. **Risk:** Orta — `PROTOBUF` özel: namespace'li semboller, leading underscore yok, basename indeks (L1634 `_build_protobuf_basename_index`). Bu indeks fonksiyonu da serialization.py'a taşınabilir veya `signature_db.py`'da kalabilir (önerim: index fonksiyonu kalır, dict taşınır). **Karar:** `database.py` (SQLite tabanlı) ve `serialization.py` ayrı tutulur — concept ayrımı.

#### Grup 8 — Grafik / medya (8 dict, 362 entry, 415 LOC)

| Dict | Entry | LOC | Hedef modül |
|---|---:|---:|---|
| `_OPENGL_METAL_GPU_SIGNATURES` (L2995) | 57 | 58 | `graphics_media.py` |
| `_COREGRAPHICS_SIGNATURES` (L3060) | 34 | 35 | `graphics_media.py` |
| `_COREIMAGE_COREML_SIGNATURES` (L3102) | 10 | 11 | `graphics_media.py` |
| `_IMAGE_LIB_SIGNATURES` (L3120) | 51 | 56 | `graphics_media.py` |
| `_AUDIO_SIGNATURES` (L3183) | 45 | 56 | `graphics_media.py` |
| `_FFMPEG_SIGNATURES` (L3246) | 34 | 44 | `graphics_media.py` |
| `_SDL2_SIGNATURES` (L3297) | 31 | 41 | `graphics_media.py` |
| `_GRAPHICS_EXT_SIGNATURES` (L6648) | 100 | 114 | `graphics_media.py` |

**Bağımlılık:** Yok (CoreImage/CoreML Apple ailesinde değil, GPU ve grafik genel). **Risk:** Düşük. **Not:** `COREIMAGE_COREML` Apple-spesifik ama API'leri grafik domain'i; bu yüzden grafik altında.

#### Grup 9 — C++ stdlib + tier-1 third-party (4 dict, 193 entry, 379 LOC)

| Dict | Entry | LOC | Hedef modül |
|---|---:|---:|---|
| `_CPP_STL_SIGNATURES` (L2772) | 60 | 216 | `strings_module.py` (rename önerisi: `cpp_stdlib.py`) |
| `_BOOST_SIGNATURES` (L3636) | 58 | 68 | `strings_module.py` |
| `_ABSEIL_SIGNATURES` (L3711) | 43 | 52 | `strings_module.py` |
| `_FOLLY_SIGNATURES` (L3770) | 32 | 43 | `strings_module.py` |

**Bağımlılık:** Yok. **Risk:** Düşük-orta — `CPP_STL` 60 entry / 216 LOC oranı yüksek (uzun template imzaları, namespace'li). **Önerim:** `strings_module.py` ismi yanıltıcı; `cpp_stdlib.py` olarak yeniden isimlendir veya iskelet `strings_module.py`'a taşı (mevcut iskelet adlandırmayı koruyup içeriğini doldur — ADR 0007 §10.5 kararı korunur).

#### Grup 10 — Logging (2 dict, 83 entry, 103 LOC)

| Dict | Entry | LOC | Hedef modül |
|---|---:|---:|---|
| `_LOGGING_SIGNATURES` (L3820) | 45 | 53 | `logging.py` |
| `_LOGGING_EXT_SIGNATURES` (L6590) | 38 | 50 | `logging.py` |

**Bağımlılık:** Yok. **Risk:** Çok düşük.

#### Grup 11 — Event loop / regex / math / UI / misc (8 dict, 304 entry, 339 LOC)

| Dict | Entry | LOC | Hedef modül |
|---|---:|---:|---|
| `_LIBUV_SIGNATURES` (L7973) | 69 | 85 | `event_utils.py` |
| `_LIBEVENT_SIGNATURES` (L8065) | 29 | 30 | `event_utils.py` |
| `_REGEX_SIGNATURES` (L8102) | 18 | 19 | `event_utils.py` |
| `_ICU_SIGNATURES` (L8128) | 41 | 42 | `event_utils.py` |
| `_MATH_SIGNATURES` (L8177) | 77 | 82 | `event_utils.py` |
| `_QT_SIGNATURES` (L8266) | 16 | 17 | `event_utils.py` |
| `_TESTING_SIGNATURES` (L8292) | 9 | 10 | `event_utils.py` |
| `_MISC_SIGNATURES` (L8309) | 44 | 45 | `event_utils.py` |

**Bağımlılık:** Yok. **Risk:** Orta — modül adı (`event_utils`) içerikle sınırlı uyumlu; tek alternatif iki modüle bölmek (`event_runtime.py` + `text_utils.py`), ancak küçük dict'leri parçalamak fayda/maliyet kötüleşir. **Karar:** mevcut iskelete sığsın, daha sonra rename mümkün.

#### Grup 12 — Game engine / ML compute / IPC queue (3 dict, 208 entry, 240 LOC)

| Dict | Entry | LOC | Hedef modül |
|---|---:|---:|---|
| `_MSGQUEUE_SIGNATURES` (L6954) | 61 | 69 | `game_ml.py` (alt grup: messaging) |
| `_ML_COMPUTE_SIGNATURES` (L7031) | 74 | 84 | `game_ml.py` |
| `_GAME_ENGINE_SIGNATURES` (L7123) | 73 | 87 | `game_ml.py` |

**Bağımlılık:** Yok. **Risk:** Düşük. **Not:** `MSGQUEUE` aslında messaging; iskelet adı `game_ml.py` zorlama. Mevcut iskeleti koruyalım, `MSGQUEUE` orada misafir.

#### Grup 13 — Anti-analiz / mega batch (3 dict, 603 entry, 646 LOC) ⚠️

| Dict | Entry | LOC | Hedef modül |
|---|---:|---:|---|
| `_ANTI_ANALYSIS_SIGNATURES` (L6362) | 14 | 30 | (ayrı: `anti_analysis.py` veya `game_ml.py`) |
| `_MEGA_BATCH_1_SIGNATURES` (L7346) | 329 | 344 | **MUHTEMELEN DAĞITILACAK** |
| `_MEGA_BATCH_2_SIGNATURES` (L7698) | 260 | 272 | **MUHTEMELEN DAĞITILACAK** |

**Bağımlılık:** Mega batch dict'leri karma içerik (ADR 0007 §3.6 risk satırı). Pre-analiz şart. **Risk:** YÜKSEK — 589 entry'nin her biri lib/category alanına bakılarak doğru gruba (POSIX, Linux, modern_runtime, vb.) yönlendirilecek; geçici `sigdb_builtin/misc_batch.py` modülü kabul edilebilir bir kaçış valfi.

#### Grup 14 — Crypto/network detay (legacy in-place dict'ler — Tip A override altında, hâlâ dolu)

Bu kategoriler **runtime'da override** edildi ama legacy dict gövdeleri silinmedi:

| Dict | Entry | LOC | Durum |
|---|---:|---:|---|
| `_OPENSSL_SIGNATURES` (L664) | 329 | 378 | crypto.py override |
| `_BORINGSSL`, `_LIBSODIUM`, `_MBEDTLS`, `_WINCRYPTO` | 166 | 170 | crypto.py override |
| `_ZLIB`, `_BZIP2`, `_LZ4`, `_ZSTD` | 142 | 146 | compression.py override |
| `_LIBCURL`, `_CARES`, `_NGHTTP2`, `_WEBSOCKET`, `_GRPC`, `_MACOS_NETWORKING`, `_POSIX_NETWORKING`, `_APPLE_NETWORK_FRAMEWORK`, `_NETWORKING_EXT` | 515 | 540 | network.py override |
| `_WIN32_KERNEL32`, `_WIN32_NTDLL`, `_COMPRESSION_EXT` | 134 | 192 | pe_runtime / compression override |
| **Toplam ~Tip A artığı** | ~1 286 | ~1 426 | **A-DELETE'te silinecek** |

Bu **~1 426 LOC**, ADR 0007 §3.4'ün A-DELETE adımı — Faz 9–N tamamlanınca tek seferlik temizlik commit'i olarak yapılır.

#### Grup 15 — Pattern bazlı koleksiyonlar (özel yapı)

| Dict | Entry | LOC | Hedef modül |
|---|---:|---:|---|
| `_STRING_REFERENCE_SIGNATURES` (L8363) | 0 (`frozenset[str] -> tuple` map, üst-anahtar sayımı 0 dönüyor; gerçek entry sayısı `len()` ile alınır) | 328 | `calls.py` |
| `_CALL_PATTERN_SIGNATURES` (L8691) | (`list[tuple[...]]`, ~satır sayısı = entry) | ~250 | `calls.py` |

**Bağımlılık:** Yok. **Risk:** ORTA-YÜKSEK — yapı `dict[frozenset[str], tuple]` (string ref) ve `list[tuple]` (call pattern). Standart `SIGNATURES = {"<dict>": dict}` pattern'i bunlara uymaz; `calls.py` modülü farklı export yapısı kullanmalı (ör. `STRING_REFS: dict[frozenset, tuple]` + `CALL_PATTERNS: list[tuple]`). Override pattern'i de farklılaşır (.get() yerine doğrudan re-bind).

### 1.3 Toplam yol haritası — sayım kapanışı

| Kategori grubu | Dict | Entry | LOC | Faz |
|---|---:|---:|---:|---|
| Grup 1 — POSIX | 8 | 247 | 351 | 9 |
| Grup 2 — Linux | 3 | 399 | 481 | 10 |
| Grup 3 — macOS framework | 12 | 696 | 852 | 11 |
| Grup 4 — Win32 (kalan) | 3 | 412 | 492 | 12 |
| Grup 5 — Modern dil ekleri | 5 | 442 | 620 | 13 |
| Grup 6 — Scripting | 3 | 155 | 161 | 14 |
| Grup 7 — DB / serialization | 6 | 581 | 617 | 15 |
| Grup 8 — Grafik / medya | 8 | 362 | 415 | 16 |
| Grup 9 — C++ stdlib | 4 | 193 | 379 | 17 |
| Grup 10 — Logging | 2 | 83 | 103 | 18 |
| Grup 11 — Event/regex/math | 8 | 304 | 339 | 19 |
| Grup 12 — Game/ML | 3 | 208 | 240 | 20 |
| Grup 13 — Anti-analiz / mega batch ⚠️ | 3 | 603 | 646 | 21 |
| Grup 14 — Tip A artığı (A-DELETE) | ~14 | ~1 286 | ~1 426 | 22 |
| Grup 15 — Pattern koleksiyonları | 2 | n/a | ~580 | 23 |
| **TOPLAM kalan iş** | **~84** | **~5 700+** | **~7 700 LOC** | Faz 9–23 |

Beklenen son durum (tüm grupların tamamlanması, A-DELETE dahil):

| Aşama | signature_db.py LOC |
|---|---:|
| Şu an (2026-04-26) | **10 578** |
| Grup 1–13 sonu (Faz 9–21, override edildi, legacy in-place) | ~10 578 (değişmez — Tip A pattern) |
| Grup 14 (A-DELETE, Faz 22) | **~3 200** (Tip A artığı silindi) |
| Grup 15 (pattern koleksiyon extract, Faz 23) | **~2 600** |
| Faz B (platform filter, ADR 0007 §4) | **~2 500** |
| Faz C (match logic extract, opsiyonel) | **~900** |

Berke'nin verdiği **≤1 000 LOC dispatcher hedefi**, Faz 9–23 + Faz B + (opsiyonel) Faz C tamamlanınca karşılanır. Faz C ertelenirse 2 500 LOC kabul edilebilir.

---

## 2. Karar — Faz 9–23 Sıralaması

### 2.1 Sıralama prensipleri

1. **Risk artan sırada:** Önce küçük + bağımsız (Logging, Scripting), sonra büyük + bağımsız (Linux, macOS), en son karma/karmaşık (Mega Batch).
2. **Bağımlılık tabanlı:** Apple framework'ü ObjC runtime'dan sonra (apple_runtime.py zaten yapıldı → §3 hazır).
3. **Dosya iskeletini yeniden kullan:** `sigdb_builtin/` altında 16 stub var (ADR 0007 §10.5). Yeni dosya açma; mevcut iskeletleri doldur.
4. **Entry sayısı yığma:** Her faz 100–700 entry hedef bandında; `MEGA_BATCH` gibi 600+ entry'lik karma içerik kendi başına bir faz.
5. **Test parite kuralı:** Her faz `tests/test_sigdb_<grup>_migration.py` getirir; identity + coverage + key uniqueness testi (ADR 0007 §7).

### 2.2 Önerilen sıra

| Faz | Grup | Hedef | Entry | LOC kazancı (override sonrası) | Risk |
|----|------|-------|------:|------:|---|
| **9** | Grup 10 | `logging.py` | 83 | 0 (Tip A, A-DELETE'te 103) | Çok düşük — pilot fazı, override pattern'i pekiştirmek için |
| **10** | Grup 6 | `languages.py` | 155 | 0 (161 A-DELETE) | Çok düşük |
| **11** | Grup 1 | `posix_system.py` | 247 | 0 (351 A-DELETE) | Düşük |
| **12** | Grup 11 | `event_utils.py` | 304 | 0 (339 A-DELETE) | Orta (8 dict tek modülde) |
| **13** | Grup 8 | `graphics_media.py` | 362 | 0 (415 A-DELETE) | Düşük |
| **14** | Grup 4 | `windows_api.py` | 412 | 0 (492 A-DELETE) | Orta (`WIN32_EXT` 373 entry) |
| **15** | Grup 2 | `linux_system.py` | 399 | 0 (481 A-DELETE) | Düşük |
| **16** | Grup 9 | `strings_module.py` (cpp_stdlib) | 193 | 0 (379 A-DELETE) | Orta (`CPP_STL` template) |
| **17** | Grup 12 | `game_ml.py` | 208 | 0 (240 A-DELETE) | Düşük |
| **18** | Grup 5 | `runtimes.py` (extension — modern_runtime ile birleşik tutulmaz, ayrı modül; isim alternatifi `runtime_extensions.py`) | 442 | 0 (620 A-DELETE) | Düşük-orta (.NET CLR ayrı VM ailesi) |
| **19** | Grup 7 | `database.py` + `serialization.py` (iki paralel PR) | 581 | 0 (617 A-DELETE) | Orta (`PROTOBUF` namespace) |
| **20** | Grup 3 | `macos_apple.py` | 696 | 0 (852 A-DELETE) | Orta (12 küçük framework dict) |
| **21** | Grup 13 ⚠️ | `mega_batch.py` (geçici) → entry-by-entry yeniden dağıtım | 603 | 0 (646 A-DELETE) | **YÜKSEK** — pre-analiz fazı (.5 alt-faz) |
| **22** | Grup 14 (A-DELETE) | Tüm Tip A artığını sil + `_load_builtin_signatures` slim et | — | **~1 426 LOC silinecek** | Orta (her override için identity parity yeniden çalıştırılır) |
| **23** | Grup 15 | `calls.py` — `STRING_REFERENCE` + `CALL_PATTERN` (özel yapı) | n/a | **~580 LOC silinecek** | Orta (özel export yapısı) |

### 2.3 Faz 21 — Mega Batch pre-analiz prosedürü

ADR 0007 §3.6 riski: Mega batch'lerin kategorize edilmesi keyfi.

**Önerilen yöntem:**

1. Her `MEGA_BATCH_1`/`MEGA_BATCH_2` entry'si için `entry["lib"]` ve `entry["category"]` alanlarına bak.
2. Lib → Grup haritası (deterministic):
   - `lib in {"libc", "glibc", "musl"}` → `posix_system.py`
   - `lib.startswith("CoreFoundation"), Foundation, AppKit` → `macos_apple.py`
   - `lib in {"kernel32", "ntdll", "user32", ...}` → `windows_api.py`
   - `lib in {"libc++", "libstdc++"}` → `strings_module.py`
   - `lib in {"OpenGL", "Metal", "Vulkan"}` → `graphics_media.py`
   - vb.
3. Belirsiz olanlar (lib alanı boş, jenerik) → `sigdb_builtin/misc_batch.py` (geçici depo).
4. Migrasyon test: `test_mega_batch_dispersal_coverage` — orijinal 589 entry'nin tamamı en az bir hedef modülde olmalı (eksik = fail).
5. v1.13'te `misc_batch.py` 0 entry'ye düşürülür (her entry doğru gruba taşındı).

### 2.4 Tip B sert override'a geçiş — Faz 22 (A-DELETE) detayı

Şu an 8 alt modülün 5'i (Tip A) legacy dict in-place tutuyor. A-DELETE adımı:

1. Her grup için legacy dict'i sil (signature_db.py'da).
2. Override block `try: from ... import SIGNATURES` aynen kalır, ancak `if _BUILTIN_X is not None:` kapısının altındaki `.get(name, _LEGACY_DICT)` artık `_LEGACY_DICT`'e başvuramaz → yerine `.get(name, {})` veya doğrudan `_X = _BUILTIN_X[name]` (KeyError = bug = sigdb_builtin eksik anahtar).
3. Identity parity testi A-DELETE öncesi commit'in pickle dump'ı ile karşılaştırma (ADR 0007 §7.2).
4. v1.12 sonu / v1.13 başı yapılır — Faz 9–21 tamamlanınca **tek commit**.

Beklenen tasarruf: **~7 700 LOC silinme** (toplam 92 dolu dict gövdesi + override block kaldırma).

---

## 3. Sonuçlar (Consequences)

### 3.1 Olumlu

- `signature_db.py` 10 578 → ~2 500 LOC (Faz 9–23 sonu, Faz B sonrası ~2 400). Faz C ile ≤1 000 hedef karşılanır.
- 17 alt modül × ortalama 600 LOC = ~10 200 LOC dağıtılmış, modüler, PR diff'leri okunabilir.
- Yeni signature eklemek tek dosyaya commit olur; signature_db.py'a dokunulmaz.
- LMDB cache ve match logic Faz A boyunca **dokunulmaz** — test suite stabil kalır.

### 3.2 Olumsuz

- Geçici durumda (Faz 9–21) signature_db.py LOC'u **artar** (override block her fazda +20 LOC). v1.13'te A-DELETE ile geri ödenir.
- 17 modülün isim seçimi mevcut iskeleti koruduğu için bazıları yanıltıcı (`event_utils.py` 8 farklı domain barındırıyor). Faz B sonrası rename PR'ı ayrı yapılabilir.
- `MEGA_BATCH` dağıtımı entry düzeyinde insan denetimi gerektirir — risk ADR 0007 §3.6'da kayıtlı.
- A-DELETE öncesi 1 sürüm boyunca legacy dict'ler korunmalı (rollback band'ı). Bu disiplin gerektirir.

### 3.3 Tarafsız (operasyonel)

- Her faz **1 PR + 1 migrasyon testi**. ADR 0007 §3.3 prosedürü aynen uygulanır.
- CI yükü her faz için ~3 500 test koşusu; pytest-xdist ile <5 dk hedef.
- `sigdb_builtin/__init__.py` her fazda yeni modülün re-export'unu eklenmeyebilir — modüller doğrudan `from karadul.analyzers.sigdb_builtin.X import SIGNATURES` ile çağrılır (mevcut pattern).

---

## 4. Alternatifler

### 4.1 Alt 1 — "Big bang" tek PR (reddedildi)

92 dict tek PR'da 17 modüle dağıtılır. **Sebebi reddedildi:** Code review imkânsız (10K+ satır diff), rollback granül değil, parity test risk konsantrasyonu.

### 4.2 Alt 2 — Match logic'i de aynı anda ayır (kapsam genişlemesi)

Faz 9 ile beraber match logic de ayrılır. **Sebebi reddedildi:** ADR 0007 §5'te zaten "Faz C opsiyonel, riskli, v1.15'e bırakılır" diye karar verilmiş. Veri dismantle ile match dismantle birleştirilirse 20+ test dosyası eş zamanlı kırılabilir.

### 4.3 Alt 3 — Tip A → Tip B'ye anında geçiş (yumuşak override yok)

Her migrasyon doğrudan legacy dict'i siler, fallback yok. **Sebebi reddedildi:** ADR 0007 §3.7 rollback stratejisi rolü. Tip A → Tip B 1 sürüm gecikme istisnasız iyi (rollback = 1 import değişikliği).

### 4.4 Alt 4 — Faz sayısını 7'ye düşür (gruplama agresif)

Grupları birleştir: POSIX+Linux, macOS+Apple framework hep, vb. **Sebebi reddedildi:** Her faz 1 PR ilkesi, PR boyutunu okunamaz hale getirir. Mevcut 15 faz (9–23) optimum.

---

## 5. Kabul Kriterleri (Faz 9–23 ortak)

- [ ] Her faz için identity parity testi mevcut ve PASS.
- [ ] Her faz için coverage parity testi (count eşitliği).
- [ ] Her faz için key uniqueness testi (paket içi).
- [ ] Full suite (`pytest tests/`) PASS — 4 187+ test (v1.11.0-beta baseline).
- [ ] mypy regresyon yok (signature_db.py mypy hata sayısı ≤ baseline).
- [ ] SignatureDB cold init < 1.5s, warm < 0.05s.
- [ ] PR commit mesajı format: `v<ver>: sig_db Faz <N> <grup> migration (<entry> entry)`.
- [ ] ADR 0008 §1.3 LOC tablosunun ilgili satırı güncellenir (her faz sonrası).

---

## 6. Tahmini Süre (Paralel Ajan ile)

Berke'nin paralel ajan limiti **7** (`feedback_parallel_agents.md`). Faz 9–23 = 15 faz.

Yaklaşık takvim:

| Aşama | Süre (paralel ajan) | Süre (tek ajan) |
|---|---|---|
| Faz 9–10 (pilot — küçük) | 1 gün (paralel iki PR) | 2 gün |
| Faz 11–17 (orta — bağımsız) | 3–4 gün (3 PR paralel × 2 dalga) | 7–10 gün |
| Faz 18–20 (büyük — orta risk) | 2–3 gün (her biri ayrı PR) | 5–6 gün |
| Faz 21 (mega batch ⚠️) | 1–2 gün (pre-analiz + dağıtım, paralel zor) | 1–2 gün |
| Faz 22 (A-DELETE) | 1 gün (tek commit, tüm parity'lerin yeniden) | 1 gün |
| Faz 23 (pattern koleksiyon) | 1 gün | 1 gün |
| **TOPLAM** | **~10 gün (1.5 hafta)** | **~17–22 gün (3 hafta)** |

Berke'nin v1.12 → v1.15 sürüm penceresi (~5 sürüm) bu takvimi rahatça karşılar. Paralel akış: developer ajanı migrasyon + tester ajanı parity test + reviewer ajanı identity check.

---

## 7. ADR 0007 ile Uyum

- **Korunan kısımlar:** §4 (Faz B platform filter), §5 (Faz C match logic), §6 (Faz D final slim), §7 (parity test stratejisi), §9 (genel riskler), §10 (açık sorular).
- **Güncellenen kısımlar:**
  - §1.1 sayım: 96 dict → 102 dict (gerçek + Mega Batch ayrımı).
  - §3 Faz A: 13 alt-faz → 13 grup (Faz 9–21), aynı pattern.
  - §3.4 A-DELETE: Faz 22 olarak yeniden numaralandırıldı.
- **Yeni:** Grup 15 (pattern koleksiyon, Faz 23) — ADR 0007'de §3'te listelenmişti ama numaralandırılmamıştı.

ADR 0008, ADR 0007'nin yerine geçmez; **§3'ünü ölçülmüş gerçeklerle yeniden numaralandırır**, geri kalan bölümleri ADR 0007'den okunmaya devam edilir.

---

## 8. Kararlar (Berke onayı 2026-04-26 — Codex danışmanlığı)

Aşağıdaki 5 madde **karar olarak çakılmıştır** (önceden açık soru idi). Codex önerisi B-A-B-A-B desenini izler — konservatif, görünürlük > atomiklik.

1. **Sıra onayı:** ✅ **B — §2.2'deki önerilen sıra korunur.** Mega Batch (Faz 21) ortaya alındı, sona değil. Pilot fazlar (9–10) override pattern'ini pekiştirmeden Mega Batch'in entry-level karar yağmuruna girmeyiz.
2. **Faz 18 isim:** ✅ **A — Yeni `runtimes.py` modülü açılır**, `modern_runtime.py` Rust/Go semantiğiyle dolu, .NET/Erlang/Elixir vb. ayrı dosyaya gider. ADR 0007 §10.5 "yeni isim yok" kuralı bu özel durum için **istisna kabul edildi**: semantic ayrım override pattern'inden daha güçlü. Berke onayı bu noktada karar vericidir.
3. **Faz 19 paralelizm:** ✅ **B — Seri yürütme.** `database.py` önce, `serialization.py` sonra. Sebep: aynı override block'a iki paralel ajan yazımı = merge conflict garanti. Hız kaybı kabul edilir, conflict riski elimine edilir.
4. **Faz 21 misc_batch.py kaderi:** ✅ **A — Tam silinir.** "Miscellaneous" kovası 6 ayda 500 entry'lik anti-pattern canavarına döner. Her entry deterministic bir gruba ait olmalı; sınıflandırılamayan varsa Faz 21 entry-level pre-analiz prosedüründe (§2.3) kategori önerisi üretilir.
5. **A-DELETE granülitesi (Faz 22):** ✅ **B — 13 logical block (her grup için ayrı commit).** ~7700 LOC tek commit blame/bisect'i öldürür. 13 commit, kategori başına izlenebilir blame, regresyon halinde tek grubu revert edebilme avantajı. PR yine tek olabilir, ama içindeki commit yapısı 13 ayrı commit halinde kalır.

---

## 9. Onay

- [x] **Berke onayı (2026-04-26)** — sıra + isim seçimleri + 5 karar onaylandı (Codex B-A-B-A-B danışmanlığıyla)
- [ ] Reviewer incelemesi (ADR 0007 ile uyum)
- [ ] Tester parity test strateji teyidi (ADR 0007 §7'den miras)

Plan kabul edildi. Faz 9 (Logging) ilk PR pilot olarak açılır — ~83 entry, beklenen süre yarım gün.

---

## 10. Referanslar

- [ADR 0007 — signature_db.py Dismantle Planı](0007_signature_db_dismantle_plan.md)
- [ADR-003 — LMDB sigdb](ADR-003-lmdb-sigdb.md)
- [ADR-002 — Binary Name Recovery](ADR-002-binary-name-recovery.md)
- v1.11.0-beta release notları (commit `e05fda1`)
- `feedback_parallel_agents.md` — 7 paralel ajan limiti
- `karadul-v1100-progress.md` — v1.11.0 ilerleme kaydı
