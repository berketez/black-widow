# P-GÜV — Hedef çalıştırma ve ağ güvenliği (Dalga 1)

- Taban commit: `e9d2d08` (sürüm 1.23.1)
- Worktree: `.claude/worktrees/agent-a9434d5ba801263ed`
- Kalemler: GHIDRA-11 (KRİTİK), GHIDRA-07 (YÜKSEK), GHIDRA-13 (ORTA), MEK-03 (= BICIM-06 `.d.ts` kısmı)
- Kural: hiçbir hedef gerçekten çalıştırılmaz; Frida ile gerçek süreç başlatılmaz; ağa çıkılmaz. Sınamalar sahte aygıt / sahte oturum / ağ bekçisi ile.
- Gösterim betiği (önce/sonra aynı sayım): scratchpad `pguv/goster.py` (oturuma özel; içeriği aşağıdaki tablolarda). Sahte Frida modülü, `urlopen` + `socket.connect` bekçisi, `karadul run` yalnız etkileşimsiz ve `--yes`'siz çağrılır (hiçbir şey çalıştırılamaz).

## Durum
- [x] GHIDRA-11
- [x] GHIDRA-07
- [ ] GHIDRA-13
- [ ] MEK-03

## GHIDRA-11 — Frida spawn: kancasız sürdürme, öldürülmeyen süreç

**Önce (taban `e9d2d08`, sahte aygıtla gerçek `FridaSession` kodu):**

| Ölçüm | Önce | Sonra |
|---|---|---|
| Normal akışta aygıt çağrı sırası | `spawn, attach, resume, create_script, script.load, script.unload, session.detach` | `spawn, attach, create_script, script.load, resume, kill, script.unload, session.detach` |
| `resume` kanca yüklenmeden önce mi | evet | hayır |
| Normal akışta `kill` sayısı | 0 | 1 (oturum ayrılmadan önce) |
| Attach başarısız: çağrı sırası | `spawn, attach` (süreç askıda yetim) | `spawn, attach, kill` |
| Yazılan `collect_duration` | her zaman zaman aşımı (30 sn); `wait` süreç bitince erken dönmüyordu (`_on_detached` hiçbir şey işaretlemiyordu) | `wait`'in döndürdüğü gerçek süre; zaman aşımı ayrı alanda (`collect_timeout`) |

**Onarım:**
- `karadul/frida/session.py`
  - `spawn()` süreci askıda bırakır (resume yok, `frida_spawn_wait` uykusu kalktı); attach ya da başka bir hata olursa spawn edilen süreç `_kill_spawned_quietly()` ile öldürülür.
  - Yeni `resume()`; yeni `kill()` (yalnız bu oturumun spawn ettiği süreci öldürür; `attach()` ile bağlanılan yabancı süreç öldürülmez; süreç zaten bitmişse `ProcessNotFoundError` "durdu" sayılır; başka hata `RuntimeError` olarak yükselir, yutulmaz).
  - `detach()`: önce öldürülmemiş spawn sürecini öldürür, sonra betikleri boşaltır ve oturumu ayırır; öldürme başarısızsa oturumu yine kapatır ve hatayı yeniden fırlatır.
  - `_on_detached` bir `threading.Event` işaretler ve nedeni saklar (`detach_reason`); `wait()` bu olayla erken döner ve gerçek süreyi döndürür.
- `karadul/stages.py` `DynamicAnalysisStage.execute` (yalnız dinamik aşama bölgesi): sıra `spawn (askıda) → load_script → resume → wait → kill`; kanca yüklenemezse süreç hiç sürdürülmez (`RuntimeError`, `finally` içindeki `detach` öldürür); `finally` içindeki `detach` hatası artık `debug` değil, `errors`'a yazılır ve `success=False`. Yeni istatistikler: `collect_timeout`, gerçek `collect_duration`, `target_terminated`, varsa `frida_detach_reason`. Hedef tipine göre program seçimi `_spawn_plan()` yardımcı yöntemine taşındı (davranış aynı; bilinmeyen tip bu commit'te hâlâ eski yolda, GHIDRA-07 commit'inde kapanır).
- `tests/test_frida.py` (entegrasyon, varsayılan takımda koşmaz, koşturulmadı): gerçek spawn örneği `spawn()` sonrası `resume()` çağıracak biçimde güncellendi.
- Not: `timeouts.frida_spawn_wait` artık okunmuyor (askıda spawn'da bekleme gereksiz). Ayarı kaldırmak P15'in işi (config.py'de yalnız bool dönüşümü bana ait).

**Test:** `tests/test_pguv_frida.py` 12 test (8 oturum düzeyi + 4 aşama düzeyi). Taban kodda 10'u kırmızı, 2'si yeşil (yabancı PID öldürülmez; istisnada detach — ikisi eski kodda da doğru olan davranışı kilitliyor). Yeni kodla 12/12 yeşil; `tests/test_frida.py` + `tests/test_robustness_fixes.py` ile birlikte 63 geçti.

**Mutasyon:** `scripts/measurement/mutation_specs_pguv.json` içinde `g11_*` 10 mutant → 10/10 öldü.

**Commit:** `4b30822`

## GHIDRA-07 — Çalıştırma kapısı: "false" dizgisi kapıyı açıyordu

**Önce / sonra (gerçek `Config.load` ile geçici YAML; `security.allow_target_execution: <değer>`):**

| YAML değeri | Önce (yüklenen değer → kapı) | Sonra |
|---|---|---|
| `"false"` | `'false'` → AÇIK | `False` → kapalı |
| `"no"` | `'no'` → AÇIK | `False` → kapalı |
| `"0"` | `'0'` → AÇIK | `False` → kapalı |
| `"off"` | `'off'` → AÇIK | `False` → kapalı |
| `"kapalı"` | `'kapalı'` → AÇIK | `ConfigValueError` (açık hata) |
| `false` (tırnaksız) | `False` → kapalı | `False` → kapalı |
| `true` / `"true"` | `True` / `'true'` → açık | `True` → açık |
| **"Kapalı" niyetli ama kapıyı açan değer sayısı** | **5 / 5** | **0 / 5** |

Ek: kapı YAML'dan açıldığında CLI hiçbir uyarı basmıyordu; `TargetType.UNKNOWN` hedef `generic_spawn` ile başlatılıyordu (kod izlemesi; sınama aşağıda).

**Onarım:**
- `karadul/config.py`: `_strict_bool` + `_coerce_field` + `ConfigValueError`. `Config._from_dict`'in 16 bölüm döngüsündeki genel `setattr` hepsi `_coerce_field` üstünden geçer (bütün bölümlerde aynı yol); dataclass alan tipi `bool` olan 70 alanın her biri katı dönüşümde. Kabul: bool, 0/1 tamsayı, `true/false/yes/no/on/off/1/0` dizgileri (büyük-küçük harf ve boşluk duyarsız). Geri kalan her şey (`"kapalı"`, `2`, `1.0`, `""`, liste, değersiz anahtar = None) `ConfigValueError` ile reddedilir. Bilinmeyen anahtar / öbür tipler P15'te.
- `karadul/stages.py` (dinamik aşama): kapı `is not True` ile; `_spawn_plan()` `TargetType.UNKNOWN` için `None` döner ve aşama "bilinmeyen tip çalıştırılmaz" nedeniyle atlanır (Frida oturumu açılmaz). Tanınan öbür tipler (BUN, Delphi, PyInstaller paketi, JAR, APK, .NET, .app) eski `generic_spawn` yolunda kaldı: brif yalnız bilinmeyen tipi kapatmayı istiyor, kapsam küçültülmedi.
- `karadul/cli.py` (`analyze`, yalnız dinamik kapı bloğu): kapı hangi kaynaktan açılırsa açılsın ve dinamik aşama planda ise stderr'e kaynağıyla birlikte "ÇALIŞTIRILACAK" uyarısı (`--json`/`--quiet`'te de; stdout temiz kalır). YAML'dan açık ama `--dynamic` yoksa: etkileşimsiz ortamda (ya da `--json`/`--quiet`'te) kapı bu koşu için kapatılır ve "ÇALIŞTIRILMAYACAK" denir; etkileşimli ortamda `click.confirm(default=False)` sorulur, "hayır" kapıyı kapatır. `--skip-dynamic` ya da `--stage` dinamiği plandan çıkarıyorsa soru sorulmaz.
- Giriş noktası taraması: arayüz (`ui/server.py:1800`) analizi hep `--skip-dynamic` ile koşturuyor; `batch` varsayılan `Config()` kullanıyor; `hacker_cli` `skip_dynamic=True`. YAML'dan kapının açılabildiği tek giriş `analyze`.
- Depodaki ayar biçimli YAML'lar katı yükleyiciyle yükleniyor: `docker/measurement/karadul.yaml` OK (ayar biçimli tek dosya).

**Test:** `tests/test_pguv_kapi.py` 38 test (katı bool 25, aşama kapısı 8, CLI 5). Eski kodda 30'u kırmızı; 8 yeşil olanlar eski kodda da doğru olan davranışı kilitliyor (tırnaksız YAML bool'ları, bool olmayan alan, gerçek True oturuma ulaşır, tanınan yerel tip, `--skip-dynamic`'te soru yok). Yeni kodla 38/38. Config yükleyen 17 mevcut test dosyası: 481 geçti, 3 kırmızı (`tests/test_bsim.py` lite/native — taban `e9d2d08`'de aynı sırayla da aynı 3 kırmızı; tek başına koşunca yeşil; sıra bağımlı JVM durumu, bu paketle ilgisiz).

**Mutasyon:** `g07_*` 9 mutant → 9/9 öldü.

**Kalan (yama):** `analyze`'da bozuk bool değeri artık `ConfigValueError` yığın iziyle düşer (sessiz değil, ama çirkin). `_load_config` dar bölgemin dışında: düzgün "HATA: ayar dosyası: …" + çıkış 2 için yama `yamalar/P-GUV__cli.py.patch`.
