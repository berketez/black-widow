# P-GÜV — Hedef çalıştırma ve ağ güvenliği (Dalga 1)

- Taban commit: `e9d2d08` (sürüm 1.23.1)
- Worktree: `.claude/worktrees/agent-a9434d5ba801263ed`
- Kalemler: GHIDRA-11 (KRİTİK), GHIDRA-07 (YÜKSEK), GHIDRA-13 (ORTA), MEK-03 (= BICIM-06 `.d.ts` kısmı)
- Kural: hiçbir hedef gerçekten çalıştırılmaz; Frida ile gerçek süreç başlatılmaz; ağa çıkılmaz. Sınamalar sahte aygıt / sahte oturum / ağ bekçisi ile.
- Gösterim betiği (önce/sonra aynı sayım): scratchpad `pguv/goster.py` (oturuma özel; içeriği aşağıdaki tablolarda). Sahte Frida modülü, `urlopen` + `socket.connect` bekçisi, `karadul run` yalnız etkileşimsiz ve `--yes`'siz çağrılır (hiçbir şey çalıştırılamaz).

## Durum
- [x] GHIDRA-11
- [ ] GHIDRA-07
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
