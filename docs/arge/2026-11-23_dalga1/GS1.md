# GS1 — GS-1: Ghidra sonrası adımların görünmesi ve iptalin kesinleşmesi (ilerleme dosyası)

Paket: uygulama oturumu 5 (2026-11-27), GS1 (`docs/arge/2026-11-23_dalga1/gonderim/GS1.md`; A-36).
Taban: main `c59d3c0e` (`git merge --ff-only main` sonrası; ürün kodu `ed28e36b` ile aynı, arada yalnız belge). Başlangıç: 2026-11-27 22:22. Sert son: 2026-11-28 00:45.
Koşu kökü: `~/karadul_olcum/runs/dalga1-2026-11-23/GS1/` (özetler `ozet/`). `karadul.__file__` worktree'yi gösteriyor.
Takım tartışma dosyasına yazılmadı: gönderim yalnız listelenen dosyalara yazma izni veriyor (BA2 ile aynı).

## Kalemler

| # | Kalem | Durum | Commit |
|---|---|---|---|
| 1 | Hüküm 7: SIGTERM'e yanıtsızlığın nedeni (Ghidra'sız ölçüm) | bitti: **neden JVM** (süreç içinden çözülemez, dış iptal gerekir) | bu commit |
| 2 | Ön kayıt (`on_kayit_GS1.md`) | bitti (ölçümden önce) | `21bec7ac` |
| 3 | Kesin iptal (`_kill_proc`, `cancel_job`, `_kill_jobs` / `_terminate_jobs`) + testler | | |
| 4 | Adım ve aşama olayları (`runner.py`, `core/pipeline.py`, `core/ilerleme.py`) + testler | | |
| 5 | `son_cikti_yasi_sn` + `index.html` | | |
| 6 | Mutasyon (yeni tanım + eski tanımlar) | | |
| 7 | Tek ürün koşusu (debian `cat`; H1, H2, H5) | | |
| 8 | Tam takım | | |

## Kalem 1 — hüküm 7: SIGTERM'e yanıtsızlığın nedeni (ürün kodu değişmeden; H4)

Betik `scripts/arge/gs1/sigterm_olc.py` (her koşul ayrı çocuk süreçte, kendi süreç grubunda). Çocuk önce işaret işleyicilerinin dökümünü yazar (Python düzeyi `signal.getsignal` + C düzeyi `sigaction`, işleyici adresi `dladdr` ile kitaplık / simgeye çevrilir), `HAZIR` basar ve ana iş parçacığında BA-1'in eski `memmove` kalıbına girer (yapay girdi `memmove(a,b,` + `x,` × 30, kapanan ayraç yok; aynı kalıp 20 karakterde 0,046 sn, 24'te 0,731 sn, 28'de 8 sn'de bitmedi: üstel, dönmez). Sürücü `HAZIR`'dan 1 sn sonra SIGTERM gönderir, 15 sn bekler, ölmezse gruba SIGKILL. (c) ve (e) Ghidra JVM'ini başlattığı için `ghidra_kuyruk.sh GS1 h7:c` / `h7:ce` ile koşuldu (analiz yok; JVM ürünün yolundan, `headless._ensure_pyghidra_started`, ≈ 2,4 sn). 22:29–22:31, 1 dk yük 4,8 → 13,4 (yük altında; süreler hüküm değil, yalnız ölür / ölmez).

| Koşul | SIGTERM'in C düzeyi işleyicisi | Python'un gördüğü | Sonuç | Süre / dönüş |
|---|---|---|---|---|
| (a) yalın Python + takılı `re` | `SIG_DFL` | `SIG_DFL` | **öldü** | 0,002 sn; işaretle öldü (−15) |
| (b) `karadul analyze`'ın işleyicileri (`karadul.cli.main` grubu gerçekten koştu: `analyze --help`; analizin modülleri yüklendi) + takılı `re` | `SIG_DFL` (karadul yalnız SIGUSR1 kuruyor: `cli.py:574`) | `SIG_DFL` | **öldü** | 0,011 sn; −15 |
| (c) b + süreç içi JVM (pyghidra, ürünün yolu) + takılı `re` | **`libjvm.dylib` `UserHandler`** (SIGINT, SIGHUP, SIGQUIT de; SIGUSR2 `SR_handler`) | `SIG_DFL` (Python bilmiyor) | **ÖLMEDİ** (15 sn) | SIGKILL gerekti (−9) |
| (d) denetim: yalın Python + Python düzeyi SIGTERM işleyicisi + takılı `re` | `python3.12 signal_handler` | Python işlevi | öldü (işleyici koştu) | 0,005 sn; çıkış 99 (işleyicinin kodu) |
| (e) denetim: c ama `re` yerine `time.sleep` (ana iş parçacığı GIL'i bırakır) | `libjvm` `UserHandler` | `SIG_DFL` | öldü | 0,497 sn; **çıkış 143** (JVM'in kapanış yolu: 128 + 15) |

- **Neden (H4, ilk ölçüm): JVM.** Süreç içi JVM başlayınca SIGTERM'in işleyicisi HotSpot'unki olur; SIGTERM süreci öldürmez, JVM'in kapanış sırasını başlatır ("SIGTERM handler" Java iş parçacığı). Kapanış kancalarından biri (JPype: `org.jpype.ref.JPypeReferenceNative.removeHostReference`) Python'a dönmek için `PyGILState_Ensure` → `take_gil`'de bekliyor; GIL'i ana iş parçacığında C düzeyinde eşleşen `sre_search` tutuyor ve bırakmıyor. Kanıt: (c)'de SIGTERM'den 3 sn sonra `/usr/bin/sample` (2 sn, 1 358 örnek): ana iş parçacığı 1 358 / 1 358 örnekte `_sre_SRE_Pattern_search`; "Java: SIGTERM handler" 1 358 / 1 358 `JVM_MonitorWait` (kancayı bekliyor); "Java: Thread-0" 1 358 / 1 358 `JPypeReferenceNative_removeHostReference → PyGILState_Ensure → take_gil`. GIL serbestken (e) aynı yol 0,5 sn'de bitiyor.
- (d) Python'un `re`'si eşleşme döngüsünde işaret denetliyor (`PyErr_CheckSignals`): ana iş parçacığındaki Python işleyicisi takılı eşleşmede bile koştu. Karadul SIGTERM'e Python işleyicisi kurmuyor; sorun bu değil.
- **Hüküm: süreç içinden çözülemez, dış iptal gerekir.** Neden `cli.py`'de bizim kurduğumuz bir işleyici değil (b): yama yok. Süreç içi bir bekçi de çözüm değil: işaret JVM'e gidiyor, JVM'in kapanışı GIL'i bekliyor, GIL takılı eşleşmede. Kesebilen tek şey başka süreçten SIGKILL (kalem 3).
- Ölçülmedi (not): JVM `-Xrs` ile başlatılsaydı (HotSpot SIGTERM'i kurmaz, öntanım eylem → çekirdek öldürür) süreç SIGTERM'le ölür müydü, ve bunun Ghidra projesinin kapanışına etkisi. `headless.py` bu paketin dosyası değil; ayrı ölçüm (ÖL-5b / ÖL-6 ile).
- Ham sonuçlar `~/karadul_olcum/runs/dalga1-2026-11-23/GS1/ozet/{h7_abd,h7_c,h7_ce}.json`, örneklem `ozet/ornek_c.txt`.
