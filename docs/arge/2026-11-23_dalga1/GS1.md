# GS1 — GS-1: Ghidra sonrası adımların görünmesi ve iptalin kesinleşmesi (ilerleme dosyası)

Paket: uygulama oturumu 5 (2026-11-27), GS1 (`docs/arge/2026-11-23_dalga1/gonderim/GS1.md`; A-36).
Taban: main `c59d3c0e` (`git merge --ff-only main` sonrası; ürün kodu `ed28e36b` ile aynı, arada yalnız belge). Başlangıç: 2026-11-27 22:22. Sert son: 2026-11-28 00:45.
Koşu kökü: `~/karadul_olcum/runs/dalga1-2026-11-23/GS1/` (özetler `ozet/`). `karadul.__file__` worktree'yi gösteriyor.
Takım tartışma dosyasına yazılmadı: gönderim yalnız listelenen dosyalara yazma izni veriyor (BA2 ile aynı).

## Kalemler

| # | Kalem | Durum | Commit |
|---|---|---|---|
| 1 | Hüküm 7: SIGTERM'e yanıtsızlığın nedeni (Ghidra'sız ölçüm) | bitti: **neden JVM** (süreç içinden çözülemez, dış iptal gerekir) | `a836acaf` |
| 2 | Ön kayıt (`on_kayit_GS1.md`) | bitti (ölçümden önce) | `21bec7ac` |
| 3 | Kesin iptal (`_kill_proc`, `cancel_job`, `_kill_jobs` / `_terminate_jobs`) + testler (9) | bitti; H3 **TUTTU** | `0c6531c3` |
| 4 | Adım ve aşama olayları (`runner.py`, `core/pipeline.py`, `core/ilerleme.py`) + testler | bitti | `8b5ae8e7` |
| 5 | `son_cikti_yasi_sn` + `index.html` (OL4 yaması + iki satır) + testler | bitti | `8b5ae8e7` |
| 6 | Mutasyon (yeni tanım 29 / 29 + sekiz eski tanım 234 / 234; `p17`'de üç bayat `find` düzeltildi) | bitti | `a191c5d3` (tanım), bu commit |
| 7 | Tek ürün koşusu (debian `cat`; H1, H2, H5) | bitti: H1 **TUTTU**, H2 metne göre **TUTMADI** (4 / 143 dosyada yalnız zaman / süre / yol / anahtar sırası), H5 **TUTTU** | bu commit |
| 8 | Tam takım (yamasız) | bitti: **11 415 geçti / 26 atlandı / 11 kaldı** (11'i de iki test yamasının kapsadığı beklenen kırmızı) | bu commit |

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
- **Ek ölçüm (ön kayıt dışı, hüküm değil; 22:5x, kuyruk `GS1 ek:xrs`, `scripts/arge/gs1/xrs_olc.py`):** `karadul` içe aktarılmadan, JVM `HeadlessPyGhidraLauncher` ile ürünün VM argümanlarının bir alt kümesiyle (yığın 1 GB) başlatıldı + aynı takılı düzenli ifade. `-Xrs`'siz: SIGTERM işleyicisi `libjvm` `UserHandler`, 15 sn'de **ölmedi** (c'nin karadul'suz yinelemesi). **`-Xrs` ile: SIGTERM işleyicisi `SIG_DFL`, süreç 0,009 sn'de öldü (−15).** Yani süreç içi bir çare var (JVM'i `-Xrs` ile başlatmak; `headless.py` `_ensure_pyghidra_started`, bu paketin dosyası değil), ama yan etkisi ölçülmedi: işaretle kapanışta JVM kapanış kancaları koşmaz (Ghidra projesinin kapanması / kilit dosyaları), Ctrl-C davranışı değişir. Karar ve ölçüm ÖL-5b / ÖL-6'ya not; arayüzün dış SIGKILL'i bundan bağımsız gerekli (takılma JVM dışı bir nedenle de olabilir). Ham `ozet/ek_xrs.json`.
- Ham sonuçlar `~/karadul_olcum/runs/dalga1-2026-11-23/GS1/ozet/{h7_abd,h7_c,h7_ce}.json`, örneklem `ozet/ornek_c.txt`.

## Kalem 3 — kesin iptal (`0c6531c3`, `ui/server.py`)

- `_sonlandir(procs, bekleme=None)`: her sürecin grubuna SIGTERM (`_sonlandirma_grubu`: sunucunun kendi grubu ya da süreç yoksa grup sinyali yok, yalnız `terminate` / `kill`); `IPTAL_BEKLEME_SN` (modül sabiti, 5,0) boyunca 0,05 sn aralıkla `_yasiyor` (lider `poll()` + ayrı gruptaysa `os.killpg(pgid, 0)`: lider ölse de gruptaki torun yaşıyorsa yaşıyor sayılır); hâlâ yaşayana gruba SIGKILL, sonra grubun boşalması en çok `_OLUM_BEKLEME_SN` (2,0) beklenir. Her süreç için `"term"` / `"kill"`.
- `_kill_proc(proc)` → `_sonlandir([proc])[0]`; `cancel_job` dönüşüne `sonlandirma`. `_kill_jobs` (sunucunun SIGTERM / SIGINT işleyicisi `_terminate_jobs` ve ebeveyn bekçisi bunu çağırır) bütün süren işlere aynı yolu TEK beklemeyle uygular; bekleme `_JOBS_LOCK` dışında (yoklamalar kilitte beklemesin). Kendi grubunu vurmama koruması SIGKILL için de geçerli (test).
- **H3 (ölçüm `scripts/arge/gs1/iptal_olc.py`, ürün ağacı `urun-8b5ae8e7`'nin `ui/server.py`'si, 22:54, 1 dk yük 9,8; yük altında):**

| Senaryo | `sonlandirma` | `cancel_job` dönüşü | lider | torun |
|---|---|---|---|---|
| SIGTERM'e uyan süreç + torun (`sleep`) | `term` | 0,050 sn | −15, 0,050 sn | 0,050 sn |
| SIGTERM'i yok sayan süreç + SIGTERM'i yok sayan torun | `kill` | 5,053 sn | −9, 5,053 sn | 5,053 sn |
| SIGTERM'i yok sayan süreç C düzeyinde takılı düzenli ifadede + torun | `kill` | 5,097 sn | −9 | 5,097 sn |
| **gerçek durum: süreç içi JVM (ürünün yolu) + takılı düzenli ifade** (kuyruk `GS1 h3:jvm`) | `kill` | 5,084 sn | −9 | (torun yok) |

  **H3: TUTTU** (yok sayan süreç + torunu ≤ 7 sn'de ölü, `kill`; uyan süreç `term`, ≤ 2 sn). Not: JVM senaryosunun çocuğu (`sigterm_olc.py cocuk c`) worktree'den koştu; o sırada aynı worktree'de mutasyon koşusu sürüyordu (çocuk `karadul`'u içe aktarıyor). JVM'in işaret davranışı bu modüllere bağlı değil; iptal kodu ürün ağacından. Ham `ozet/h3_iptal.json`, `ozet/h3_iptal_jvm.json`.
- Testler `tests/test_gs1_kesin_iptal.py` (9): uyan → `term` ≤ 2 sn; yok sayan + torun → `kill`, bekleme − 0,2 ≤ süre ≤ bekleme + 2; C düzeyinde takılı düzenli ifade → `kill`; lider ölüp torun yaşarken → `kill` (grup denetimi); bekleme modül sabitinden; kendi grubu hiç vurulmaz (SIGTERM ve SIGKILL); `_kill_jobs` tek bekleme (üç iş, 1,5 sn bekleme, < 2,5 sn); `_terminate_jobs` aynı yol; bitmiş iş 409 ve sinyal yok.
- **Yama (dosya listemde değil):** `yamalar/GS1__test_p17_iptal.py.patch` — `test_cancel_kills_process_group`'un dönüş kaydı tam eşitliği `{"ok", "job"}` → `+ "sonlandirma": "term"` (hüküm 5'in istediği alan). Yamasız ağaçta bu test kırmızı (beklenen). Yamalı kopyada (`…/GS1/yamali_kopya/`, `karadul` / `ui` worktree'ye bağlı) `test_p17_iptal.py` 8 / 8.

## Kalem 4 — adım ve aşama olayları (`8b5ae8e7`)

- **Üretici** `karadul/core/ilerleme.py`: `ASAMALAR` (sözleşmenin aşama listesi), `olay_satiri(asama, adim, durum, **alanlar)`, `olay_yaz(...)` (`karadul.ilerleme`, INFO). Sözleşme dışı aşama / durum / alan `ValueError`. Köprünün üreticisi (`headless.ilerleme_satiri`, hep `asama=static`) değişmedi; iki üretici aynı satırı veriyor (test: 5 durum × 11 alan kümesi × 4 adım adı). `GOSTERILEN_ALANLAR`'a `asama` eklendi (arayüz olayı kendi aşamasının altına yazar).
- **Adım koşucusu** `karadul/pipeline/runner.py`: `_execute_step` / `_execute_step_parallel_safe` ince sarmalayıcı oldu (eski gövdeler `_…_govde`, metinleri değişmedi). `_AdimOlayi`: adım başında `ILERLEME asama=<aşama> adim=<aşama>.<adım> durum=basladi`; bitişte `gecen_sn` ile `kismi` (istisna → `neden="istisna: <Tür>: <ileti>"`; ya da adım `ctx.errors`'a ekledi → ilk hata, birden çoksa `"N hata; ilki: …"`), `atlandi` (adımın döndürdüğü yapıtlarda adı `_status` ile biten ve değeri `disabled` olan anahtar → `neden="<anahtar>=disabled"`), yoksa `bitti`. `neden` en çok 200 karakter. Aşama `PipelineContext.extra["_current_stage"]`'den; sözleşme dışı ya da yoksa olay yok. Paralel düzeyde hatanın hangi adımdan geldiği `_IzlenenHatalar` ile (koşucunun kurduğu `ctx.errors`; ekleyen iş parçacığının o anki adımı; liste olarak davranışı aynı, test). Sıralı kipte liste farkı (adımın açtığı iş parçacıklarının eklediği de sayılır).
- **Boru hattı** `karadul/core/pipeline.py` `_execute_stage` (gövde `_execute_stage_govde`): aşama başında `asama=<aşama> adim=<aşama> durum=basladi`, sonunda `_asama_sonu_olayi` (atlandı → `atlandi neden=<skip_reason>`; başarısız → `kismi neden="aşama başarısız: …"`; hata ya da `stats.partial` → `kismi`; yoksa `bitti`; hepsinde `gecen_sn` = `duration_seconds`). `dynamic` aşaması sözleşmede yok → olay üretilmez (not).
- İçe aktarma: `core/pipeline.py` ve `runner.py` üreticiyi işlev içinde içe aktarıyor (`karadul.core.ilerleme` → `karadul.ghidra.headless`; modül düzeyinde içe aktarma `karadul.core` paketinde döngü riski).
- Sahte ilerleme yok: adım içi `suruyor` yok, zamanlayıcı yok (test: 0,6 sn süren adımda yalnız iki olay); baş olayı adım koşmaya başlamadan günlükte (test).
- "Atlandı" işaretinin sınırı: yalnız `pdb_symbol_recovery`, `trex_struct_recovery`, `binaryninja_analysis` bayrak kapalıyken `*_status = "disabled"` döndürüyor. Bayrak kapalıyken iş yapmadan dönen öbür adımlar (ör. `bsim_match`: yalnız `ctx.stats`'a `disabled` yazıyor; `kesin_anchors`) `bitti` görünür. Tek biçimli bir "atlandım" bildirimi adımlarda yok (`karadul/pipeline/steps/` bu paketin dışında).
- Testler `tests/test_gs1_adim_olaylari.py` (96; adım / aşama kısmı 81).

## Kalem 5 — `son_cikti_yasi_sn` ve `index.html` (`8b5ae8e7`)

- `_job_progress` yeni alan `son_cikti_yasi_sn` = `round(max(0, time.time() − os.stat(log).st_mtime), 1)`; dosya yoksa `null` (`_son_cikti_yasi`). Var olan alanlar değişmedi.
- `index.html`: OL4 yaması (`yamalar/OL4__index.html.patch`; `git apply --check` temizdi, elle aynı fark) + düzeltme: koşul `s.key==='static'` → `p.ilerleme.asama===s.key` (olay kendi aşamasının satırının altında; köprünün son olayı yeniden kurma sürerken gösterilmez). Hüküm 4'ün satırı: iş sürerken ve alan doluyken aşama kutusunun sonunda `son çıktı N sn önce` (< 60 sn) / `son çıktı N dk önce` (sınıf `sonyas`, stil kuralı yok; renk / eşik / uyarı / animasyon yok). CSP karması yenilendi: `IFN9YqApCjQD9Uk/0B64N3HIZSabmu3YcUcu9C9KqsY=` (`~/karadul_olcum/runs/dalga1-2026-11-23/OL4/betik/csp_karma.py`). `node --check` 0.
- **Arayüzde görünen yeni satırlar (metin):** `reconstruct.c_naming · basladi`; `reconstruct.engineering_annotation · kismi · 61.0 sn · 1 hata`; `ghidra.decompile · suruyor · 500 / 13559 · 45.3 sn` (statik sürerken, eskisi gibi); `son çıktı 43 sn önce`; `son çıktı 31 dk önce`.
- Testler (aynı dosyada, 15): sunucu alanı (31 dk önce yazılmış günlük → 1 859–1 870 sn; dosya yok → `null`; yeni günlük < 5 sn); gerçek `renderStages` node'da sahte DOM ile (olay kendi aşamasının altında, bitmiş aşamanın olayı başka aşamada yok, statik olayı, kısmi alanlar, beş yaş değeri, iş bitince / alan yokken satır yok); yeni satırlarda `animation` / `@keyframes` / `ilerliyor` / zamanlayıcı yok; CSP karması betikle aynı. Var olan arayüz testleri (`tests/test_ui_*.py`) yeşil.
- **Yama:** `yamalar/GS1__test_ol4_ilerleme.py.patch` — iki tam eşitlik denetimine `"asama": "static"` ve anahtar kümesi denetimine `son_cikti_yasi_sn`. Yamasız ağaçta bu üç denetim 10 sınamayı kırmızı yapıyor (biri 8 parametreli; beklenen, kalem 8). Yamalı kopyada `test_ol4_ilerleme.py` 52 / 52.

## Kalem 6 — mutasyon

- `scripts/measurement/mutation_specs_gs1.json`: **29 mutant, 29 öldü**, hata 0 (22:53:44–22:56:22; üretici `~/karadul_olcum/runs/dalga1-2026-11-23/GS1/betik/spec_uret.py`: her `find` tekil, `replace` farklı uzunlukta). Kesin iptal 8 (SIGKILL yok, bekleme yok, grup denetimi yok, kill → "term" yazılır, kendi grubu vurulur, dönüşte `sonlandirma` yok, kapanışta ayrı beklemeler, bekleme sabiti okunmaz), son çıktının yaşı 2, adım olayları 8 (başlangıç yok, hata kismi sayılmaz, paralel atıf liste farkıyla, izlenen liste kurulmaz, atlandı → bitti, istisnada kapanış yok, aşama öneki yok, aşama denetimsiz), aşama olayları 4, üretici 3 (tırnaksız, aşama denetimi yok, gösterimde `asama` yok), `index.html` 4 (aşama koşulu yok, yaş satırı yok, bitmiş işte yaş satırı, dakika çevrimi yok; hedefleri davranış testleri — CSP karma testi her betik değişikliğini yakaladığı için mutantı yanlış nedenle öldürürdü). Günlük `…/GS1/mutasyon/gs1.log`.
- **Eski tanımlar** (dokunulan beş dosyaya — `ui/server.py`, `ui/index.html`, `karadul/pipeline/runner.py`, `karadul/core/pipeline.py`, `karadul/core/ilerleme.py` — bakan sekiz tanım; `grep` ile), 22:56–23:07, sırayla, sürücü `betik/eski_mutasyon.py` (`mutation_probe.py` ile aynı uygulama / geri alma; fark: hedef test `test_ol4_ilerleme.py` ya da `test_p17_iptal.py` ise yamalı kopyadan koşulur — yamasız ağaçta o dosyalarda kırmızı test var, mutant kendiliğinden "öldü" görünürdü; 30 mutant böyle koştu):

| Tanım | Mutant | Öldü | Yaşadı | Hata (find eşleşmedi) | Düzeltme |
|---|---|---|---|---|---|
| ol4 | 22 | 22 | 0 | 0 | — |
| p17 | 54 | 54 | 0 | 0 | üç `find` bu paketin değişikliğiyle bayatlamıştı, düzeltildi (aynı mutasyon, yalnız metin): `i10_iptal_isaretlenmez`, `i10_iptal_oldurmez` (`sonlandirma = _kill_proc(proc)` / dönüş kaydı), `i10_ortak_grup_vurulur` (girinti: koruma satırı `_sonlandirma_grubu`'na taşındı) |
| adim3_ui | 30 | 30 | 0 | 0 | — |
| ui_cagri_kenari | 13 | 13 | 0 | 0 | — |
| ui_lm_api | 30 | 30 | 0 | 0 | — |
| ui_lm_panel | 23 | 23 | 0 | 0 | — |
| p14 | 17 | 17 | 0 | 0 | — |
| p15a | 45 | 45 | 0 | 0 | — |
| **toplam** | **234** | **234** | **0** | **0** | |

- Gönderimin listesindeki `pguv` ve `surum_oncesi` tanımlarında bu paketin dokunduğu dosyaya bakan mutant yok (0 / 34, 0 / 28); yine de tam takımdan sonra koşuldu (23:21–23:23, aynı sürücü): **surum_oncesi 28 / 28 öldü; pguv 31 / 31 öldü + 3 bayat `find`** — `g07_bool_donusum_yok`, `g07_yalniz_security_bolumu` (`karadul/config.py`) ve `m03_kaynak_esleme_ana_anahtarsiz` (`karadul/reconstruction/naming/pipeline.py`). Üçü OL4'ün bildirdiği aynı üç tanım (bu paketten önce bayattı; dosyalar bu paketin değil): düzeltilmedi, bildirildi (MUTBAKIM-2'nin listesinde). Ham `…/GS1/mutasyon/eski2.{log,json}`.
- Koşu sonunda kod dosyaları temiz (`git status`: yalnız belge ve tanım dosyası). Ham `…/GS1/mutasyon/eski.{log,json}`.

## Kalem 7 — tek ürün koşusu: debian `cat` (H1, H2, H5)

- Ürün ağacı `~/karadul_olcum/urun-8b5ae8e7` (`git worktree add --detach` + altı bağ, `urun-ed28e36b` ile aynı hedefler). Girdi S8 tabanının `raw/` kopyası (`…/urun-onarim-a62f15e/debian/coreutils/cat/ws/workspaces/cat/20261119_054950/raw/cat`, sha256 `0d5a5dd543ed8d31…`). Komut (ağacın kökünden): `python -m karadul analyze <cat> --skip-dynamic --output-dir <kök>/ws --output <kök>/out --verbose`, stdout / stderr ayrı, taze `KARADUL_CACHE_DIR`, `PYTHONHASHSEED=0`, kuyruk `GS1 cat:verbose` (22:48:25–22:48:59, yuva 2, 34 sn, 1 dk yük 5,3 → 7,0; yük altında), çıkış 0. Sürücü `betik/cat_kos.zsh`, ölçüm `betik/cat_olc.py` → `ozet/cat_olc.json`, H2 ayrıştırması `betik/h2_ayri.py` → `ozet/h2_ayri.json`. Taban: `ANA/s8_taban_ed28e36b/debian/coreutils/cat` (kökte `BITTI` vardı).
- stderr'de 126 `ILERLEME` satırı, ayrışmayan 0; stdout'ta 0.
- **H1: TUTTU.** Günlükte `Step '<ad>' tamam` satırı olan adım **35**; olay olan adım 35; yeniden kurma adım olayı **70 = 2 × 35**; her adımda tam bir `basladi` + bir bitiş (bozuk çift 0, eksik 0, fazla 0); bitişler `bitti` 34, `atlandi` 1 (`binaryninja_analysis`, `bn_status=disabled`), `kismi` 0. Aşama olayları: identify, static, deobfuscate, reconstruct, report — her biri `basladi` + `bitti`.
- **H2: metne göre TUTMADI; `naming_map.json` bayt eşit.** `out/` 143 / 143 dosya iki yanda; 139 bayt eşit, 4 farklı: `README.md` (üretim zamanı, süreler), `src/compile_commands.json` (çalışma alanı yolu), `report.json` (63 anahtar yolu: üretim zamanı, aşama / adım süreleri, `flirt_load_seconds`, `yara_scan_time_ms`, ürün ağacının yolu `flirt_data_root` / `sigdb_data_root` / `ngram_db_dizini` / IOC özetindeki veri kökü; ayrıca `reconstruct.stats`'ın anahtar SIRASI farklı, anahtar kümesi aynı 266 / 266), `report.html` (aynı alanlar). Yol / zaman / süre normalleştirilince `README.md` ve `compile_commands.json` eşit. Anahtar sırası farkı bu paketin değişikliğine bağlı değil: OL4'ün aynı kodla iki `cat` koşusunda da (`OL4/cat/ontanim` ↔ `quiet`) `reconstruct.stats` sırası farklı (paralel adımların bitiş sırası). Ön kayıt bu tür dosyaları adıyla yazmayı öngörüyordu; hüküm metne göre verildi.
- **H5: TUTTU.** Olay başına maliyet (baş + bitiş, `_AdimOlayi` gerçek günlük işleyicisiyle dosyaya yazarken, 7 × 5 000 çift, ortanca): **11,4 µs**; bu koşuda GS-1 olayı 80 (70 adım + 10 aşama) → 0,91 ms / 33,7 sn duvar = **%0,0027** (≤ %0,1). Yük altında.

## Kalem 8 — tam takım (yamasız)

23:09:12–23:20:12 (657,7 sn; 1 dk yük 7,96 → 5,34; aynı anda HZ7a / PUV6c ajanları: **yük altında**), worktree kökünden, kod `8e8801b5` (son kod commit'i `8b5ae8e7` + sınama / tanım / belge), worktree'de geçici çalışma verisi bağları (`vendor`, `scripts/node_modules`, `sigs`, `signatures.lmdb`, `signatures_homebrew{,_bytes,_bytes_v2}.json`, `sigs_macos_system.json`; commit'lenmedi, bitince kaldırıldı): **11 415 geçti / 26 atlandı / 11 kaldı** (152 seçilmedi). Taban `ed28e36b` 11 321 / 26 / 0; bu paketin yeni sınaması 105 (96 + 9): 11 415 + 11 = 11 426 = 11 321 + 105.
- **Kalan 11'in hepsi beklenen ve yamalı:** `tests/test_ol4_ilerleme.py` 10 (`test_gosterim_alanlari_uydurmaz`, `test_tek_seferde_okuma_da_ayni_ve_beklenen_degerler`: `ilerleme` sözlüğüne `asama` eklendi; `test_parcali_okuma_tek_seferlik_tam_okumayla_ayni[0–7]`: `_job_progress`'in anahtar kümesine `son_cikti_yasi_sn` eklendi) → `yamalar/GS1__test_ol4_ilerleme.py.patch`; `tests/test_p17_iptal.py::test_cancel_kills_process_group` 1 (dönüş kaydına `sonlandirma`) → `yamalar/GS1__test_p17_iptal.py.patch`. Yamalı kopyada iki dosya 52 / 52 + 8 / 8 (`…/GS1/yamali_kopya/`, `karadul` / `ui` worktree'ye bağlı). Başka kırmızı yok. Bu pakette `config.py` yaması yok.
- Uyarılar (3) bu paketten değil (`jpype.isThreadAttachedToJVM` ÖL-1'den; iki `ComputationRecoveryConfig`). Günlük `…/GS1/tam_takim/pytest.log`.

## Ön kayıt hükümleri (`21bec7ac`; eşikler değişmedi)

| H | Ön kayıt | Ölçülen | Hüküm |
|---|---|---|---|
| H1 | yeniden kurmada koşan her adım için tam bir `basladi` + bir bitiş; olay = 2 × adım; her aşama bir baş + bir son | 35 adım, 70 olay; bozuk çift 0; 5 aşama × 2 | **TUTTU** |
| H2 | `out/` ağacı ve `out/naming_map.json` S8 tabanıyla (`s8_taban_ed28e36b`) bayt eşit | `naming_map.json` bayt eşit; `out/` 139 / 143 bayt eşit, 4 dosyada yalnız zaman / süre / yol alanları ve `reconstruct.stats` anahtar sırası (aynı kodla iki koşuda da oynuyor) | metne göre **TUTMADI** (ad haritası ve kaynak ağacı eşit) |
| H3 | SIGTERM'i yok sayan süreç + torunu ≤ 7 sn'de ölü, `kill`; uyan süreç `term`, ≤ 2 sn | 5,05 / 5,10 sn `kill` (gerçek JVM + takılı düzenli ifade: 5,08 sn `kill`); uyan 0,05 sn `term` | **TUTTU** |
| H4 | hangi koşulda SIGTERM'le ölmüyor (ilk ölçüm) | yalnız (c): süreç içi JVM + GIL'i tutan takılı eşleşme (JPype kapanış kancası GIL'i bekliyor); (a) ve (b) ölüyor | ilk ölçüm: **JVM** |
| H5 | adım olaylarının payı ≤ %0,1 | %0,0027 (80 olay × 11,4 µs / 33,7 sn) | **TUTTU** |

## Kapsam dışı (hüküm 8; yapılmadı)

- CLI'da gözetmen süreç (CLI'dan başlatılan analiz için dışarıdan SIGKILL): ÖL-5b ile. Bugün kesin iptal yalnız arayüz sunucusunun başlattığı işte; terminalden koşulan `karadul analyze` C düzeyinde takılırsa Ctrl-C / SIGTERM'e yine yanıt vermez (JVM, kalem 1).
- Statik aşamanın köprü dışı alt adımlarının olayları (`karadul/analyzers/macho.py`; ÖL-3'ün dosyası): bugün statik aşamada köprü bittikten sonra aşamanın sonu olayına kadar olay yok (Ollama'da ≈ 215 sn).
- Adım bütçesi / adımı zorla kesme (Ghidra sonrası adımlar için ÖL-2 benzeri bütçe): yok.

## Sonraki paketlere not

### ÖL-5b (sürdürme, CLI gözetmeni)

- Neden ölçüldü (kalem 1): süreç içi JVM SIGTERM / SIGINT / SIGHUP / SIGQUIT'i alıyor (`libjvm` `UserHandler`); kapanış kancası (JPype `removeHostReference`) GIL'i bekliyor. CLI gözetmeni de dışarıdan SIGKILL'e yükselmeli (arayüzün `_sonlandir`'ı aynı düzen: grup, bekleme, grup boşalana kadar denetim). Gözetmenin "takıldı" kararı için veri: `ILERLEME` olaylarının yaşı (günlüğün `st_mtime`'ı) — ama adım içi olay olmayan uzun adım (ör. 600 sn'lik `c_naming`) takılmadan da sessiz kalır; eşik ölçümle seçilmeli (bu pakette yok).
- JVM `-Xrs` ile başlatılınca takılı düzenli ifadedeki süreç SIGTERM'le 0,009 sn'de öldü (ek ölçüm, kalem 1). Ghidra projesinin kapanışına / kilit dosyalarına ve Ctrl-C davranışına etkisi ölçülmedi (`headless.py`).
- SIGKILL'le kesilen koşunun çalışma alanı yarım kalır (`out/` yazılmaz, Ghidra proje kilidi kalabilir): sürdürme bunu görmeli.

### ÖL-6 (bellek / disk bekçisi)

- Bekçi süreç dışıysa aynı `_sonlandir` düzeni kullanılabilir; süreç içi bir bekçi C düzeyinde takılmada koşamaz (GIL), SIGTERM de JVM yüzünden etkisiz (kalem 1).
- Adım olayları (`asama=reconstruct adim=reconstruct.<ad>`) bellek tepesinin hangi adımda olduğunu günlükten eşlemek için kullanılabilir (zaman damgası `--verbose`'da saniye çözünürlüğünde).

### ÖL-8 (arayüz ölçeği)

- `index.html`'in yeni satırları her yoklamada `renderStages` ile baştan çiziliyor (OL4 notu: `.substage` animasyonu yüzünden sınıfsız / `substages` / `sonyas` sınıfı). Kutuyu yerinde güncellemeye geçilirse yeni iki satır da taşınmalı; CSP karması yeniden hesaplanır.
- `ilerleme` alanı artık `asama`'yı taşıyor (`GOSTERILEN_ALANLAR`); arayüz olayı kendi aşamasının altında gösteriyor. `son_cikti_yasi_sn` sunucuda `os.stat` ile (her yoklamada bir çağrı).
- `cancel_job` en çok `IPTAL_BEKLEME_SN + _OLUM_BEKLEME_SN` (7 sn) sürebilir. `index.html` (`cancelAnalysis`, değişmedi) istek sürerken düğmede `… iptal ediliyor` yazıyor, yoklama sürüyor, sonuç bir sonraki yoklamada (`finished` + `cancelled`); dönen `sonlandirma` arayüzde gösterilmiyor (istenirse ÖL-8).

### Ana oturum

- İki test yaması (`GS1__test_p17_iptal.py.patch`, `GS1__test_ol4_ilerleme.py.patch`; ikisi de `git apply --check` temiz) bu dal main'e alınırken uygulanmalı; yamasız tam takımda beklenen 11 kırmızı kalem 8'de.
- `ui/index.html`'deki OL4 yaması bu dalda uygulandı (ana oturumun ayrıca uygulamasına gerek yok; uygularsa bağlam tutmaz).
- `mutation_specs_p17.json`'da üç `find` düzeltildi (kalem 6).
- Riskler: (1) `_IzlenenHatalar` `ctx.errors`'un türünü `list` alt sınıfına çeviriyor (eşitlik, `+`, JSON, dilim aynı; `type(x) is list` denetimi yapan kod bozulur — depoda `ctx.errors` için böyle bir denetim aranmadı). (2) Adımın kendi açtığı iş parçacığından paralel düzeyde eklenen hata o adıma yazılmaz → `bitti` görünür (sıralı kipte görünür). (3) `atlandi` yalnız `*_status = "disabled"` döndüren üç adımda. (4) `cancel_job` HTTP isteği en çok ≈ 7 sn sürebilir. (5) `son_cikti_yasi_sn` günlüğün `st_mtime`'ı: `--verbose` dışı satır (ör. Rich çubuğu) da günlüğü tazeler; yaş "son olay" değil "son çıktı"dır (hükmün tanımı).

## Koşu kökü

`~/karadul_olcum/runs/dalga1-2026-11-23/GS1/` — **29 MB** (23:23, `du -sh`; `ozet/` 236 KB). Özet `ozet/`: `h7_abd.json`, `h7_c.json`, `h7_ce.json`, `ornek_c.txt`, `ek_xrs.json`, `h3_iptal.json`, `h3_iptal_jvm.json`, `cat_olc.json`, `h2_ayri.json`, `cat_ilerleme_satirlari.txt` (126), `cat_uptime_{bas,son}.txt`, `kuyruk_GS1.txt`, `gs1.log`, `eski.log`, `cocuk_*.stderr`. Betikler `betik/` (`cat_kos.zsh`, `cat_olc.py`, `h2_ayri.py`, `spec_uret.py`, `eski_mutasyon.py`, `mutasyon.zsh`, `tam_takim.zsh`, `yama_uret.py`); depoda `scripts/arge/gs1/{sigterm_olc,iptal_olc,xrs_olc}.py`. Ara ürün (silinebilir; ana oturum siler): `cat/{ws,out,cache}`, `yamali_kopya/`, `mutasyon/`, `tam_takim/`, `olcum/`. Ürün ağacı `~/karadul_olcum/urun-8b5ae8e7` (detached worktree, altı bağ; kökte `karadul.yaml` yok) silinmedi.

## Commit'ler (dal `worktree-agent-abf132b4e0a909dee`, push yok)

`8cc80acf` ilerleme dosyası · `21bec7ac` ön kayıt · `a836acaf` hüküm 7 ölçümü · `0c6531c3` kesin iptal + testler + p17 test yaması · `8b5ae8e7` adım / aşama olayları + son çıktının yaşı + `index.html` + testler + ol4 test yaması · `a191c5d3` mutasyon tanımı + iki sınamanın ayırt ediciliği · `8e8801b5` H1–H5, mutasyon, p17 tanım düzeltmesi · bu commit kapanış.

## PAKET BİTTİ
