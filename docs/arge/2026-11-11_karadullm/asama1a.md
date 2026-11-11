# KaradulLM Aşama 1a: arka uç çekirdeği

- **Tarih:** 2026-11-11. **Dal:** worktree `worktree-agent-af7dbea1d7e0fa879`, taban `main` 1c78ec6.
- **Kapsam:** tasarımın (`tasarim.md`) §10 Aşama 1'inin ilk yarısı: arka uç, hız yoklaması, bellek bekçisi, tur şeması, denetim günlüğü. Ajan döngüsü (`agent.py`), bağlam (`context.py`), araçlar (`tools/`), denetim kuralları (`guard.py`), öneri kuyruğu, arayüz uçları ve `scripts/measurement/karadullm_zemin.py` bu işte yok.
- **Koşulmayanlar:** gerçek model, `llama-server`, ağ isteği. Testlerin hepsi sahte `Popen`, sahte HTTP taşıyıcısı ve betikli sahte arka uçla çalışır.
- **Kör setler okunmadı.**

## 1. Yazılanlar

| Dosya | Ne yapar | Tasarım maddesi |
|---|---|---|
| `karadul/lm/__init__.py` | Paket tanımı; içe aktarmada yan etki yok. Paketin bütün sayısal sabitleri burada (kök etiketiyle: pilot / tasarım / [seçim] / [bu iş]) | §2.1; proje kuralı (sabit tek yerde) |
| `karadul/lm/backend.py` | `Backend` soyutlaması: `start`, `stop`, `health`, `chat(messages, schema, stream)`, `capabilities`, `identity`. Üç gerçekleme: `LlamaServerBackend`, `OpenAIEndpointBackend`, `FakeBackend` | §2.1, §2.2 "Yerel sunucu", "Kullanıcı uç noktası", §6.2 "Model sunucusu", "Ağ kapalı öntanımı", "Anahtar" |
| `karadul/lm/probe.py` | Hız yoklaması (iki istek; P, G, ö), iki hesap yolu (`timings` / akış), T̂ ve kip kuralı, kayan medyan | §2.2 "Hız yoklaması", §8.3 |
| `karadul/lm/memory_guard.py` | `llama-server` için RSS + footprint ölçümü, 20 GiB eşiği, artalan bekçisi, aşımda durdurma çağrısı | §2.2 "Bellek bekçisi" |
| `karadul/lm/protocol.py` | Düz `anyOf` zarfı, kendi şema doğrulayıcısı, pilotun ayrıştırma kopyası, "ad öner" cevap şeması, L1/L2/L3 kuralı ve tek onarım turu | §3.1, §2.2 yetenek düzeyi tablosu |
| `karadul/lm/audit.py` | Denetim günlüğü (JSONL), oturum dosyası yolu, anahtar ve ham veri ayıklama | §5.4, §2.4 |
| `tests/test_lm_backend.py`, `test_lm_probe.py`, `test_lm_protocol.py` | Sahte arka uçla birim testleri ve pilot kopyalarının eşitlik testleri | §9.3, K-P0 kalıbı |
| `scripts/measurement/mutation_specs_lm_cekirdek.json` | Mutasyon tanımı; her test işlevi en az bir mutantın hedefi | §9.3 |

### 1.1 Yerel sunucu (`LlamaServerBackend`)

- **Komut:** `build_llama_command` pilotun `LlamaSunucu.komut` çıktısıyla aynı sırada aynı bayrakları üretir (`llm_pilot.py:725-734`), sonuna `--api-key <64 onaltılık basamak>` ekler. `--host 127.0.0.1`; kapı `find_free_port` ile çekirdekten alınır. Eşitlik: `test_komut_pilot_bayraklariyla_ayni`.
- **Süreç:** `Popen(..., stdin=DEVNULL, process_group=0)`; `start_new_session` yok (gerekçe `ui/server.py:1812-1818`). PID dosyası `<durum_dizini>/llama_server.pid`: `{"pid", "port", "ikili"}`. Kapı rastgele olduğu için pilotun `_kayitli_pid` denetimi (`llm_pilot.py:711-723`) kapıyı dosyadan okur.
- **Her hata yolunda kapatma:** başlatmadaki her istisna (ikili yok, `Popen` hatası, erken çıkış, hazır olmama, kesme) `_shutdown("hata")` çağırır: SIGTERM → `STOP_WAIT_SEC` bekleme → SIGKILL, PID dosyasındaki yetim sürecin kapatılması, PID dosyasının silinmesi, anahtarın unutulması. Başlatma başında PID dosyasında kalmış yetim süreç (ikili yolu ve kapı eşleşirse) kapatılır; yabancı süreç kapatılmaz. `atexit` ile çıkışta durdurma; boşta `IDLE_SHUTDOWN_SEC` sonra `stop_if_idle`.
- **Künye:** başlatmada ikilinin ve şablonun sha256'sı, `--version` satırları, model yolu ve boyutu, gizlenmiş bayraklar. Model dosyasının sha256'sı hesaplanmaz (aşağıda §2 madde 9).
- **Sohbet:** ilk istekte kendini başlatır; istekler kilitle sıraya girer (`--parallel 1`). Süreç istek sırasında ölürse arka uç `hata` durumuyla kapanır; süreç yaşıyorsa geçici HTTP hatası sunucuyu kapatmaz.

### 1.2 Kullanıcı ucu (`OpenAIEndpointBackend`)

- Loopback tanımı ad çözümlemesiz: `127.0.0.0/8`, `::1`, `localhost`. Loopback değilse `allow_network=True` verilmeden `start`, `health`, `probe_level`, `chat` HİÇBİR istek atmadan `NetworkConsentRequired` yükseltir (`test_loopback_olmayan_uca_onaysiz_istek_atilmaz`: taşıyıcı çağrı sayısı 0).
- URL'de kullanıcı bilgisi reddedilir; künyeye ve günlüğe yalnız şema + makine + kapı + yol girer (sorgu dizgisi anahtar taşıyabilir).
- **Yetenek düzeyi (§2.2):** önce L3 (`json_schema`, istemde şema anlatılmaz; çıktı şemaya uymalı), sonra L2 (`json_object`; çıktı bütünüyle JSON nesnesi), yoksa L1. Uç bir özelliği yalnız 400/404/415/422/501 ile reddederse "desteklemiyor" sayılır; 401 gibi başka hatada düzey belirlenmez ve hata yükselir. Yoklanmadan şemalı istek atılmaz (`CapabilityUnknown`).
- HTTP katmanı standart kitaplık (`urllib`). Loopback isteğinde vekil sunucu kullanılmaz; hiçbir istekte yönlendirme izlenmez (loopback uç uzak makineye yönlendirerek onay denetimini aşabilirdi).

### 1.3 Hız yoklaması ve kip

- İstek 1: yapay metin (~1.000 jeton hedefi, ilk satırda her yoklamada yeni etiket), 1 jeton üretim. İstek 2: istek 1'in iletileri + istek 1'in cevabı (asistan turu) + kısa kullanıcı eki, 64 jeton üretim. İkisi de akışlı.
- `timings` yolu: P = istek 1 `prompt_per_second`, G = istek 2 `predicted_per_second`, ö = istek 2 `cache_n` ≥ %95 × ortak önek.
- Akış yolu: G = (üretilen − 1) / (t_son − t_ilk); ö = `cached_tokens` ≥ %95 × ortak önek; P = (N₂ − N₁) / (t_ilk₂ − t_ilk₁), N = işlenen istem jetonu (`prompt_tokens − cached_tokens`).
- Her değer geçerlilik koşulu tutmazsa `None`; nedeni `notes`'ta. Ölçülmeden önce bütün alanlar `None`; ölçüm yokken kip `None` (uydurulmaz).
- T̂ = N_yeni / P + M / G (M = 80; N_yeni = 2.500, ö = 1 ve seçimde ön işleme açıksa 30). Tasarım §8.3 tablosunun A-yük (28,7 sn), A-boş (16,7 sn) ve ön işlemeli (7,6 sn) değerleri testte aritmetik denetimi olarak yeniden üretilir.
- Kip: ilk kararda T̂ ≤ τ etkileşimli. Bant: etkileşimliden kuyruğa T̂ > τ·1,2; kuyruktan etkileşimliye T̂ ≤ τ·0,8. τ ve bant `__init__.py`'de tek yerde.

### 1.4 Tur protokolü

- Zarf `build_envelope(tools, final_properties, final_required)`: kökte yalnız `anyOf`; araç başına `{"kind": const "call", "tool": const <ad>, "args": {...}}`, sonda `{"kind": const "final", ...}`; her dal `additionalProperties: false`.
- `check_schema` desteklenen alt kümeyi zorlar (bilinmeyen anahtar sözcük, `$ref`, `^…$` olmayan desen, aynı düzeyde `properties` + `anyOf`, yazılmamış `additionalProperties` hata verir). Gerekçe: llama.cpp desteklemediği özelliği sessizce atlıyor ve öntanımlı `additionalProperties`'i JSON Schema'dan farklı yorumluyor (§3.1, [K-D1]).
- `validate` kendi yazılmıştır; `true`/`1` ve `false`/`0` ayrı değerlerdir. `jsonschema` kuruluysa test aynı derlemde iki doğrulayıcının aynı hükmü verdiğini denetler (ürün kodu `jsonschema`'ya bağlı değil).
- `parse_turn`: düşünme bloğu atılır, ilk dengeli JSON nesnesi okunur, şemayla denetlenir → `gecerli` / `sema_ihlali` / `gecersiz` / `butce_asimi` / `ret`.
- `next_action`: L2'de biçim hatası ilk kez görülürse `onar`, sonra `vazgec`; L1'de yeniden deneme yok; L3'te onarım yok; bütçe aşımı ve ret hiçbir düzeyde onarılmaz. `repair_message` modelin yazdığı değeri geri göndermez, yalnız alan yolu ve kural adı.
- **Pilot kopyası:** `think_end`, `first_json`, `parse_name_answer` (`llm_pilot.py:498-557`) ve jenerik ad kuralı `is_placeholder_name` (`function_f1.py:136-164` + `tests/benchmark/metrics.py:647-663`). Eşitlik sapma dizgileri ve tohumlu 300 rastgele metin × 3 bitiş nedeni × 6 koşul × 3 adresle kilitli.

### 1.5 Denetim günlüğü

- Olaylar: `kunye`, `model_istegi` (her istek, hatalı olanlar dahil tek kayıt; amaç etiketiyle), `yoklama`, `yetenek_yoklamasi`, `bellek_durdu`, `baslatma_hatasi`, `durdurma`.
- `model_istegi`: istek gövdesi (iletiler hariç), iletilerin sha256'sı ve bayt uzunluğu, `usage`, `timings`, bitiş nedeni, süre, ilk / son jeton zamanı, cevabın sha256'sı ve bayt uzunluğu. Cevap metni ve iletiler yazılmaz.
- Anahtar: arka uç anahtarı `add_secret` ile kaydeder; her satır yazılmadan önce gizli değerler `<gizli>` olur; `authorization`, `headers`, `messages`, `api_key` vb. alanların değeri hiç yazılmaz; `bytes` yalnız sha256 + uzunluk; tanınmayan nesne `repr` ile değil tür adıyla. Dosya 0600, dizin 0700.

## 2. Tasarımdan sapmalar ve gerekçeleri

1. **Yoklama 2 "ek" desenindedir.** Tasarım "aynı istem + 16 jetonluk ek" diyor. Ek kullanıcı iletisinin içine yazılsaydı karma mimarili Qwen3.8 geri sarma isterdi ve pilotun bayraklarıyla ö hep 0 çıkardı (zemin §4, "dal" satırı), oysa ajan döngüsünün büyüyen konuşmasında önek kullanılıyor ("ek" satırı). Bu yüzden ek, istek 1'in cevabından sonra yeni bir kullanıcı turu olarak geliyor. K-Z1'in tanımı da "sona eklenmiş istem"dir. Sonuç: ö "sona ekleme" yeniden kullanımını ölçer; aynı sistem istemiyle yeni konuşmanın ("dal") yeniden kullanımını ölçmez. §8.4 madde 9'daki "seçimde ön işleme" ancak kesin sona ekleme olarak gerçeklenirse bu ölçümden yararlanır (sonraki iş).
2. **Akış yolunda P çoğu uçta boş kalacak.** Tasarımın formülü (N₂ − N₁) / (t_ilk₂ − t_ilk₁) gerçeklendi, ama iki koşulla: N işlenen jetondur (önbellekten geleni düşer) ve |ΔN| ≥ 256 olmalı, işaretler tutarlı olmalı. 16 jetonluk ekte önbellek kullanılmazsa ΔN ≈ +30'dur ve fark ağ gürültüsünde kaybolur → P `None`. P bu yolda yalnız uç `cached_tokens` bildirirse ve önbellek kullanıldıysa (ΔN ≈ −N₁) ölçülür. Uç önbellek bilgisini vermiyorsa işlenen jeton bilinemez ve P `None`. Kip o zaman "ölçülemedi" kalır. Çözüm seçenekleri (karar gerekiyor): üçüncü bir istek (yeni metin, farklı uzunluk) ya da `timings` yoksa uzun bir ek. Bu işte uydurma değer üretmemek için boş bırakıldı.
3. **Bu işte konmuş eşikler** (tasarımda yok; `__init__.py`'de "[bu iş]"): `PROBE_MIN_PREFILL_TOKENS = 256`, `PROBE_MIN_GEN_TOKENS = 8`, `PROBE_WORDS = 460` (zemin yoklamasının 1.200 sözcük → 2.594 jeton oranından), `CAPABILITY_PROBE_MAX_TOKENS = 32`, `ERROR_EXCERPT_CHARS = 300`.
4. **Kip bandının yorumu.** "Değişim ancak kayan medyan τ'nun %20 altına ya da üstüne geçtiğinde" şöyle gerçeklendi: etkileşimliden çıkış T̂ > 1,2τ, kuyruktan çıkış T̂ ≤ 0,8τ; eşitlik ana kuraldaki gibi etkileşimli taraftadır. Kip durumu `SpeedTracker`'da tutulur. Araştırmacının kipi elle değiştirmesi (§7.1) arayüz işidir.
5. **Kayan medyan:** yoklamanın P ve G'si ilk gözlemdir; P ve G ayrı kuyruklarda, son 5 gözlem. Hangi görev gözleminin P olarak beslenebileceği (ör. önbellekten gelen 37 jetonluk istemin "hızı" P değildir) ajan döngüsünün işidir; `observe` geçerli sayıyı kabul eder, karar vermez.
6. **Bellek bekçisinde seçim farkı.** Pilot `ps -axo` ile LM Studio motor süreçlerinin en büyüğünü seçer ve footprint'i yalnız RSS ≥ 0,2 GiB ise ölçer; ürün kendi PID'ini bilir ve onu her seferinde ölçer. Tanım aynı (RSS + footprint, 3 basamak, `≤ 20` geçer) ve pilotun `model_bellegi` çıktısıyla aynı sahte `ps`/`footprint` girdisinde eşitliği testli. Footprint ölçülemezse alan `None`, örnek `complete=False` (üst sınır o zaman yalnız RSS; pilotta da `fp or 0.0`).
7. **Yerel uçta L3 yoklanmaz, bildirilir** (zemin §5: düz `anyOf` zarfı bu motor sürümünde derlendi, 10/10). **"Ad öner" cevap şeması (`NAME_ANSWER_SCHEMA`) motorda derlenmedi:** iki düz dal, `{"type": "null"}`, mantıksal `const`, dizi öğesi deseni. Z5 yalnız dizgi `const`, `enum`, `pattern`, `maxLength` ve `additionalProperties: false` taşıyan zarfı sınadı. Bu şema ve araç argümanlarındaki `integer` + `minimum`/`maximum` kullanılmadan önce Z5 benzeri bir derleme denemesine girmeli.
8. **Kullanıcı ucunda düşünme denetimi öntanımlı kapalı.** `chat_template_kwargs` standart OpenAI ucunda bilinmeyen alan olarak reddedilebilir; `thinking_control=True` ile açılır. Yerel uçta açık (pilotun gövdesiyle aynı; `test_istek_govdesi_pilotun_cozme_ayarlariyla_ayni`).
9. **Model dosyasının sha256'sı başlatmada hesaplanmaz** (16 GiB ≈ 8 sn ve üzeri); künyede `None`. Künyede Karadul commit'i yok (çalışma anında git yok); oturum künyesi sonraki işte.
10. **Ebeveyn bekçisi arka uçta değil.** Yetim koruması burada PID dosyası (sonraki başlatmada temizlik) ve `atexit`'tir. Arayüz sunucusu SIGKILL ile ölürse `llama-server` sonraki başlatmaya kadar yaşar. `ui/server.py`'nin `_parent_watchdog` ve `_kill_jobs` yoluna `backend.stop` bağlanması Aşama 3'tür.

### 2.1 Tasarımdaki satır başvurularının denetimi

Açılıp doğrulandı (2026-11-11, 1c78ec6):

| Tasarımdaki | Gerçek | Not |
|---|---|---|
| `ui/server.py:1695-1701` (`process_group=0` gerekçesi) | **`ui/server.py:1812-1818`** | Dosya tasarımdan sonra değişmiş |
| `ui/server.py:1650` (`_running_job`) | **`ui/server.py:1767`** | aynı |
| `ui/server.py:2081-2092` (ebeveyn bekçisi) | **`ui/server.py:2198-2210`** | aynı |
| `overrides.py:63-78` | `overrides.py:62-78` | bir satır |
| `llm_pilot.py:725-734`, `:755-766`, `:768-788`, `:711-723` | tutuyor | |
| `llm_pilot.py:594-632` (`model_bellegi`), `:65`, `:986` | tutuyor (`bellek_ust` 986-991) | |
| `llm_pilot.py:500-557`, `:511` | tutuyor (blok yorumu 498'de başlıyor) | |

## 3. Testler ve mutasyon

Koşular 2026-11-11, worktree'de, 4668e83 üzerinde.

| Komut | Sonuç |
|---|---|
| `PYTHONDONTWRITEBYTECODE=1 python -m pytest tests/test_lm_backend.py tests/test_lm_probe.py tests/test_lm_protocol.py -q -p no:cacheprovider` | **110 geçti** (backend 54, probe 14, protocol 42; 72 test işlevi) |
| `PYTHONDONTWRITEBYTECODE=1 python -m pytest tests -q -p no:cacheprovider -k "lm or public_api"` | 396 geçti, 1 atlandı |
| `PYTHONDONTWRITEBYTECODE=1 python -m pytest tests -q -p no:cacheprovider` | 7.969 geçti, **4 düştü**, 56 atlandı. Düşen dördü (`test_deobfuscator.py` 3, `test_pipeline.py::TestPipelineExecution::test_identify_and_static`) `@babel/parser` bulunamadığı için: worktree'de `scripts/node_modules` yok. Bu işle ilgisiz; ana ağaçta dizin var |
| `PYTHONDONTWRITEBYTECODE=1 python scripts/mutation_probe.py --spec scripts/measurement/mutation_specs_lm_cekirdek.json` | **132 / 132 öldü**, 0 hayatta, 0 hata. Ölümlerin hepsi test başarısızlığı (125'i tek başarısız test; 7'si parametreli testte bir başarısız durum); toplama hatasıyla ölen yok |

- 72 test işlevinin her biri en az bir mutantın hedefidir (sayım betikle yapıldı: tanımdaki `test` alanları ile test dosyalarının AST'si).
- İlk koşuda bir mutant hayatta kaldı: `first_json`'un dizi de kabul etmesi. Bu **eşdeğer mutanttı**: arama yalnız `{` konumlarından başladığı için çözülen değer hiçbir zaman dizi olamaz. Yerine "ilk çözülemeyen `{`'den sonra aramayı keser" mutantı kondu; pilot eşitlik derlemine onu sınayan bir örnek eklendi.
- İlk yazımda bir eksik de görüldü: izleyici kip durumunu unutsa (bant kuralı hep "önceki kip yok" ile çalışsa) hiçbir test düşmüyordu. `test_kayan_medyan_ve_kip_durumu`'na kuyrukta T̂ = 9 sn'nin kuyrukta tuttuğu durum eklendi; mutantı (`p_kip_unutulur`) öldürüyor.
- Testler gerçek süreç açmaz ve ağ isteği atmaz. Tek istisna `find_free_port`'un kendi testidir: çekirdekten boş kapı almak için `127.0.0.1:0`'a soket bağlar ve hemen kapatır (istek yok). İçe aktarma testi alt süreçte `Popen`, `socket.connect` ve `socket.bind`'ı yasaklayıp paketi içe aktarır.

## 4. Sonraki işe (ajan döngüsü, araçlar) bırakılan arayüzler

- `Backend.chat(messages, schema=None, stream=False, *, max_tokens=MAX_TOKENS_STEP, on_token=None, purpose="gorev") -> ChatResult`. `ChatResult`: `content`, `finish_reason`, `usage`, `timings`, `prompt_tokens`, `completion_tokens`, `cached_tokens`, `duration_sec`, `first_token_sec`, `last_token_sec`. Her çağrı kendi `model_istegi` kaydını yazar.
- `Backend.capabilities().level` → `protocol.next_action(level, parsed, repairs_done)`; `protocol.repair_message(parsed)` onarım turunun iletisi.
- `protocol.build_envelope(tools, final_properties, final_required)`; araç argüman şemaları `check_schema`'dan geçmeli (`additionalProperties` açık yazılı). `protocol.parse_turn(content, finish_reason, schema) -> TurnParse(status, obj, branch, issues, ...)`.
- K0 "ad öner": `protocol.NAME_ANSWER_SCHEMA` (L3'te `response_format`) ve `protocol.parse_name_answer(content, finish_reason, abstain_allowed=..., address=...)` (pilotun durum sınıfları; K-P1 için aynı puanlayıcı). Kanıt kimlikleri `kanit` alanında, `^r[0-9]{1,9}$`.
- `probe.run_probe(backend, audit=...) -> ProbeResult`; `probe.SpeedTracker`: `seed_from_probe`, `observe(prefill_tps, gen_tps)`, `decide(prefill_on_select) -> ModeDecision(mode, t_hat_sec, first_token_sec, first_token_ok, ...)`.
- `memory_guard.MemoryGuard(pid_provider=lambda: backend.pid, on_exceed=lambda s: backend.stop("bellek"), audit=...)`: her model çağrısından sonra `check()`, boşta `start(MEMORY_POLL_SEC)`. Yalnız `backend.capabilities().memory_guard` doğruysa kurulur.
- `audit.AuditLog(audit.session_log_path(ikili_sha256, oturum_kimligi))`; arka uçlar kendi anahtarlarını kaydeder.
- `LlamaServerBackend.stop(reason)`: `istek` | `bosta` | `analiz` | `bellek` | `hata`; `stop_if_idle()` periyodik çağrılmalı (Aşama 3'te sunucu iş parçacığı).

## 5. `karadul/config.py`'ye taşınacak sabitler

`karadul/lm/__init__.py`'deki hepsi: `CONTEXT_TOKENS`, `MODEL_SEED`, `MAX_TOKENS_STEP`, `MEMORY_LIMIT_GIB`, `REQUEST_TIMEOUT_SEC`, `READY_TIMEOUT_SEC`, `HEALTH_POLL_SEC`, `HEALTH_REQUEST_TIMEOUT_SEC`, `STOP_WAIT_SEC`, `MAX_TOKENS_CHAT`, `INTERACTIVE_TAU_SEC`, `MODE_BAND`, `FIRST_TOKEN_TARGET_SEC`, `ROLLING_WINDOW`, `IDLE_SHUTDOWN_SEC`, `MEMORY_POLL_SEC`, `REF_PROMPT_TOKENS`, `REF_PROMPT_TOKENS_PREFILLED`, `REF_OUTPUT_TOKENS`, `PROBE_PROMPT_TOKENS_TARGET`, `PROBE_FIRST_MAX_TOKENS`, `PROBE_GEN_TOKENS`, `PROBE_REUSE_FRACTION`, `RATIONALE_MAX_CHARS`, `MEMORY_ROUND_DIGITS`, `PROBE_WORDS`, `PROBE_MIN_PREFILL_TOKENS`, `PROBE_MIN_GEN_TOKENS`, `CAPABILITY_PROBE_MAX_TOKENS`, `ERROR_EXCERPT_CHARS`. `karadul/config.py`'ye bu işte dokunulmadı. Pilot kopyası olanlar (ilk dokuz) taşınırken eşitlik testi yerinde kalmalı.

## 6. Doğrulanmayanlar ve riskler

- **Gerçek `llama-server` ile hiçbir yol koşmadı.** Özellikle doğrulanmayanlar: akışlı istekte `timings`'in son parçada gelip gelmediği; `stream_options.include_usage`'ın bu yapıda kabul edilip edilmediği (gelmezse yoklama kendiliğinden akış yoluna düşer); `/health`'in anahtar istemediği varsayımı (başlıkla gönderiliyor); `--version` çıktısının biçimi (pilotla aynı süzgeç).
- **Anahtar komut satırında.** `--api-key` aynı kullanıcının süreçlerine `ps` ile görünür. `--api-key-file` bu yapıda var mı doğrulanmadı (ikili çalıştırılmadı).
- **Kapı yarışı:** boş kapı bulunup soket kapatıldıktan sonra başka bir süreç onu alabilir; o zaman `llama-server` erken çıkar ve başlatma hatayla (kapatılarak) biter, yeniden deneme yok.
- **`localhost`** ad çözümlemesiz loopback sayılıyor; `/etc/hosts` değiştirilmişse yanlış olabilir.
- Yetenek yoklamasında model şemayı istemsiz tutturursa L3 sanılabilir; istem şemayı anlatmadığı için olasılık düşük ama sıfır değil. L2 yanlış sınıflaması zararsızdır (sunucu tarafında doğrulama + onarım).
- Doğrulayıcı JSON Schema düzenli ifadesi yerine Python `re` kullanır; desenler basit tutulmalı.
- Akış yolundaki P'nin boş kalma sorunu (§2 madde 2) kullanıcı uçlarının çoğunda kipin "ölçülemedi" kalması demek.

## Ek (ana oturum, 2026-11-11 14:42): gerçek yerel sunucuyla duman testi

Ajan bu işte gerçek sunucu çalıştıramadı (yasaktı). Birleştirmeden sonra ana oturum, makine boşken (yük ortalaması 3,0) paketi gerçek `llama-server` ve Qwen3.8-27B Q4_K_M ile bir kez çalıştırdı. Betik `zemin/lm_duman.py`, çıktı `zemin/lm_duman_sonuc.json`. Tek koşu; tekrar edilmedi.

| | Sonuç |
|---|---|
| Başlatma (`LlamaServerBackend.start`, `/health` hazır) | 10,6 sn |
| Yetenek düzeyi | L3 |
| Hız yoklaması (`probe.run_probe`, `timings` yolu) | önek 184,0 jeton/sn; üretim 17,3 jeton/sn; süre 9,4 sn |
| Önek yeniden kullanımı ("ek" deseni) | var: 1 013 / 1 013 jeton önbellekten |
| "Ad öner" için beklenen süre ve kip | 18,2 sn → `kuyruk` (τ = 10 sn) |
| Şemaya zorlanmış istek (`NAME_ANSWER_SCHEMA`, 128 jeton) | 7,8 sn; `finish_reason: length`; ayrıştırma hükmü `butce_asimi` |
| Bellek (`memory_guard.measure_process`) | 17,471 GiB (RSS 16,353 + footprint 1,118) |
| Kapatma | `stop("istek")` sonrası `pgrep llama-server` boş |

Doğrulananlar (§6'daki "gerçek sunucuyla koşmadı" maddelerinden): başlatma ve `/health`, `timings` alanlarının gelmesi, önek yeniden kullanımının ölçülmesi, şemalı isteğin motorda derlenmesi, bellek ölçümü, kapatma. Denetim günlüğünde anahtar ya da yetki başlığı yok.

**Yeni bulgu (Aşama 1b'de düzeltilmeli):** şemalı istekte model adı ve gerekçeyi doğru doldurdu, sonra `kanit` dizisini sınırsız doldurmaya başladı (`"r8","r1","r2",…`) ve 128 jetonluk bütçeyi tüketti; cevap geçersiz sayıldı. Şema dizinin uzunluğunu ve öğelerini sınırlamıyor; dilbilgisi kısıtı da sonsuz diziye izin veriyor. Düzeltme: `kanit` için `maxItems` ve öğe değerlerini o istekte gerçekten verilen kanıt kimlikleriyle sınırlayan bir `enum` (istek başına kurulur), ya da K0'da alanı sunucunun doldurması. Yapay tek örnek; oran ölçülmedi.

Boş makinedeki hız (184,0 / 17,3), tasarım §8.1'in "A-boş" sınıfı için kullandığı başvuru değerine (195 / 20,5; başka model) yakın ama altında; §8.2'deki süreler bu ölçümle yeniden hesaplanmalı.
