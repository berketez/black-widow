# Kapanış denetimi — Ajan B (ARAYUZ, LM, BICIM, GHIDRA, MEK)

Yayın kapısı Y3 (`YAYIN_KAPISI.md`), brif `DENETIM_BRIF.md`. Salt okur denetim, 2026-11-19.

## Künye

- **Denetlenen kod:** main HEAD `2381dce` (sürüm 1.24.1; `karadul/__init__.py:12`, `pyproject.toml:7`, `Info.plist:17-18` aynı). Çalışma ağacında kod değişikliği yok (`git status`: yalnız başka işlerin izlenmeyen `docs/arge/2026-11-19_mythos/*`, `scripts/arge/` dizinleri ve ajan A'nın raporu).
- **Ölçüm tabanı:** birleşik 119 ölçümü `a62f15e`'de koşuldu (`docs/arge/2026-11-19_birlesik_olcum/sonuc.md`). HEAD ondan 93 commit ileride (P02b, P16d, P-S4, P12c, P05c, P22c, P22h, P20b, P18). Ölçüm sayıları bu kulvarlarda a62f15e'nin kanıtıdır; HEAD'de yeniden koşulmadı (Ghidra yasak).
- **Kulvar önekleri:** `DIZIN.md`'dekiyle aynı (ARAYUZ 19, LM 8, BICIM 15, GHIDRA 16, MEK 14 = **72 bulgu**). Küçük kalemler kulvar dosyalarının "Küçükler" bölümlerinden: ARAYUZ 20 satır (1'i bulgu değil), LM 12, BICIM 12, GHIDRA 14 = **57 kalem**. MEK kulvarının "Küçükler" bölümü yok.
- **Kaynak kaydı:** `docs/arge/2026-11-18_onarim/DURUM.md`, paket dosyaları `P*.md`, `gonderim/OKU.md`.

## Yöntem

- Kritik ve yüksek bulguların hepsi bugünkü koddan doğrulandı (dosya:satır). Güvenlik bulgularının bir kısmı ayrıca salt okur komutla yeniden denendi.
- Orta ve düşük bulgularda paket kaydına dayanıldı, çoğunda ek olarak koddan bakıldı. Kaydı olmayan satır `açık` yazıldı.
- Bu denetimde çalıştırılanlar. Hepsi scratchpad'te ya da depo dışı yazmasız; sonunda `git status` temiz kaldı:
  1. BICIM-04 yükleri bugünkü üreticilerle (`JavaBinaryAnalyzer._generate_build_gradle`, `DotNetBinaryAnalyzer._generate_csproj`). Üç çıktıda da `execute`, `touch` ve `Exec` yok.
  2. BICIM-07: scratchpad'te `evil.py` varken `resolve_target("evil.pyc")` ve `resolve_target("evil.sub")` çağrıldı (`sys.path`'te `''` ile). İkisi de `FileNotFoundError` verdi; işaret dosyası oluşmadı.
  3. GHIDRA-04 / 07: scratchpad YAML'larıyla `Config.load` ve `config validate` denendi (sonuçlar satırlarda).
  4. MEK-01: boş dosya ve düz metinle `python -m karadul analyze … --skip-dynamic --output-dir <scratchpad>` koşuldu (`KARADUL_CACHE_DIR` geçici). İkisi de çıkış 1 verdi; neden ekranda.
  5. `pytest -p no:cacheprovider tests/test_p20_webpack_modules.py`: 10 geçti. `tests/test_pguv_frida.py`: 12 geçti.
- Ghidra, tam takım, arayüz sunucusu ve model sunucusu koşulmadı.
- Not: Reviewer ajan tanımı `~/.claude/team-state/discussion.md`'ye yazmayı istiyor. Brif "yazabileceğin TEK dosya" dediği için oraya yazılmadı.

Durum sözlüğü: `kapandı` / `kısmen` / `bekletildi (K-n)` / `açık` / `gereksizleşti` / `doğrulanamadı`.

---

## Kulvar ARAYUZ (19 bulgu)

| Kimlik | Önem | Durum | Kanıt |
|---|---|---|---|
| ARAYUZ-01 | KRİTİK | kapandı | P04a (MUH-03, K-1) ve P07. **Kod:** Şablon eşleşmesi kanıt kapısından geçmezse `pending_compositions`'a gider (`reconstruction/engineering/composition_analyzer.py:1083-1098`). Kapı ≥ 2 fonksiyon, ≥ 2 tespit ve çağrı çizgesinde ortak sürücü ister (`:1390-1434`). Rapor yalnız `compositions`'ı iddia eder, bekleyenleri sayı olarak basar (`reporting/report_data.py:683-705`). Tablo hücresi aşama başına fonksiyon listesi gösterir (`sections_render.py:167-176`). **Ölçüm:** masum kapı çıktı kipi, 119 ikili: bileşim yanlış iddiası 451 → 0 (`birlesik_olcum/sonuc.md:34`, `:360`). **Kalan:** genel bileşimler (pipeline / iterative / fork-join, `composition_analyzer.py:1100-1123`) kapıdan geçmiyor; alan etiketi hâlâ alt dizgiden geliyor (P07 "Kalan"). |
| ARAYUZ-02 | YÜKSEK | kapandı | P08 ve P07. **Kod:** Yazıcı `category` / `family` / `tier` alanlarını yazıyor (`pipeline/steps/ghidra_metadata.py:253-257`); `SignatureMatch.family` alanı var (`analyzers/signature_db.py:208`). Okuyucu önce `reconstructed/`'a bakıyor; kayıtta bu alanlar yoksa "veri yok" der, "IOC yok" demez (`report_data.py:476-538`, `:509-512`). **P07:** IOC bölümü 0 → 14/14. Gerçek bir Sliver / Cobalt Strike örneğiyle denenmedi. |
| ARAYUZ-03 | YÜKSEK | kapandı | P17. **Kod:** "F1 ~0.45-0.49" metni yok. Notlar ölçüm künyesinden kuruluyor (`ui/server.py:1404-1457`; yeni2, 1.22.1: 672 / 2 261 yanlış). `tests/test_p17_hakkinda.py` değerlerin kaynak JSON'la aynı kalmasını kilitliyor. **Kalan (Y10 için):** not "Sonraki sürümler bu ölçümü yinelemedi" diyor (`:1450`). 2026-11-19 birleşik ölçümü (havuz %6,6, makro %31,0) panelde yok; yayından önce güncellenmeli. |
| ARAYUZ-04 | ORTA | kapandı | P17; `ui/server.py:1117-1130` (`_SETTINGS_RETIRED`). |
| ARAYUZ-05 | ORTA | kapandı | P17: düğme `network.enabled`'ı açıyor ve gerçek etkisini gösteriyor. P15a: alt izinler ana anahtarı izliyor (`config.py:426-440`). |
| ARAYUZ-06 | ORTA | kapandı | P17: Kaydet var olan dosyayla birleştirerek yazıyor; kaybolan anahtar 4/4 → 0/4. |
| ARAYUZ-07 | ORTA | kapandı | P07: uydurma sayaç 42 → 0. Yama `50f214f`: kaynağı olmayan değer `report.json`'da null. |
| ARAYUZ-08 | YÜKSEK | kapandı | P07. **Kod:** dört üretici aynı veri katmanını kullanıyor (`core/report_generator.py:24-25`, `:321`; `html_report.py:180`; `markdown_report.py:109`; `sarif_report.py:186`). Ortak bölüm sırası: packer, anti_debug, yara, capa, ioc, crypto, naming, compositions (`report_data.py:150`). **P07:** temiz raporda bu bölümler 0 → 14/14. |
| ARAYUZ-09 | ORTA | kısmen | Arayüz yüzü P17'de onarıldı (`ui/server.py:143`, `:511`). CLI `--output` yüzü onarılmadı: P18 "ARAYUZ-09 onarılmadı (gerçek çıktıda etki yok)" diyor; `core/output_formatter.py`'de karşılığı yok. |
| ARAYUZ-10 | ORTA | kapandı | P17: iptal, görünür yoklama hatası, süren işe yeniden bağlanma; çift başlatma 2 → 1. |
| ARAYUZ-11 | ORTA | kapandı | P17: kısmi / başarısız şerit (`ui/index.html:1004`); açılabilen fonksiyon 9 322 / 20 008 → 20 008 / 20 008. Not: arayüzden JS / APK / .NET / Python analizi gözle denenmedi. |
| ARAYUZ-12 | ORTA | kapandı | P17: sayaç "600 / 2587" biçiminde, kesme satırı var. |
| ARAYUZ-13 | ORTA | kapandı | P17: "çözüldü" yerine "ad atandı"; etiket kırılımı gösteriliyor. |
| ARAYUZ-14 | ORTA | kapandı | P17: düzeltme doğru ikilinin özetine yazılıyor (0/14 → 14/14). Özetsiz çalışma alanında 409 dönüyor; anahtar sözcük, tip adı ve çakışan ad reddediliyor (`overrides._validate_name`). |
| ARAYUZ-15 | DÜŞÜK | kapandı | P17; `ui/server.py:945`. |
| ARAYUZ-16 | DÜŞÜK | kapandı | P17 / K-6. Güncelleme sorgusu öntanımlı kapalı; ağ ayarına ve `ui_prefs.json` tercihine bağlı (`ui/server.py:1713-1751`, `ui/app_window.py:189-196`). MEK-04 ile aynı. |
| ARAYUZ-17 | YÜKSEK | kapandı | P07. **Kod:** KRDL001 `reconstructed/algorithms.json`'dan; YARA isabetleri yapılandırılmış kayıttan (paketleyici → KRDL004, derleyici / sıkıştırma → KRDL007 not); KRDL002 ad etiket dağılımından (`reporting/sarif_report.py:125-144`, `:328-331`). **P07:** KRDL001 0 → 117; "(unknown)" 37 → 0. **Birleşik ölçüm:** SARIF yanlışı 81 → 12. Kalan 12, doğru bilinen YARA kurallarının KRDL001 / 007 kayıtları; bunları yanlış sayan masum kapı izleyicisinin kusuru (`sonuc.md:213-231`). |
| ARAYUZ-18 | ORTA | bekletildi (K-1) | P09: `types.h`'de kurtarılan yapı 0, örtüşen alan 0. Adaylar `typed/types_candidates.txt`'te; P18 adayları çıktıya koymuyor. Yapı kurtarmanın kendisi K-1'de bekliyor (P10: `APPLY_REWRITES = False`). |
| ARAYUZ-19 | ORTA | kısmen | Madde 1 (KaradulLM paneli, olay akışı, örümcek) P22c'de yapıldı. Madde 6: `/api/binaries` P17'den beri giriş çiplerinde kullanılıyor. Madde 2 (arayüzde çok adımlı ilişki), 3 (parametre / yerel ad düzeltme, geri alma), 4 (gövde / dizgi / etiket araması) ve 5 (adayın elenme nedeni) için kayıt yok → açık. |

**Arayüz uçlarının güvenliği (koddan, numarasız denetim):**
- `do_GET` bütün `/api/*` isteklerinde (`/api/ping` dışında) `_guard`'dan geçiyor. Koruma Host, Origin ve `X-Karadul-Token` denetliyor (`ui/server.py:2951-2976`, `:2992-2994`). `do_POST` her istekte jeton istiyor (`:3079-3081`).
- Gövde boyutu sınırlı; aşımda 413 (`:2978-2990`).
- PUT / DELETE işleyicisi yok. Sunucu yalnız `127.0.0.1`'e bağlanıyor (`:3178`).
- KaradulLM uçları (`/api/lm/*`, `:2907-2918`) aynı korumadan sonra yönlendiriliyor. Öneri kabulü yalnız öneri kimliği alıyor; ad istemciden alınmıyor (`:2774`).
- Bu denetimde yeni bir açık görülmedi.

### ARAYUZ küçük kalemleri (20 satır)

| # | Kalem (kulvar satırı) | Durum | Kanıt |
|---|---|---|---|
| 1 | `.stripped` eki (`:241`) | kapandı | P17; `ui/index.html`'de `'.stripped'` yok |
| 2 | Sabit HIZLI çipleri + `~/coreutils_gt` (`:242`) | kısmen | Çipler `/api/binaries`'ten (P17). Kişisel yol `~/coreutils_gt` arama yeri olarak duruyor (`ui/server.py:2191`, `:2226`) |
| 3 | `_running_job` yarışı (`:243`) | kapandı | P17 (çift başlatma 2 → 1) |
| 4 | Günlük dosya tanıtıcısı yalnız yoklamada kapanıyor (`:244`) | açık | Kayıt yok; kapanış hâlâ `_job_progress`'te (`ui/server.py:2521-2528`) |
| 5 | Eski iş kimliği çalışma alanını yeniden etkinleştiriyor (`:245`) | kapandı | P17; `ui/server.py:2539-2552` (bir kez etkinleştiriyor) |
| 6 | `_job_progress` bütün günlüğü her yoklamada okuyor (`:246`) | açık | kayıt yok |
| 7 | `bwPollDownload` sonsuz yoklama (`:247`) | açık | kayıt yok |
| 8 | `highlight` dizgi içindeki `//` (`:248`) | açık | kayıt yok |
| 9 | `_clean_c_source` sözcük sınırsız `undefined` (`:249`) | kapandı | P18 kalem 3 |
| 10 | Yedek yol `rglob` düzleştirmesi (`:250`) | kapandı | P18 kalem 3 |
| 11 | `typedef void* undefined;` (`:251`) | kapandı | P18: `typedef uint8_t undefined;` |
| 12 | `dependency_graph.json` çıplak adres (`:252`) | açık | P18 "bakılmayan küçükler" |
| 13 | Before / After örnek seçimi (`:253`) | açık | kayıt yok |
| 14 | "Strings found" ↔ `string_count` (`:254`) | açık | kayıt yok |
| 15 | "daha doğru tip çıkarımı" iddiası (`:255`) | kapandı | Metin `ui/index.html`'de yok (P11 yaması `7ee79ed`) |
| 16 | Eskimiş ağ yorumu (`:256`) | kapandı | Metin `ui/server.py`'de yok |
| 17 | `build_mac_app.sh` HRMA çalışma zamanı (`:257`) | açık | `packaging/macos/build_mac_app.sh:92` öntanım hâlâ `$HOME/HRMA/...` |
| 18 | `Info.plist` yedek sürüm 1.21.1 (`:258`) | kapandı | `Info.plist:17-18` 1.24.1 |
| 19 | Kılavuz "aynı dosya" cümlesi (`:259`) | kapandı | P17 yaması `97686d7` |
| 20 | XSS / jeton denetimi temiz (`:260`) | bulgu değil | Yukarıdaki uç denetimi bunu bugün de doğruluyor |

---

## Kulvar LM (8 bulgu)

Genel taramada KaradulLM "bağlı değil" idi. P22c'den beri arayüze bağlı (`/api/lm/*`). Bulgular artık analistin gördüğü yolda.

| Kimlik | Önem | Durum | Kanıt |
|---|---|---|---|
| LM-01 | YÜKSEK | kapandı | P21 (`643db5c`). **Kod:** `karadul/lm/guard.py` D0–D3 ve D6–D14'ü uyguluyor. D4 / D5 kodlanmadı; `sinanmayan` diye işaretli (`guard.py:105-106`). Öneri `guard.check_proposal`'dan geçiyor (`lm/agent.py:913`), hüküm sonuca yazılıyor (`:209`). `kesin` ya da elle verilmiş adlı hedefte model çağrılmıyor, `protected_report` dönüyor (`:931-933`). **P21:** kanıtsız `while` / `main` / `helper` / `malloc` 4/4 kabul → 0/4 (sahte arka uç). Gerçek modelle koşulmadı (Y7). |
| LM-02 | YÜKSEK | kapandı | P21. **Kod:** Gövde ya da akış okunurken çıkan `OSError` ve `http.client.HTTPException` anahtarı arındırılarak geçici `BackendError`'a çevriliyor (`lm/backend.py:494-516`). `[DONE]` gelmeden kesilen akış `BackendError(transient=True)` (`:414-416`). |
| LM-03 | YÜKSEK | kapandı | P21 + P22b. **Kod:** D6 dizgiden kurulan adı ve simge kopyasını çelişki sayıyor (`guard.py:454-468`). D13 enjeksiyon bayrağı üç yerde: öneri (`:537-539`), özet (`:613-617`), keşif cevabı (`:680-684`). **P21:** enjeksiyon 6/6 → 0/6 (sahte arka uç); masum 8 324 fonksiyonda yanlış alarm 0. Gerçek modelle enjeksiyon denemesi yapılmadı. |
| LM-04 | ORTA | kapandı | P21: gerçek / kestirim oranı 1,06–1,17 → 1,03–1,07 (rakam başına jeton). Gerçek jetonlayıcıyla ölçülmedi. |
| LM-05 | ORTA | kapandı | P21: ebeveyn bekçisi, yetim sunucu 2/2 → 0/2. P22c1 (`0dd707a`): arayüz kapanınca oturum ve sunucu kapanıyor, açılışta yetimler toplanıyor. **Risk:** `LLAMA_API_KEY`'in gerçek `llama-server`'da okunduğu doğrulanmadı. |
| LM-06 | ORTA | kapandı | P21: iptal görev başına, öntanımlı süre bütçesi. P22a: akışta parça başına iptal ve süre denetimi. |
| LM-07 | ORTA | kısmen | P21'de üç durum testli: (a) kopma, (b) iptalden sonraki görev, (c) `2.0` argümanı (`lm/tools/__init__.py:619`). Açık: (d) K1 / K2 şemasının motorda derlenmesi, (e) gerçek modelle ad ve kanıt koşusu, (f) gerçek jetonlayıcıyla karşılaştırma. |
| LM-08 | YÜKSEK | kısmen | P22b aşağıdan yukarı özet zincirini kurdu: `lm/order.py`, `lm/summaries.py`, paketteki `callee_summaries` girişi (`agent.py:990`, `context.py:375`), D0 kısa yolu. Bulgunun sınaması yapılmadı: aynı 5 fonksiyonda özetlerle K0 koşusu ve çekimser oranı yok. Gerçek model hiç koşulmadı (`P22b.md:168`; YAYIN_KAPISI Y7). 5/5 çekimserliğin düzelip düzelmediği bilinmiyor. |

### LM küçük kalemleri (12 satır)

| # | Kalem (kulvar satırı) | Durum | Kanıt |
|---|---|---|---|
| 1 | `find_free_port` TOCTOU (`:248`) | açık | `lm/backend.py:125-129` aynı |
| 2 | `parse_completion` `choices` nesne → `KeyError` (`:249`) | kapandı | P21 (`P21.md:71`) |
| 3 | `reasoning_content` yok sayılıyor (`:250`) | açık | `backend.py`'de karşılığı yok |
| 4 | `llama_server.log` döndürülmüyor (`:251`) | açık | `backend.py:789` `open(..., "ab")` |
| 5 | Araçtaki istisna türü kayda girmiyor (`:252`) | açık | kayıt yok (LM-07 (c) yalnız `2.0` durumunu onardı) |
| 6 | Sonuç kimliği sayacı ajan ömrünce artıyor (`:253`) | açık | kayıt yok |
| 7 | "30 sözcük" ↔ 240 karakter; `gerekce` için `minLength` yok (`:254`) | açık | `lm/protocol.py:477`, `:482` aynı metin |
| 8 | KL-0 kural 5 `[verified]`'ı anmıyor (`:255`) | açık | kayıt yok |
| 9 | K1 komşu listesinde decompile'ı olmayan çağıranlar (`:256`) | açık | kayıt yok |
| 10 | Pilot sunucusu anahtarsız, CORS açık (`:257`) | açık | Pilot ön kayıtlı, bilerek değişmiyor; ürün yolu değil |
| 11 | `probe`, `stop_if_idle`, `memory_guard.start` çağrılmıyor (`:258`) | kısmen | `run_probe` `lm/session.py:752`'de; `stop_if_idle` `ui/server.py:2867-2874`'te (`_lm_idle_tick`). `memory_guard.start` doğrulanamadı |
| 12 | Denetim günlüğü zincirsiz (`:259`) | açık | Tasarım zincir istemiyor; ad yanıltıcı kalıyor |

---

## Kulvar BICIM (15 bulgu)

| Kimlik | Önem | Durum | Kanıt |
|---|---|---|---|
| BICIM-01 | KRİTİK | kapandı | P20 (+ P20b webpack 5 haritası). **Kod:** modül düğümü tek başına geçerli bir programa sarılıyor; ifade deyimi olarak yazılıyor (`scripts/smart-webpack-unpack.mjs:1209-1221`). Modül başına `parse_ok` sayacı var (`:1093`, `:1172-1174`). **Bu denetimde:** `tests/test_p20_webpack_modules.py` → 10 geçti. **P20:** bozuk modül 3/3 → 0 (`node --check`). |
| BICIM-02 | YÜKSEK | kapandı | P-S4. **Kod:** kaynak, deobfuscate aşamasının `artifacts["output_file"]`'ı. `00_original*`, parça dizinleri ve modül dizini aday olmuyor (`stages.py:2726-2766`). |
| BICIM-03 | ORTA | kapandı | P20: kova toplamı 21 ≠ 3 → 3 = 3; `params_applied` ≤ kurtarılan. CLI tablosu gerçek anahtarları okuyor (yama `ba3bfee`). |
| BICIM-04 | KRİTİK | kapandı | P19 (`04314d2`). **Kod, Java:** dış değer `fullmatch` kalıbından geçiyor ve yalnız tek tırnaklı Groovy dizgisine yazılıyor; kalıba uymayan değer yorum satırına bile girmiyor (`analyzers/java_binary.py:78-138`, `:1167-1246`). **Kod, .NET:** NuGet kimliği kalıbı ve `quoteattr` / `escape` uygulanıyor; `PackageReference` yalnız bilinen kimliklere yazılıyor (`analyzers/dotnet_binary.py:1046-1100`). **Bu denetimde:** kulvarın üç yükü bugünkü üreticilerle koşuldu; çıktılarda `execute`, `touch`, `Exec` yok. **Ayrıca:** aşağıda "Ek risk 1" (ILSpy çıktısı süzgeçsiz kopyalanıyor). |
| BICIM-05 | YÜKSEK | kapandı | P19 (`3e47966`). **Kod:** başarı = en az bir kaynak dosya; araç sıfırdan farklı kodla çıkarsa `partial` (`java_binary.py:716-735`, `dotnet_binary.py:956-966`). jadx ve ILSpy kurulu değil; sahte araçla sınandı. |
| BICIM-06 | YÜKSEK | kapandı | P19: ASAR Python'da açılıyor (`analyzers/electron.py:58`, `:698`); depoda `npx` çağrısı kalmadı (`grep`). P-GÜV / P15a: uzak `DtsNamer` yalnız `network.enabled is True` ve `allow_dts_fetch is True` iken kuruluyor (`reconstruction/naming/pipeline.py:77-81`, `:154-158`). `jsnice` ağ kapısı P20'de. |
| BICIM-07 | YÜKSEK | kapandı | P19 (`60dc98f`). **Kod:** çözücüde `importlib` yok (`core/target_resolver.py:20-24`, `:96`, `:316`). Spotlight ve bulanık eşleşme yalnız öneri veriyor (`:233`, `:352`). **Bu denetimde:** scratchpad'te `evil.py` varken `evil.pyc` ve `evil.sub` → `FileNotFoundError`; işaret dosyası oluşmadı. |
| BICIM-08 | YÜKSEK | kapandı | P19 (`216a94b`). **Kod:** .NET kararı DataDirectory[14], CLI başlığı ve `BSJB` kökünden veriliyor (`core/target.py:1085-1093`). CLI başlığı yoksa reconstruct başarısız oluyor ve "yerel PE olarak analiz edilmeli" diyor (`dotnet_binary.py:805-813`). |
| BICIM-09 | YÜKSEK | kısmen | P-S4. **Kapanan:** ana bileşen önce türe göre seçiliyor (`analyzers/app_bundle.py:71-80`, `:135-160`); JAR kendi hattına gidiyor (`stages.py:1554-1556`); Electron JS yeniden kuruluyor (`stages.py:1096-1107`). **Açık:** (4) paketteki her `.framework` ve `.dylib` bütçesiz Ghidra'ya veriliyor (`core/target.py:259-268`, süzgeç ya da süre bütçesi yok). Electron `.app` uçtan uca hiç koşulmadı (P-S4 izi, `OKU.md:81`). |
| BICIM-10 | ORTA | kısmen | P19 (`55630b8`): tek `.pyc`, FAT64, cx_Freeze, wheel / IPA / nupkg tanınıyor. P-S4: UNKNOWN artık JS hattına düşmüyor (MEK-01 denemesinde "hedef türü tanınmadı"). **Açık:** evrensel ikilideki Go / Bun dilimi yalnız `desteklenmiyor` + neden alıyor; cx_Freeze gerçek örnekle doğrulanmadı; yt-dlp_macos'ta .pyc çözülemiyor (kök neden bilinmiyor). |
| BICIM-11 | YÜKSEK | kapandı | P20. **Kod:** imza belirteç sınırıyla aranıyor (`reconstruction/naming/npm_fingerprinter.py:577`). Yalnız dizgi benzerliği olan modül `vendor/`'a gitmiyor, `hints`'e yazılıyor (`:617-659`; `naming/pipeline.py:125-128`). **P20:** zararlı / masum `vendor/` 5/5 → 0/5. |
| BICIM-12 | YÜKSEK | kapandı | P20. **Kod:** README başında güvenilmeyen kod uyarısı var, Quick Start / `npm start` yok (`reconstruction/project_builder.py:69-85`). Uydurma giriş dosyası yazılmıyor (`:191`, `:404`). Dockerfile `--ignore-scripts` kullanıyor (`:636`). Giriş, ad hattının son çıktısından kuruluyor (`stages.py:3121` `named_source=current_file`). **Kalan:** bağımlılıklar `"latest"` (küçük kalem 11). |
| BICIM-13 | ORTA | kapandı | P-S4: Fiddle renderer/816 `project_reconstructor`'a gidiyor; ayrışan JS 65/65. |
| BICIM-14 | ORTA | kapandı | P19 (`18a61fd`). **Kod:** CArchive ve PYZ ortak bütçe kullanıyor; dosya belleğe alınmadan boyut denetleniyor (`analyzers/packed_binary.py:1495-1503`, `:1572-1573`); ad çakışmasında `unique_casefold_name` (`:1256`, `:1399`). |
| BICIM-15 | ORTA | kısmen | **Bağlanan ya da silinen:** `container_classifier` (P19), `_execute_legacy` (P-S2), `beautify` / `babel_transforms` / `babel_pipeline.py` (P20b), `synchrony` bayrak arkasında (P20). **Duran ölü kod:** `reconstruction/jsnice_renamer.py`, `reconstruction/ts_declarations_namer.py`; depoda içe aktaran yok. P20 önerisi "bağlanmasın / takma ad"; silme kararı Berke'de. |

### BICIM küçük kalemleri (12 satır)

| # | Kalem (kulvar satırı) | Durum | Kanıt |
|---|---|---|---|
| 1 | Çift içe aktarma + `~/.dotnet/tools` beyaz listede yok (`:237`) | açık | `dotnet_binary.py:39`, `:45`; `core/safe_subprocess.py` listesinde `~/.dotnet/tools` yok |
| 2 | `package.json` `main` ile yol geçişi (`:238`) | kapandı | P19; `analyzers/electron.py:827-833` (`resolve().relative_to(extract_dir)`) |
| 3 | Go kararı düz dizgilerle (`:239`) | kısmen | Bölüm adı denetimi eklendi (`core/target.py:725-731`). Dizgi yedeği `go.buildid` / `Go build` duruyor (`:735`) |
| 4 | `.asar` uzantısı içerik denetimsiz; `main_binary` en büyük dylib (`:240`) | açık | kayıt yok |
| 5 | x86_64 dilimi `_arm64` adıyla (`:241`) | kapandı | P16a evrensel dilim + P-S4 kural kaydı (`pipeline/steps/binary_prep.py:102`, `analyzers/macho.py:253`) |
| 6 | jadx `--no-debug-info` (`:242`) | açık | `java_binary.py:700` |
| 7 | APK paket adı sezgisi (`:243`) | açık | P19 gözlemi: iki gerçek APK'da paket adı okunamıyor (uydurma ad artık yazılmıyor) |
| 8 | jadx yokken sıkıştırılmış JAR'da `strings` (`:244`) | kapandı | P-S4: JAR / APK 4/4 `arac_yok` |
| 9 | `$TMPDIR/bw_param_recovery_*.json` artığı (`:245`) | doğrulanamadı | Kodda `finally` temizliği var (`reconstruction/param_recovery.py:246-247`); artığın kaldığı yol ölçülmedi |
| 10 | Pipeline başarısızken çıkış 0 (`:246`) | kapandı | MEK-01 (bu denetimde çıkış 1) |
| 11 | Bağımlılıklar `"latest"` (`:247`) | açık | `reconstruction/dependency_resolver.py:136`, `:172`, `:307`. README uyarısı ve `--ignore-scripts` riski azaltıyor |
| 12 | `smart-webpack-unpack` sabit 300 sn (`:248`) | açık | `deobfuscators/deep_pipeline.py:580` |

---

## Kulvar GHIDRA (16 bulgu)

| Kimlik | Önem | Durum | Kanıt |
|---|---|---|---|
| GHIDRA-01 | YÜKSEK | kapandı | P16b, ardından P16c (toplu sorgu). **Kod:** süreçler arası `fcntl.flock` alınıyor; alınamazsa sınırlı süre bekleniyor, sonra `skipped_busy` + neden yazılıyor (`ghidra/bsim.py:17-27`, `:110`). H2 bağlantısı oturum sonunda bırakılıyor. **Ölçüm:** birleşik 119 koşusunda `bsim_yedege_dustu` 78 → 0 (`sonuc.md:242`, `:361`). |
| GHIDRA-02 | YÜKSEK | kapandı | P16b. **Kod:** ingest edilen her ikilinin kimliği (md5, sha256, ELF build-id / Mach-O LC_UUID) kaynak kaydına yazılıyor (`bsim.py:214-421`). Sorguda üç şey dışlanıyor ve sayılıyor: kendisi, aynı dosya, aynı yapı (`:626-648`, `:881-929`, `:1553`). Eşleşmede `matched_exe_md5` / `sha256` var (`:163-177`). **P16b:** soyulmuş Mac htop'ta sembollü kopyadan gelen adlı aday 597 → 0. |
| GHIDRA-03 | ORTA | kapandı | P16b: lite dizini atomik (`os.replace`); bozuk dizin ezilmiyor, yedeğe taşınıyor (`bsim.py:27`). |
| GHIDRA-04 | YÜKSEK | kapandı | P15a (`d6224bd`). **Bu denetimde (scratchpad YAML):** bilinmeyen bölüm (`binary_reconstrution`) ve `timeouts.ghidra: "abc"` → `ConfigValueError: ayar dosyasında 2 sorun …` ("bunu mu demek istediniz" önerisiyle). Aynı dosyada `config validate` çıkış 1. Boş `tools:` bölümü çökmeden yükleniyor. |
| GHIDRA-05 | ORTA | kapandı | P16a: adres sırası; iki koşu bayt bayt aynı. P16d: `pcode_high_vars` sırası. Birleşik ölçüm: `decompiled_json_kirpik` 25 640 → 0 (`sonuc.md:361`). |
| GHIDRA-06 | ORTA | kapandı | P16a: toplam decompile süresi uygulanıyor; fonksiyon başına süre `max_decompile_timeout_per_func`'tan (`ghidra/headless.py:407`). P16c: otomatik analiz `TimeoutTaskMonitor` ile sınırlı (`:677-709`); JVM yığını ayardan (`:52`, `:304`); `ghidra_batch_size` etkisiz ayarlar kaydında (`config.py:629`, `:1099`). |
| GHIDRA-07 | YÜKSEK | kapandı | P-GÜV + P15a. **Kod:** kapı yalnız gerçek `True` ile açılıyor; öbür her değer atlatıyor (`stages.py:726`). Bilinmeyen tip spawn edilmiyor (`:731-739`). CLI, ayar dosyasından açılan kapıyı `--dynamic` verilmediyse kapatıyor ve kaynağını yazıyor (`cli.py:784-808`). **Bu denetimde:** `security.allow_target_execution: "no"` → `False` yüklendi. |
| GHIDRA-08 | ORTA | kısmen | P16a (`be3ee13`): CLI yedeğinde betik çıktısı yoksa açık başarısızlık ve neden yazılıyor (`headless.py:2534-2545`); anahtarlar eşitlendi. Yedek yol Ghidra 12.1.2'de hâlâ çalışmıyor (`pyghidraRun -H` bağlanmadı). PyGhidra'sız kurulum analiz yapamıyor, ama bunu açıkça söylüyor. |
| GHIDRA-09 | YÜKSEK | kapandı | P16a (+ yamalar `c4a2339`, `e809b08`). **Kod:** `static/ghidra_log.txt` ve `static/ghidra_status.json` başarıdan bağımsız yazılıyor (`analyzers/macho.py:1107-1148`). Ghidra başarısızsa `static` aşaması da başarısız (`:427`). Yarım decompile dizini "deobfuscate edildi" diye kopyalanmıyor (`e809b08`). PyGhidra yolunda uydurma `returncode` yok (`headless.py:626` → `None`). |
| GHIDRA-10 | YÜKSEK | kapandı | P16a + P18. **Kod:** `program_function_count`, `thunk_count` ve `external_count` ayrı tutuluyor (`headless.py:795-807`). CLI'da ayrı satır (`cli.py:1048-1052`), raporlarda ayrı alan (`markdown_report.py:218-219`, `report_data.py:735`). Çıktı ağacında thunk'lar `src/import_thunks/` altında etiketli (`reconstruction/c_project_builder.py:196-197`, `:512`). **P18:** program koduyla karışık thunk 33 545 → 0. |
| GHIDRA-11 | KRİTİK | kapandı | P-GÜV. **Kod:** sıra şöyle: spawn (süreç askıda) → kanca yükle → `resume()` → bekle → `kill()` (`stages.py:769-806`). Kanca yüklenemezse süreç sürdürülmüyor (`:788-790`). `finally` içindeki `detach()` öldürülmemiş spawn sürecini de öldürüyor (`stages.py:861-865`; `frida/session.py:299-310`). Attach başarısızsa askıdaki süreç öldürülüyor (`session.py:196-206`). Toplama süresi gerçek süre (`stages.py:796-800`). **Bu denetimde:** `tests/test_pguv_frida.py` → 12 geçti. Gerçek Frida ile koşulmadı. |
| GHIDRA-12 | ORTA | kapandı | P16b yaması `b36dcc3` (`bsim create / list / ingest / query` analizin veritabanını yönetiyor). |
| GHIDRA-13 | ORTA | kapandı | P-GÜV. **Kod (güvenlik):** `karadul run` yalnız `allow_target_execution is True` ise çalışıyor (`cli.py:1136-1165`). Uyarı "analiz edilen kodun kendisidir" diyor (`:1221-1225`). `npm install` her zaman `--ignore-scripts`; ağ kapalıyken `--offline` (`:1265-1271`). |
| GHIDRA-14 | YÜKSEK | kapandı | P15b. **Kod:** veri kökü `resolve_data_root`'tan (ortam değişkeni ya da paket kökü; `cwd` değil): `config.py:60-121`, `:1393-1395`. Okuyucular `data_root` kullanıyor (`analyzers/signature_db.py:609`, `:1760`; `pipeline/steps/byte_pattern.py:21`, `:259`; `_feedback_typing_extras.py:231`, `:418`). **P15b ön kaydı H1–H6 tuttu:** üç girişte `naming_map.json` ve 19 istatistik aynı. **Yan sonuç (IMZA kulvarı):** FLIRT artık her girişte bekletiliyor (P08b); uygulama `sigs/` taşımıyor, n-gram `veri_yok`. |
| GHIDRA-15 | ORTA | kısmen | `ghidra/scripts/legacy/` silindi (K-3 A2, P16a). Duranlar: `karadul/decompilers/` (`angr_backend`, `factory`, `ghidra_backend`, `pipeline_adapter`), `karadul/ghidra/debugger_bridge.py`, `perf.use_legacy_jython_scripts` alanı (`config.py:928`). |
| GHIDRA-16 | ORTA | kapandı | P13a: `808a7f8` aynı ön kayıtla alındı. Dizgi xref'i 0 → 5 439 / 8 164; `faz1` adı 0. |

### GHIDRA küçük kalemleri (14 satır)

| # | Kalem (kulvar satırı) | Durum | Kanıt |
|---|---|---|---|
| 1 | Decompile dosya adı belirlenimsiz (`:198`) | kapandı | P16a; `headless.py:1449` (dosya adı adres sırasıyla önceden planlanıyor) |
| 2 | İstisna veren parçanın fonksiyonları adsız düşüyor (`:199`) | kapandı | P16a (`P16a.md:59`) |
| 3 | Seri yedeğin O_EXCL ile ikinci kez yazması (`:200`) | doğrulanamadı | Kayıtta açık hüküm yok |
| 4 | `function_id.json` `caseD_` adları 0,95 ile (`:201`) | kapandı | P12c: `caseD_` 24 → 0 |
| 5 | Her Ghidra JSON'u iki kez yazılıyor (`:202`) | açık | `headless.py:2451` (`_save_output`) + `macho.py:436-438` |
| 6 | PyGhidra'da uydurma `returncode` (`:203`) | kapandı | `headless.py:626` (`None`) |
| 7 | `collect_duration` hep tam süre; `node` PATH'ten (`:204`) | kısmen | Süre gerçek (`stages.py:796-800`). `node` hâlâ `config.tools.node`'dan, beyaz liste yok (`stages.py:914`) |
| 8 | `check_anti_tamper` frida ile toplu koşu düşebilir (`:205`) | açık | kayıt yok |
| 9 | `SubprocessRunner`: sınırsız çıktı, yetim `java`, miras ortam (`:206`) | açık | kayıt yok |
| 10 | `hacker_cli` canlı sayaçları hiç atanmıyor (`:207`) | açık | `hacker_cli.py`'de `state.functions_found = …` vb. atama yok; P15a başka ölü kodu onardı |
| 11 | `karadul rtti` düz metinde çıkış 0 (`:208`) | açık | kayıt yok |
| 12 | Lite sorguda erişilemez koşul; native sorgu O(n²) (`:209`) | kısmen | P16c toplu sorgu O(n²) yolu öntanımdan çıkardı. Erişilemez koşul doğrulanamadı |
| 13 | `quick_f1_eval.py` adı yanıltıcı (`:210`) | açık | `karadul/scripts/quick_f1_eval.py` duruyor |
| 14 | `timeouts.ghidra_analysis` alanı yok, angr 3 600 sn (`:211`) | açık | `analyzers/macho.py:1223` |

---

## Kulvar MEK (14 bulgu)

| Kimlik | Önem | Durum | Kanıt |
|---|---|---|---|
| MEK-01 | YÜKSEK | kapandı | P15a. **Kod:** çıkış kodları 0 (tam) / 1 (başarısız) / 2 (kullanım, ayar) / 3 (kısmi) (`cli.py:292-301`, `:1017-1018`, `:1120-1121`). **Bu denetimde** (scratchpad, `KARADUL_CACHE_DIR` geçici): boş dosya ve düz metin → çıkış 1. Ekranda "HATA: analiz başarısız (çıkış 1): 1 aşama başarısız. static: Desteklenmiyor: hedef türü tanınmadı…" yazıyor. |
| MEK-02 | ORTA | kapandı | P16a (`e4d31f7`). Ghidra projesi `--output` ya da `cwd` altına yazılıyor, ikilinin dizinine değil (`ghidra/program_diff.py:204-206`). |
| MEK-03 | YÜKSEK | kapandı | P-GÜV + P15a; kanıt BICIM-06 ile aynı. Uzak `.d.ts` yalnız `network.enabled` ve `allow_dts_fetch` gerçek `True` iken (`naming/pipeline.py:77-81`, `:154-158`). `urlopen` yalnız `allow_network=True` ile kurulan örnekte (`reconstruction/dts_namer.py:496-497`). |
| MEK-04 | ORTA | kapandı | P17 / K-6: güncelleme sorgusu öntanımlı kapalı; ağ ayarına ve tercihe bağlı (`ui/server.py:1713-1751`). |
| MEK-05 | ORTA | kısmen | P15a: okunmayan 50 ayar `INERT_SETTINGS`'le uyarı veriyor (iki yönlü testle kilitli); `allow_source_match` bağlandı (`306f141`). Alan alan "bağla ya da sil" kararı verilmedi; uyarı veren ayarlar etkisiz kalıyor. |
| MEK-06 | DÜŞÜK | açık | `.github/workflows/*.yml`'de mypy adımı yok (`grep` boş). P23 gönderilmedi. |
| MEK-07 | ORTA | kısmen | **Bağlanan ya da silinen:** `karadul/lm/` (P22c'de arayüze bağlandı), `container_classifier` (P19), `confidence_calibration.py` (P04b), paralel ad koşucusu (P13a). **Duran:** `jsnice_renamer`, `ts_declarations_namer`. Listenin geri kalanı için kayıt yok (`field_namer`, `demangler_registry`, `_capa_comment_inject`, `trex_export`, `content_store`, `karadul/scripts/*`). |
| MEK-08 | ORTA | kapandı | P17: uydurma kısa ad (`FUN_` + son 6 hane) yok. |
| MEK-09 | DÜŞÜK | kısmen | (a) `clean` ve (b) `score` P15a'da (`088b001`); (d) ASCII'ye kaçmış Türkçe sözcük 130 → 0 (P15b). Açık: (c) `karadul info` evrensel Mach-O dilimlerini göstermiyor (P-S4 izi, `cli.py`). |
| MEK-10 | DÜŞÜK | açık | 10 `tests/test_*_parity.py` dosyası duruyor. `/private/tmp/pycdc_e2e`'ye bağlı testler (`test_python_pipeline_hardening.py`, `test_pyz_archive.py`) duruyor. Ghidra'lı CI işi yok. P23 gönderilmedi. |
| MEK-11 | ORTA | kapandı | P08: `entry` → CoreGraphics 0. Mach-O'da `main` kurtarılmıyor; bu ayrı bir iş (OKU, atanmamış). |
| MEK-12 | ORTA | kapandı | P20 (BICIM-01 ve BICIM-03 ile birlikte). |
| MEK-13 | DÜŞÜK | açık | Kişisel yollar duruyor: `karadul/batch.py:48` (`/Users/apple/.local/bin/claude`), `scripts/benchmark_claude_code.py:31`, `scripts/string_bridge_benchmark.py:31`. Ayrıca `scripts/*.mjs.bak2` (2 dosya); kökte `AUDIT_2026_05_13.md`, `BENCHMARK_2026_05_14.md`, `MATH_VERIFICATION_REPORT.md`, `.EXPLORATION_SUMMARY.txt`; `docs/PLAN_80_PERCENT.md`, `MASTER_PLAN.md`, `IMPOSSIBLE_SOLUTIONS_PLAN.md`. Depo herkese açık (Y9). |
| MEK-14 | DÜŞÜK | açık | `analyzers/dotnet_binary.py:39`, `:45`: `resolve_tool` iki kez içe aktarılıyor. |

---

## Ek riskler (denetimde görülen, numarasız)

1. **ILSpy çıktısı .NET projesine süzgeçsiz kopyalanıyor. BICIM-04 sınıfında bir risk: projeyi açınca kod yürütülebilir.**
   - **Kod:** `analyzers/dotnet_binary.py:829-833` ILSpy `--project` çıktısını `shutil.copytree(src_dir, output_dir, dirs_exist_ok=True)` ile kopyalıyor; hedef, üretilen `.csproj`'un bulunduğu kök dizin.
   - **Neden tehlikeli:** gömülü bir kaynağın adı `Directory.Build.props` ya da `Directory.Build.targets` olursa MSBuild projeyi açarken bu dosyayı kendiliğinden içe alır. Depoda bu adları süzen bir satır yok (`grep "Directory.Build"` boş).
   - **Kayıt:** P19 bunu açık risk olarak yazmış (`P19.md:181`); ILSpy kurulu olmadığı için denenmemiş.
   - **Koşul:** risk yalnız `ilspycmd` beyaz listedeki bir dizindeyse doğuyor. `dotnet tool install -g`'nin koyduğu `~/.dotnet/tools` listede yok (BICIM küçük 1).
   - **Durum:** doğrulanamadı.
   - **Önerim:** kopyalamada `Directory.Build.*`, `*.props`, `*.targets`, `NuGet.config`, `global.json` adlarını dışlamak (S).
   - Java tarafında aynı risk görünmüyor: jadx çıktısı `src/main/java/` altına kopyalanıyor (`java_binary.py:563-566`).
2. **Hakkında panelindeki ölçüm bayat.** Panel yeni2 (1.22.1) ölçümünü gösteriyor ve "sonraki sürümler yinelemedi" diyor. Birleşik ölçüm (a62f15e) yapıldı. Y10'un ("her sayı ölçülmüş") parçası olarak güncellenmeli (ARAYUZ-03 satırı).

---

## Yayını durduranlar (açık ya da kısmen kalan kritik / yüksek)

Kulvarlarımda açık kritik ya da yüksek bulgu yok. Kısmen kalan iki yüksek bulgu var:

1. **BICIM-09 (YÜKSEK, kısmen).**
   - **Kullanıcıya etkisi:** Electron ya da Java tabanlı bir `.app`'te asıl kod artık seçiliyor. Ama paketteki her çerçeve ve dylib (Chromium, gömülü JRE) süre bütçesi olmadan Ghidra'ya veriliyor; büyük bir `.app` analizi saatler sürebilir. Electron `.app` uçtan uca hiç koşulmadı.
   - **Onarım:** `karadul/core/target.py:252-282` (bileşen listesine süzgeç ya da bütçe), `karadul/analyzers/app_bundle.py`, `karadul/stages.py` `_execute_app_bundle`. Ölçüm: gerçek bir Electron `.app` (K-8 setindeki Fiddle).
2. **LM-08 (YÜKSEK, kısmen).**
   - **Kullanıcıya etkisi:** KaradulLM'i açan analist her fonksiyona çekimser kalan bir yardımcı görebilir. Yanlış ad üretmez ama işe yaramaz görünür. K0'ın 5/5 çekimserliğine karşı özet zinciri yazıldı, ama gerçek modelle hiç sınanmadı.
   - **Onarım:** önce kod değil ölçüm gerekiyor: P21 / P22b / P22e / P22h duman listeleri (YAYIN_KAPISI Y7). Sonuca göre `karadul/lm/agent.py`, `context.py`, `summaries.py`.

İkisinin de durdurucu sayılması Berke'nin kararı. BICIM-09'un kalanı başarım ve kapsam sorunu, LM-08'in kalanı ölçüm eksikliği; ikisi de yanlış iddia ya da güvenlik açığı değil. "Ek risk 1" numarasız ama BICIM-04 sınıfında; durdurucu sayılması önerilir (onarımı küçük).

## Ertelenebilirler (yayın notu "bilinen kusurlar" taslağı)

- **ARAYUZ-09:** aynı `--output` dizinine ikinci CLI koşusu önceki koşunun dosyalarını bırakır; "Names Recovered" bayat dosyaları sayabilir. Her koşuya boş dizin verin.
- **ARAYUZ-18 (K-1):** kurtarılan yapı tanımları `types.h`'ye yazılmaz; adaylar yalnız `typed/types_candidates.txt`'te.
- **ARAYUZ-19:** arayüzde parametre / yerel ad düzeltme, geri alma, gövde ve dizgi araması, adayın elenme nedeni yok.
- **LM-07:** KaradulLM'in K1 / K2 kipleri ve gerçek modelle ad önerisi sınanmadı; testler sahte arka uçla.
- **BICIM-10:** evrensel ikili içindeki Go / Bun dilimi analiz edilmez ("desteklenmiyor" der). cx_Freeze tanıması gerçek örnekle doğrulanmadı. Bazı PyInstaller ikililerinde .pyc çözülemiyor.
- **BICIM-15:** `jsnice_renamer.py` ve `ts_declarations_namer.py` ölü kod; JSNice uzak servise gittiği için bağlanmadı.
- **GHIDRA-08:** PyGhidra kurulu değilse analiz yapılamaz. CLI yedeği Ghidra 12'de çalışmaz, bunu hata olarak söyler.
- **GHIDRA-15:** çoklu decompiler arka ucu (angr) ve hata ayıklayıcı köprüsü ölü kod; angr desteklenmiyor.
- **MEK-05:** yaklaşık 50 ayar etkisizdir ve yüklenirken uyarı verir.
- **MEK-07:** ürün giriş noktalarından erişilemeyen birkaç modül duruyor.
- **MEK-06:** mypy CI'da koşmuyor.
- **MEK-09 (c):** `karadul info` evrensel Mach-O dilimlerini göstermez.
- **MEK-10:** Ghidra'lı uçtan uca testler CI'da koşmaz; parite testleri hep atlanır.
- **MEK-13:** depoda kişisel yollar ve eski plan belgeleri var. Herkese açık depoda yayından önce temizlenmesi önerilir (Y9).
- **MEK-14:** `dotnet_binary.py`'de çift içe aktarma (davranış etkisi yok).
- **Küçük kalemler:** 57 kalemin 31'i açık, 5'i kısmen, 2'si doğrulanamadı. Kullanıcıya görünenler:
  - bayat güncelleme ilerleme yoklaması (ARAYUZ küçük 7);
  - kod vurgulamada dizgi içindeki `//` (ARAYUZ küçük 8);
  - `llama_server.log`'un sınırsız büyümesi (LM küçük 4);
  - JS projesinde `"latest"` bağımlılıkları (BICIM küçük 11);
  - paket betiğinin başka projenin (HRMA) çalışma zamanını kullanması (ARAYUZ küçük 17).

## Sayım

### Bulgular: önem × durum (5 kulvar, 72 bulgu)

| Önem | kapandı | kısmen | bekletildi | açık | gereksizleşti | Toplam |
|---|---|---|---|---|---|---|
| KRİTİK | 4 | 0 | 0 | 0 | 0 | 4 |
| YÜKSEK | 23 | 2 | 0 | 0 | 0 | 25 |
| ORTA | 26 | 9 | 1 | 0 | 0 | 36 |
| DÜŞÜK | 2 | 1 | 0 | 4 | 0 | 7 |
| **Toplam** | **55** | **12** | **1** | **4** | **0** | **72** |

### Kulvar kırılımı

| Kulvar | Toplam | kapandı | kısmen | bekletildi | açık |
|---|---|---|---|---|---|
| ARAYUZ | 19 | 16 | 2 (09, 19) | 1 (18, K-1) | 0 |
| LM | 8 | 6 | 2 (07, 08) | 0 | 0 |
| BICIM | 15 | 12 | 3 (09, 10, 15) | 0 | 0 |
| GHIDRA | 16 | 14 | 2 (08, 15) | 0 | 0 |
| MEK | 14 | 7 | 3 (05, 07, 09) | 0 | 4 (06, 10, 13, 14) |

### Küçük kalemler (57 kalem; ARAYUZ'un 20. satırı bulgu değil, sayılmadı)

| Kulvar | kapandı | kısmen | açık | doğrulanamadı | Toplam |
|---|---|---|---|---|---|
| ARAYUZ | 10 | 1 | 8 | 0 | 19 |
| LM | 1 | 1 | 10 | 0 | 12 |
| BICIM | 4 | 1 | 6 | 1 | 12 |
| GHIDRA | 4 | 2 | 7 | 1 | 14 |
| **Toplam** | **19** | **5** | **31** | **2** | **57** |

## DENETİM BİTTİ
