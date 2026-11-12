# KaradulLM Aşama 1b: bağlam, okuyan araçlar, K0 iş akışı ve bütçeli döngü

- **Tarih:** 2026-11-11 (yazım), 2026-11-12 (tamamlama). **Dal:** worktree `worktree-agent-abf00712a21369630`, taban `main` f30ac9a (sürüm 1.22.1).
- **Yazım geçmişi:** işi yazan ajan 2026-11-11'de koşunun ortasında durduruldu; raporu yok. Commit'li üç parça (3d0dc25, 49ee81e, 3f4a39d) ve commit'siz fark 2026-11-12'de ikinci bir ajan tarafından satır satır incelendi, testler ve mutasyon koşusu yeniden koşuldu, bu not kodla karşılaştırılarak düzeltildi. Notta "bu işte" diye geçen ölçümler aksi yazılmadıkça 2026-11-12 koşularıdır; ilk ajanın koşup çıktısını saklamadığı sayılar **[doğrulanmadı]** diye işaretlidir.
- **Kapsam:** tasarımın (`tasarim.md`) §10 Aşama 1'inin ikinci yarısı: `context.py`, `tools/` (araç kaydı + O1, O2, O3), `agent.py` (K0 iş akışı ve K1 / K2 için bütçeli döngü), "ad öner" cevap şemasındaki `kanit` hatasının düzeltmesi, gerçek modelle duman betiği. Denetim katmanı (`guard.py`), öneri kuyruğu, oturum defteri, yazma önerisi araçları, kalan okuyan araçlar ve arayüz uçları bu işte yok.
- **Commit'ler (sırayla):** 3d0dc25 (`kanit` şeması), 49ee81e (bağlam + üç okuyan araç), 3f4a39d (ajan), 027e935 (bellek durmasından sonra kendiliğinden yeniden başlatma hatası), 61294e6 (mutasyon tanımı + test güçlendirme), 59d42a6 (`zemin/k0_duman.py`), bu not.
- **Koşulmayanlar:** gerçek model, `llama-server`, ağ isteği, Ghidra, Karadul hattı, `zemin/k0_duman.py` (hiçbir kipte; §5, §6). Testlerin hepsi sentetik çalışma alanı ve betikli sahte arka uçla (`FakeBackend`) çalışır. Gerçek modelle duman testi ana oturuma bırakıldı (§6).
- **Kör setler ve GT dosyaları okunmadı.** 2026-11-12'de iki saklı çalışma alanının yalnız `static/` dosyaları okundu (§2 madde 6'nın sayımları; ürün çıktısı, gerçek ad yok).
- **İşaretler:** tasarımdaki gibi. **[ölçüm]** bu işte koşulan bir komutun çıktısı; **[tahmin]** ölçülmemiş; **[bu iş]** tasarımda yazmayan, bu işte konmuş değer.

## 1. Yazılanlar

| Dosya | Ne yapar | Tasarım maddesi |
|---|---|---|
| `karadul/lm/context.py` | Pilot kopyaları (başlık silme, kod kırpma, kanıt alan metinleri, C şablonu); veri / talimat ayrımı (kaçışlama, sarmalama); sabit önek (KL-0 + sonuç anlatımı + araç tanımları); soru metni; bağlam bütçesi kestirimi; körlük taraması | §4.1, §4.3, §6.2, §2.3; sözleşme §1.3-1.5; K-P0, K-B1 |
| `karadul/lm/tools/__init__.py` | `Workspace` (saklı çalışma alanının salt okunur görünümü), sonuç zarfı, `ToolRegistry` (ad, argüman şeması, sonuç boyut sınırı), hata kodları, ad etiketleri, çağrı kenarı mantığının kopyası | §3, §6.2 "Araç yetki sınırı"; sözleşme §1 |
| `karadul/lm/tools/read.py` | Üç okuyan araç: `get_evidence` (O1), `get_decompiled` (O2), `get_xrefs` (O3) | sözleşme §2, §5 |
| `karadul/lm/agent.py` | K0 iş akışı; K1 / K2 için bütçeli döngü (öntanımlı kapalı); görev ve araç kayıtları; bellek bekçisi ve hata yolları | §2.3, §2.4, §5.4; K-A2, K-A3, K-A4, K-B2, K-L1, K-K1 |
| `karadul/lm/protocol.py` (değişti) | `build_name_answer_schema(evidence_ids)`, `refs_schema`, `name_answer_branches`, `build_task_envelope`; sabit `NAME_ANSWER_SCHEMA` kaldırıldı | §3.1 son madde; `asama1a.md` Ek |
| `karadul/lm/__init__.py` (değişti) | Bu işin bütün sayısal sabitleri (kök etiketiyle) | proje kuralı (sabit tek yerde) |
| `tests/test_lm_context.py`, `test_lm_tools.py`, `test_lm_agent.py`; `test_lm_protocol.py` (değişti) | Birim testleri ve pilot / arayüz kopyalarının eşitlik testleri | §9.3 |
| `scripts/measurement/mutation_specs_lm_ajan.json` | Mutasyon tanımı | §9.3 |
| `docs/arge/2026-11-11_karadullm/zemin/k0_duman.py` | Kuru sayım (model yok) ve gerçek modelle K0 duman betiği | §5, §6 (bu not) |

### 1.1 İstemin biçimi

Sıra tasarım §4.3'teki gibi: **[sabit önek] [oturum bloğu] [fonksiyon paketi] [soru]**.

- **Sabit önek** sistem iletisidir: KL-0 metni (tasarım §4.1'in bayt bayt kopyası; test tasarım belgesinden okuyup karşılaştırır) + sonuç zarfının anlatımı + üç aracın tanım satırı + kipe özgü kapanış. K1 / K2'de KL-0'ın araç bloğu ve çağrı biçimi eklenir. Önek yalnız kipe ve araç kümesine bağlıdır: çalışma alanından, oturumdan ya da saatten hiçbir şey almaz. K0 öneki 4.685 bayt (kestirim 1.092 jeton **[tahmin]**), K1 öneki 5.313 bayt (1.238 jeton **[tahmin]**), K2 öneki 5.220 bayt (1.216 jeton **[tahmin]**) **[ölçüm: `context.fixed_prefix` + `context.estimate_text_tokens`, varsayılan araç kaydıyla; 2026-11-12]**. Araç kümesi sürümü (`ToolRegistry.version()`) `fdb53fa12299b3eb`.
- **Fonksiyon paketi** sunucunun çağırdığı iki aracın sonucudur: `r1` = `get_evidence`, `r2` = `get_decompiled`. Her sonuç üç satırdır: `<tool_response>`, tek satır JSON zarf, `</tool_response>`.
- **Soru** en sondadır: görev cümlesi (`FUN_<adres>`), cevap biçimi (şema modele gösterilmediği için istemde anlatılır, tasarım §3.1) ve `kanit` alanına girebilecek kimlikler.
- **Oturum bloğu** için yer var (`context.user_message(..., session_block=)`); içeriği (ikili özeti, defter) Aşama 2'nin işi olduğu için bugün boş.

### 1.2 Veri / talimat ayrımı (tasarım §6.2)

- İkiliden gelen her metin (dizgi, ad, kod) yalnız sonuç zarfının `data` alanında taşınır. Zarf `json.dumps(ensure_ascii=False)` ile tek satıra serileştirilir; ardından `<`, `>`, `&`, DEL ve C1 denetim karakterleri, U+2028, U+2029 ve tek başına vekil kod birimleri `\uXXXX` kaçışına çevrilir. Çözüm kayıpsızdır (`json.loads` aynı değeri verir).
- Sonuç: sarmalanmış blokta veri kaynaklı `<`, `>`, `&` ve satır sonu yoktur. Veri `</tool_response>` ya da `<|im_start|>` yazamaz, kendi satırından çıkamaz, soruyu taklit eden bir satır açamaz. Test: `test_kacislama_veri_blogu_kapatamaz` (11 tuzak dizgi; blok sayısı, `<` sayısı, satır sayısı, kayıpsız çözüm).
- Model çıktısı da veridir. Döngüde ve onarım turunda asistan turu geçmişe `safe_assistant_content` ile yazılır: kaçışlanacak karakter taşımıyorsa aynen (bayt bayt; önek önbelleği sürer), taşıyorsa ayrıştırılmış nesnenin kaçışlı JSON'u, o da yoksa sabit yer tutucu. Onarım iletisi modelin değerini zaten yansıtmıyor (Aşama 1a).
- Kanıt paketine giren ad düz bir C tanımlayıcısı olmak zorundadır (`^[A-Za-z_][A-Za-z0-9_]*$`, ≤ 128 karakter **[bu iş]**); değilse fonksiyon adsız görünür. Gerekçe: köşeli ayraç ya da boşluk taşıyan bir "ad" `FUN_x [etiket: ad]` biçimini bozabilirdi.
- Kaçışlama bir yetki sınırı değildir (tasarım §6.2 ilk cümle). Talimat taşımayan yanıltma (yanlış ada iten dizgi) bu katmandan geçer.

### 1.3 Araçlar

| Araç | `data` | Sınır ve `truncated` | `kind` / `source` |
|---|---|---|---|
| `get_evidence(addr)` | `apis`, `callees`, `callers`, `callbacks_given`, `callback_of`, `strings`, `constants` (pilotun alan metinleri, `llm_pilot.kanit_alanlari` ile bayt bayt aynı), `lines` | Pilotun sayı sınırları (40 / 30 / 20 / 40 × 120 / 20). Atılan öğeler `truncated.fields` altında alan alan, kesilen dizgi sayısı `strings_cut`. Zarf 16.000 baytı **[bu iş]** aşarsa sınırlar yarılanır ve bu da `truncated`'a yansır | `olgu+cikarim`; `static/ghidra_xrefs.json; static/ghidra_functions.json; static/ghidra_output/decompiled` |
| `get_decompiled(addr, part, line_from, line_to)` | `code`, `total_lines`, `line_from`, `line_to`, `ghidra_warnings` (≤ 8 ayrı uyarı), `ghidra_warning_total` | Tek atış (K0, sunucu çağırır): pilotun kırpması, 9.000 bayt = baştan 7.000 + sondan 2.000. Döngü: çağrı başına 4.500 bayt **[seçim]**; `bas` baştan, `son` sondan, `aralik` verilen satırlar | `olgu`; `static/ghidra_output/decompiled/FUN_<adres>.c` |
| `get_xrefs(addr, direction, offset, limit)` | `items: [{addr, name_tag}]`, `total`, `offset` | `limit ≤ 30`; kalan `truncated` ile | `callers` / `callees`: `olgu`, `static/ghidra_call_graph.json`. `address_refs`: `vekil` |

- **Yön adları** tanım satırında açık yazılı: `"callers" = the functions that CALL addr (edges into addr)`, `"callees" = the functions that addr CALLS (edges out of addr)` (zemin §5'in gözlemi). Test tanımın metnini ve davranışı birlikte kilitler.
- **Çağrı kenarları** arayüzün bugünkü düzeltmesiyle aynı kaynaktan: `tools.call_graph_edges` `ui/server.py::_call_graph_edges`'in veri kısmının kopyasıdır. Eşitlik iki testle kilitli: 11 grafik biçiminde (kenar listeli, yalnız düğümlü, `0x` önekli, yabancı, bozuk) işlevin kendisiyle; iki biçimde `build_model`'in `calls` ve `addr_refs` çıktısıyla. Ürün `ui/`'yi içe aktarmaz (test dosya yolundan yükler).
- **Sınırlama notları** (`limits`) sözleşmenin sabit metinleridir. Sözleşmede olmayıp eklenenler: çağrı kenarı sonuçlarında "Yalnız program fonksiyonları (FUN_) listelenir…" ve "Çağrı sayısı ürün çıktısında yoktur…"; `address_refs`'te "Ghidra veri başvurusu ürün çıktısında yoktur."
- **Yetki sınırı:** hiçbir argüman şemasında yol, URL, komut ya da düzenli ifade alanı yok (test alan adlarını sayar). Araç modülleri süreç ve ağ modüllerini, `ui/`'yi ve ölçüm betiklerini içe aktarmaz (AST testi). Çalışma alanı araçlar çalıştıktan sonra bayt bayt ve değişiklik zamanıyla aynı (test).

### 1.4 Ajan

- **K0 (`Agent.suggest_name`)**: adres çözülür → yetenek düzeyi okunur → paket kurulur (iki araç, `single_shot`) → körlük taraması (kör kipte) → bağlam ön denetimi → model TEK kez çağrılır (yalnız L2 ucunda bir onarım turu) → `parse_turn` + pilotun `parse_name_answer` sınıflayıcısı → `TaskResult`. Model araç çağıramaz; K0 önekinde bu yazılıdır.
- **Döngü (`Agent.run_loop`, K1 / K2)**: Yol A zarfı; model her turda bir araç çağrısı ya da son cevap yazar. Sunucu denetimleri: araç bütçesi (K2 8, K1 2), tekrar, geçersiz çağrı, bağlam (istem + üretim + pay ≤ bağlam; araç sonuçları dilimi 6.000 jeton), iptal, süre. Bütçe bitince zarfın araç dalları kaldırılır: model yalnız son cevabı verebilir; yine vermezse görev `butce_asildi` ile biter. Geçmiş yalnız sona eklenir (her istek bir öncekinin iletilerini bayt bayt taşır; test). K1'de `addr` hedef ve paketindeki komşularla sınırlı bir `enum`'dur.
- **K1 / K2 öntanımlı kapalı.** `enabled_modes` öntanımı `("K0",)`. `run_loop` kip açıkça etkinleştirilmemişse `ModeDisabled` yükseltir; arka uç başlatılmaz, günlüğe kayıt düşmez (test: çağrı 0, başlatma 0, kayıt 0). K2'yi açmak K1'i açmaz.
- **Kayıt:** her model isteği (`Backend.chat`), çalıştırılan ya da reddedilen her araç isteği (`arac_cagrisi`: kimlik, araç, argüman, geçerlilik, sonuç sha256'sı, bayt, kırpma, süre, çalıştı mı) ve her görev (`gorev`: durum, sayaçlar, istem sürümü, araç kümesi sürümü, önek sha256'sı) birer satırdır. Sonuç metni, dizgi, kod ve model cevabı kayda girmez (test). Şemaya uymayan argüman ve kayıtlı olmayan aracın argümanı da girmez (test, kayıt işlevi doğrudan sınanır: döngüde zarf şeması böyle bir çağrıyı zaten geçirmez).
- **Bellek:** her model çağrısından sonra `memory_guard.check()`; bekçi tetiklendiyse ya da arka uç `bellek_durdu` durumundaysa görev `bellek_durdu` ile biter (cevap geçerli olsa da).
- **Bellek nedeniyle durmuş sunucu kendiliğinden yeniden başlatılmaz** (`agent.py` `_memory_stopped`, `_model_call` başı). Bekçi tetiklenmişse ya da arka uç `bellek_durdu` durumundaysa sonraki görevler model isteği atmadan `bellek_durdu` ile biter. Bu denetim olmasaydı `LlamaServerBackend._chat` süreç yokken kendini başlattığı için (`backend.py`, `if self.pid is None: self.start()`) bekçinin durdurduğu ~16 GiB'lık sunucu bir sonraki görevde yeniden yüklenirdi. Yeniden denemek için arka uç açıkça başlatılır ve bekçi yenilenir. Test: `test_bellek_bekcisi_her_model_cagrisindan_sonra` (iki koşul ayrı ayrı: bekçi tetiklenmiş ama arka uç yeniden başlatılmış; bekçi yok ama arka uç `bellek_durdu`).
- **Hata yolları:** `LMError` → görev `arka_uc_hatasi`, arka uç kapatılmaz (Aşama 1a kuralı: süreç yaşıyorsa geçici hata sunucuyu kapatmaz), ajan sonraki görevi yürütür. Başka her hata ve kesme (`KeyboardInterrupt`) → arka uç `hata` nedeniyle durdurulur, görev kaydı yazılır, hata yükselir. Ajan kilidi her yolda bırakılır. Aynı anda ikinci görev `AgentBusy` alır.
- **Körlük (`blind_target=True`)**: hedefin adı, hedefle aynı adı taşıyan komşular, `manual` etiketli adlar ve köken kaydı o anki adı anlatmayan adlar hiçbir sonuca girmez. Ayrıca paket kurulduktan sonra hedefin Karadul adı kanıt alanlarında (dizgi alanı dışında) tam sözcük olarak aranır; bulunursa istem gönderilmez (`korluk_ihlali`). Döngüde aynı tarama her araç sonucuna uygulanır; takılan sonuç yerine `arac_kapali` verilir.

## 2. Tasarımdan sapmalar ve karar gerektirenler

**Karar gerektirenler (önce bunlar):**

1. **K0 istemi pilotun C istemi değildir; yapısı farklıdır.** Tasarım iki şey istiyor: paket biçimi pilotun C şablonu olsun (§4.3) ve ikiliden gelen her metin zarfın `data` alanında JSON kaçışlı olsun (§6.2). İkisi aynı anda tutmaz. Yapılan: kanıt alanları pilotun metin biçimiyle (alan alan aynı dizgi) zarfın içinde taşınır; kod ayrı bir zarftadır. Kilitlenen değişmez: K0 isteminin zarfları çözülüp pilotun C şablonuna konunca pilotun C kullanıcı iletisi bayt bayt geri kurulur (`test_k0_paketinden_pilotun_c_iletisi_geri_kurulur`; küçük, kırpılmış ve sınıra takılan üç fonksiyonda). Yani ürün ile pilot aynı kanıtı gösterir (K-P0 bu anlamda tutar), ama modelin gördüğü metin aynı değildir: sistem istemi KL-0, paket JSON içinde, dizgiler iki kat kaçışlı, kodda satır sonları `\n`. Tasarım §9.2 K-P1'e göre bu ayrı bir satırdır (C*). Etkisi ölçülmedi.
2. **`<`, `>`, `&` kaçışının hedefi sözleşmede yazmıyor.** `arac_sozlesmeleri.md` §1.4'te cümle "`<`, `>` ve `&` karakterleri `<`, `>`, `&` yapılır" diye duruyor (hedef dizgiler kaybolmuş). JSON'un kendi kaçışı (`\u003c`, `\u003e`, `\u0026`) seçildi: JSON çözümünde kayıpsız, zarf geçerli JSON kalıyor. HTML varlığı (`&lt;`) kastedildiyse tek sabit değişir (`context._ESCAPE_RE` ve yerine koyma).
3. **Kaçışlamanın kod okunabilirliğine etkisi ölçülmedi.** Kodda her `<`, `>`, `&` altı karakterlik kaçışa dönüyor (`a < b`, `&DAT_…`). İlk ajanın iki çalışma alanındaki kuru koşusundan kalan sayılar **[doğrulanmadı: çıktısı saklanmamış, 2026-11-12'de yeniden koşulmadı, §5]**: tree'de 812, htop'ta 2.327 işaret; kaçışlı kod baytı ham kodun 1,050 ve 1,046 katı (satır sonu ve tırnak kaçışları dahil). Bu sayılar doğruysa bayt artışı küçük; jeton artışı ve modelin kaçışlı kodu okuma başarısı ölçülmedi. Öneri: Z9 (şablon işareti içerikte özel jeton olarak mı çözülüyor) ölçülsün; çözülmüyorsa kaçış yalnız `<|` ve `</` gibi işaret başlangıçlarına daraltılabilir. Kodda tasarımdaki kural duruyor.
4. **Sonuç bloğunun ayracı `<tool_response>` seçildi** (Qwen şablonunun araç sonucu etiketi; sözleşme §1.4'ün gerekçesi). Yol A'da sonuç kullanıcı iletisinde taşındığı için bu etiketi istemci yazıyor. Etiketin içerikte özel jetona çözülüp çözülmediği doğrulanmadı (Z9). Başka şablon ailesinde (`[INST]` gibi `<` taşımayan işaretler) bu kaçış yetmez; ayraç ve kaçış kümesi uç profiline göre değişmeli.
5. **Yeni hata kodları: `veri_yok`, `gecersiz_arguman`.** Sözleşmenin beş kodu iki durumu karşılamıyor: (a) adres `ghidra_functions.json`'da var ama saklı dosya yok (ithal ya da Ghidra'nın adlandırdığı fonksiyonun `FUN_` dosyası; çağrı grafiği yok); (b) şemaya uymayan ya da anlamsız argüman (`aralik`'ta `line_from > line_to`). Sessizce boş sonuç dönmek "boş = yok" okumasını besleyeceği için hata seçildi. `gecersiz_arguman`, `bilinmeyen_adres` ve `arac_kapali` geçersiz çağrı sayılır; `veri_yok` sayılmaz.
6. **`get_xrefs` sonucunda `n_calls` yok.** Sözleşme `[{addr, name_tag, n_calls}]` diyor; ürün çıktısında çağrı sayısı yok: iki çalışma alanında çağrı grafiğinin her (çağıran, çağrılan) çifti tekil, `ghidra_xrefs.json`'da da yineleme yok **[ölçüm, 2026-11-12, iki dosyanın doğrudan JSON sayımı: tree `edges` 485 / 485 tekil çift, `nodes[].callees` 485 / 485, `functions_called` 485 kayıtta 0 yineleme; htop 1.832 / 1.832, 1.832 / 1.832, 1.832'de 0]**. Alan uydurulmadı; `limits` bunu söylüyor. Pilotun `apis` alanındaki sayılar da bu yüzden hep `x1` **[ölçüm, 2026-11-12: `build_evidence` paketlerinde sayısı 1'den büyük API yok; tree 250, htop 790 paket]**.
7. **Araç bütçesi modelin her araç isteğini sayar** (tekrar ve geçersiz çağrı dahil). Tasarım "araç çağrısı / görev ≤ 8" diyor, reddedilen isteğin sayılıp sayılmayacağını söylemiyor. Sayılmazsa model sonsuz kez tekrar isteyebilirdi (T4).
8. **`kanit` için `minItems` konmadı.** Ad veren dalda en az bir kimlik zorlamak D8'i ("kanıtsız öneri" → `celiski`) yapısal olarak anlamsız kılardı; o karar denetim katmanının (Aşama 2). Bugün `kanit: []` şemaya uyar.
9. **KL-0'ın araç bloğu K1'de "at most 8 calls" diyor**, K1'in bütçesi 2. KL-0 metnine dokunulmadı; K1 önekinin sonuna "In this task you may make at most 2 tool calls…" satırı eklendi. İki cümle çelişiyor; K1 açılmadan önce KL-0'ın yeni sürümünde düzeltilmeli.

**Öbür sapmalar ve bu işte verilen kararlar:**

10. **Sabit önekte tasarımda olmayan bloklar var:** sonuç zarfının anlatımı (`Results`), araç tanım satırları, K0'ın "araç çağıramazsın" cümlesi, döngünün çağrı biçimi. Hepsi "araç tanımları"nın parçası sayıldı ve araç kümesi sürümüyle (`ToolRegistry.version()`) sürümleniyor. KL-0'ın iki bloğu bayt bayt tasarımdaki metin.
11. **`get_evidence.lines` başlıksız kodun satır sayısıdır.** `EvidencePack.line_count` Karadul'un başlık satırlarını da sayıyor; `get_decompiled.total_lines` ile aynı sayı olsun diye başlık silinmiş metin sayıldı.
12. **`get_evidence.kind` `"olgu+cikarim"`** (sözleşmedeki hücrenin karşılığı; zarfın tek değerli `kind` alanına sığmıyor).
13. **`get_xrefs` yalnız program fonksiyonlarını listeler** (iki ucu da `FUN_` decompile dosyası olan kenarlar; arayüzle aynı). Kütüphane çağrıları `get_evidence.apis`'tedir.
14. **Ad etiketi kuralı:** kayıt o anki adı anlatıyorsa kaydın etiketi; kayıt başka adı anlatıyorsa `manual` (arayüzün `_provenance` kuralı); kayıt yoksa `unverified`. Elle verilen adların asıl kaynağı olan düzeltme deposu (`~/.karadul/overrides`) okunmuyor (ikili sha256'sı ve oturum Aşama 2). `[model]` etiketi henüz üretilmiyor (deponun `model` bölümü yok).
15. **Körlük kipi tasarımdan sıkı:** köken kaydı o anki adı anlatmayan (ya da hiç olmayan) adlar da gizlenir, çünkü madde 14 yüzünden elle verilmiş bir ad `unverified` görünebilirdi.
16. **Bağlam ön denetimi kestirimle yapılır** (kod 1,5 bayt/jeton, metin 4,294 bayt/jeton **[tahmin]**; tasarımın `/tokenize` ön denetimi ağ isteği gerektirir, arka uç arayüzünde yok). K0'da da 512 jetonluk pay düşülür **[bu iş]**: istem ≤ 10.240 − 256 − 512 = 9.472. Gerçek `usage.prompt_tokens` sonuçta ve döngünün her adımında kullanılır (uç bildirdiyse son isteğin `prompt_tokens + completion_tokens`'ı; bildirmediyse kestirim tur tur birikir, test). Kestirimin gerçek sayıya oranı duman betiğiyle ölçülecek (§6).
17. **Onarım turu döngüde tur başınadır** (her turda en çok bir; kabul edilen turdan sonra hak yenilenir, test); K0'da görev başına bir.
18. **Süre ve iptal yalnız tur aralarında denetlenir.** Süren model isteği kesilmez (arka uç arayüzünde iptal yok; tasarım Z8).
19. **K0'da yalnız "ad öner" var.** "Ne yapıyor?" (tasarım §1 iş 1) için şema ve soru yazılmadı.
20. **`SpeedTracker` beslenmiyor.** Gerçek görevlerin hız gözlemini kayan medyana verme (Aşama 1a notu §2 madde 5) yapılmadı.
21. **`zemin/lm_duman.py` artık çalışmaz:** kaldırılan `protocol.NAME_ANSWER_SCHEMA`'yı kullanıyor (dokunma yetkim yoktu; sonucu `asama1a.md` Ek'te kayıtlı). Yerini `zemin/k0_duman.py` alıyor.
22. **Bu işte konmuş sabitler** (`__init__.py`, "[bu iş]"): `REFS_MAX_ITEMS = 10`, `EVIDENCE_RESULT_MAX_BYTES = 16000`, `ENVELOPE_OVERHEAD_BYTES = 256`, `XREFS_RESULT_MAX_BYTES = 8000`, `DECOMPILED_RESULT_MAX_BYTES = 59296`, `WARNINGS_MAX_ITEMS = 8`, `WARNING_MAX_CHARS = 160`, `NAME_TAG_MAX_CHARS = 128`, `LINE_NUMBER_MAX = 999999`.

## 3. `kanit` şeması düzeltmesi

- **Hata (`asama1a.md` Ek):** `NAME_ANSWER_SCHEMA`'da `kanit` öğe deseni `^r[0-9]{1,9}$` olan sınırsız bir diziydi. Gerçek modelde dizi anlamsız kimliklerle doldu ve 128 jetonluk bütçeyi tüketti.
- **Düzeltme:** sabit şema kaldırıldı. `protocol.build_name_answer_schema(evidence_ids, abstain_allowed=True)` şemayı istek başına kurar:
  - `kanit.items` = `{"type": "string", "enum": [o istekte verilen sonuç kimlikleri]}`;
  - `kanit.maxItems` = `min(kimlik sayısı, REFS_MAX_ITEMS)`; `REFS_MAX_ITEMS = MAX_TOOL_CALLS + 2 = 10`;
  - kimlik listesi boşsa, biçimsizse ya da yineleniyorsa `SchemaError` (şema kurulmaz).
- K0'da kimlikler paketin iki sonucudur; ajan her görevde yeni kimlik verir (`r1, r2`, sonra `r3, r4`…), yani bir önceki görevin kimliği sonraki görevde geçersizdir. Döngüde `final` dalları her turda o ana kadar verilen başarılı sonuçların kimlikleriyle yeniden kurulur; hata sonuçları kanıt gösterilemez.
- `uniqueItems` llama.cpp alt kümesinde olmadığı için yinelenen kimlik şemaca engellenmez (`["r1", "r1"]` geçer); ajan cevabı tekilleştirir. Dizi yine de sınırlıdır.
- **Kilitleyen testler:** `tests/test_lm_protocol.py::test_kanit_semasi_istek_basina_sinirli` (yapı, sınır, duman testindeki taşan dizi, bozuk kimlikler), `::test_ad_oner_semasi` (geçerli / geçersiz cevap kümesi; `NAME_ANSWER_SCHEMA` yok), `::test_gorev_zarfi_birden_cok_final_dali`, `::test_dogrulayici_jsonschema_ile_ayni` (üç yeni şemada `jsonschema` ile aynı hüküm); `tests/test_lm_agent.py::test_k0_kanit_semasi_o_istegin_kimlikleriyle` (arka uca giden şema; önceki görevin kimliği reddedilir).
- Pilot kopyasıyla eşitlik testleri (`test_ayristirma_pilotla_ayni` ve öbürleri) değişmedi ve geçiyor; pilot ayrıştırıcısı `kanit` anahtarını yok sayar.
- **Doğrulanmadı:** yeni şemanın (`enum` öğeli dizi + `maxItems`, `{"type": "null"}`, mantıksal `const`) motorda derlendiği ve üretimi gerçekten sınırladığı. Duman betiği (§6) bunu sınar; betik henüz koşulmadı.

## 4. Testler ve mutasyon

Koşular 2026-11-12, worktree'de, son kodla (027e935 + bu notla aynı dizide commit'lenen test ve mutasyon değişiklikleri). Makinede o sırada bir ürün ölçüm koşusu (Ghidra) vardı; aşağıdaki süreler bu yüzden karşılaştırma için kullanılmamalı.

| Komut | Sonuç |
|---|---|
| `PYTHONDONTWRITEBYTECODE=1 python -m pytest tests/test_lm_agent.py tests/test_lm_backend.py tests/test_lm_context.py tests/test_lm_probe.py tests/test_lm_protocol.py tests/test_lm_tools.py -q -p no:cacheprovider` | **168 geçti**, düşen ve atlanan yok (agent 25, backend 54, context 11, probe 14, protocol 44, tools 20) |
| `PYTHONDONTWRITEBYTECODE=1 python scripts/mutation_probe.py --spec scripts/measurement/mutation_specs_lm_ajan.json` | **159 / 159 öldü**, 0 hayatta, 0 hata. Ölümlerin hepsi tek bir test başarısızlığı (`1 failed`); toplama hatasıyla ölen yok. Modül başına: `agent.py` 56, `context.py` 39, `tools/__init__.py` 26, `tools/read.py` 21, `__init__.py` 9, `protocol.py` 8 |
| `PYTHONDONTWRITEBYTECODE=1 python scripts/mutation_probe.py --spec scripts/measurement/mutation_specs_lm_cekirdek.json` (Aşama 1a tanımı, 1b koduna karşı) | **132 / 132 öldü**, 0 hayatta, 0 hata (125'i tek başarısız test, 7'si parametreli testte bir başarısız durum; 1a'daki dağılımla aynı) |

- Her mutant koşusunun sonunda `karadul/lm/*.py`, `karadul/lm/tools/*.py` ve `tests/test_lm_*.py`'nin sha256'sı koşudan öncekiyle karşılaştırıldı: hepsi aynı (geri yükleme tam).
- `tests/test_lm_agent.py`, `test_lm_tools.py`, `test_lm_context.py`'deki 55 test işlevinin her biri ve `test_lm_protocol.py`'nin bu işte eklenen / değişen üç testi (`test_kanit_semasi_istek_basina_sinirli`, `test_ad_oner_semasi`, `test_gorev_zarfi_birden_cok_final_dali`) en az bir mutantın hedefidir (sayım betikle: tanımdaki `test` alanları ile test dosyalarının AST'si). Mutantların hepsinde aranan metin modülde tam bir kez geçiyor ve değiştirilen metnin uzunluğu özgününden farklı (.pyc tuzağı).
- **Bulunduğu hâliyle (2026-11-12 sabahı) ilk koşu:** commit'siz farkla birlikte 152 mutantlık tanım, 152 / 152 öldü. Commit'siz farkta mutasyon çalışmasının izleri vardı: (1) `tools/__init__.py`'deki körlük işlevinden `if a == blind_target: return None` satırı kaldırılmış; bu satır eşdeğerdi, çünkü `name_tag` adı `raw_name`'den okur ve hedefin adı (`hidden`) bir sonraki koşulda (`r[0] == hidden`) zaten eleniyor; o koşulu bozan mutant (`t_kor_ayni_ad`) ölüyor. (2) `context.py`'deki kaçış deseninde kaynakta görünmeyen U+2028 / U+2029 karakterleri `\u2028\u2029` yazımına çevrilmiş; derlenmiş desen eskisiyle aynı (iki sürüm derlenip karşılaştırıldı), değişiklik satır tabanlı araçların (mutant tanımı dahil) dosyayı doğru okuması için. (3) İki sınır testi: 128 karakterlik ad gösterilir, 129 gösterilmez (`len(name) > NAME_TAG_MAX_CHARS`); yalnız ithal çağrısı olan paket boş sayılmaz (`empty_content` iki koşulun birlikte aranması). Bu testler sabit yerine 128 / 129 sayılarını yazıyor: sabitin değerini değiştiren mutant (`o_uzun_ad`) ancak böyle ölür.
- **Bu işte eklenen yedi mutant** ve sonuçları: `a_bellek_yalniz_bekci`, `a_bellek_yalniz_arka_uc` (bellek durma denetiminin iki koşulu), `a_dongu_onarim_sifirlanmaz` (onarım hakkı tur başına), `a_istem_kestirimi_birikmez` (usage yokken kestirimin birikmesi), `a_gunluk_gecersiz_arguman` (şemaya uymayan argüman kayda girmez) bulundukları hâliyle testlere karşı **hayatta kaldı** (test dosyası geçici olarak eski hâline döndürülüp aynı yedi mutant koşuldu: 2 öldü, 5 hayatta). Testler güçlendirildi (`test_bellek_bekcisi_her_model_cagrisindan_sonra`, `test_dongu_gecersiz_cagri_sayilir_ve_surer`, `test_dongu_baglam_butcesi`, `test_gorev_ve_arac_kaydi_ikili_verisi_tasimaz`); beşi de öldü. `a_tekrar_ontanim` ve `a_bitis_override_yok` var olan testlerle zaten ölüyordu.
- Testler gerçek süreç açmaz ve ağ isteği atmaz; `test_ajan_ice_aktarma_siniri_ve_yan_etkisizlik` alt süreçte `Popen`, `socket.connect` ve `socket.bind`'ı yasaklayıp `context`, `tools`, `tools.read`, `agent` modüllerini içe aktarır.
- Tam test takımı bu işte koşulmadı (ana oturum talimatı); main'e alındıktan sonra koşulmalı.

## 5. Gerçek veride GT'siz sağlama (model yok)

Komut (her çalışma alanı için; sahte arka uç her fonksiyona aynı hazır çekimser cevabı verir, sunucu başlamaz):

```zsh
python docs/arge/2026-11-11_karadullm/zemin/k0_duman.py <çalışma alanı> --kuru [--kor]
```

Çalışma alanları (salt okunur): `~/karadul_olcum/runs/urun-yeni-93a2956/debian/tree/tree/ws/workspaces/tree/20261111_050850` ve `…/mac/htop/ws/workspaces/htop/20261111_055521`.

**Durum: koşulmadı (2026-11-12).** İlk ajan bu komutu iki çalışma alanında koşmuş görünüyor (§2 madde 3 ve §8'deki sayılar oradan), ama çıktısı ağaçta ya da geçici dizinlerde yok ve tablo yazılmadan durduruldu. Tamamlama işinde betik çalıştırılmadı: makinede o sırada Ghidra'lı bir ürün ölçüm koşusu vardı ve ana oturum betiğin bu işte çalıştırılmamasını istedi. Betik yalnız okundu ve sözdizimi denetlendi (`python -m py_compile`); kullandığı arayüzler (`FakeBackend.replies` / `.calls`, `AuditLog(path, keep_in_memory=)`, `LlamaServerBackend(binary, model_path, state_dir, template_path=, ready_timeout=)`, `MemoryGuard.peak` / `.tripped`, `model_istegi` kaydının `timings` alanı) koddan doğrulandı.

Ana oturuma: makine boşken iki çalışma alanında `--kuru --cikti <dizin>` ile koşup `k0_kuru_sonuc.json`'dan şu satırlar bu bölüme yazılmalı: `durumlar` (kaç fonksiyonda paket kurulamadı, `baglama_sigmayan`), `istem_jeton_kestirimi`, `sayimlar` (`kod_kirpildi_tek_atis`, `kanit_kirpildi`, `icerik_adsiz`, araç hata kodları), `kacislama` (§2 madde 3'ün sayıları), `kanit_kurma_sn` (§8'in sayıları). O zamana kadar §2 madde 3 ve §8'deki kuru koşu sayıları doğrulanmamıştır.

Bu işte kuru koşudan bağımsız olarak doğrulananlar (iki çalışma alanının `static/` dosyalarının doğrudan okunmasıyla): §2 madde 6'nın kenar tekilliği sayıları ve `apis` sayılarının hep 1 olması.

## 6. Ana oturum için: gerçek modelle duman betiği

**Durum: henüz koşulmadı.** Betik bu işte hiç çalıştırılmadı (ne gerçek ne kuru kipte); yalnız okundu ve `python -m py_compile` ile sözdizimi denetlendi (§5). Gerçek koşu, makine boşken ana oturumun işidir. Aşağıdaki "ne yapar / neyi ölçer" maddeleri betiğin koduna göre yazıldı, çıktısına göre değil.

```zsh
cd /Users/apple/Black_Widow
python docs/arge/2026-11-11_karadullm/zemin/k0_duman.py \
  ~/karadul_olcum/runs/urun-yeni-93a2956/mac/htop/ws/workspaces/htop/20261111_055521 \
  --en-cok 5 --cikti <çıktı dizini> [--kor] [--adres FUN_…]
```

- **Ne yapar:** makinede çalışan bir `llama-server` varsa başlamaz (çıkış kodu 2). Yoksa `LlamaServerBackend`'i başlatır (ikili ve model `lm_duman.py`'dekilerle aynı; `--ikili`, `--model`, `--sablon` ile değişir), adrese göre eşit aralıklı en çok N program fonksiyonunda `Agent.suggest_name` koşturur, her görevden sonra bellek bekçisini denetler, sunucuyu `finally` içinde kapatır ve kapandığını `pgrep` çıktısıyla kayda yazar. `bellek_durdu` ya da `arka_uc_hatasi` görülürse kalan fonksiyonlara geçmez.
- **Çıktı:** `<çıktı>/k0_duman_sonuc.json` (görev başına `TaskResult` + sunucunun `timings` alanı, özet) ve `<çıktı>/denetim.jsonl` (denetim günlüğü). Modelin önerdiği adlar ve gerekçeler sonuç dosyasına girer; günlüğe girmez.
- **Neyi ölçer:**
  1. Yeni `kanit` şeması motorda derleniyor mu ve üretimi sınırlıyor mu: `ozet.bitis_nedenleri` (`stop` / `length`), `ozet.durumlar` (`butce_asimi` sayısı), `ozet.kanit_uzunlugu_en_buyuk` (K0'da ≤ 2 olmalı), `ozet.uretim_jetonu`.
  2. Jeton kestiriminin doğruluğu: `ozet.gercek_bolu_kestirim` (`usage.prompt_tokens` / kestirim). Bu oran §2 madde 16'daki [tahmin] oranlarını ve bağlam ön denetiminin payını ayarlamak için gereken tek sayıdır.
  3. Süre ve bellek: `ozet.sure_sn`, görev başına `timings`, `ozet.bellek_tepe`, `ozet.bellek_durdurdu`.
  4. Durum dağılımı ve pilot sınıfları: `ozet.durumlar`, `ozet.ad_durumlari`.
- **Ölçmediği:** ad doğruluğu (GT okunmaz); K1 / K2 (kapalı); önek önbelleği (K0'da her görev yeni konuşmadır, "dal" deseni).
- Betik `karadul`'un kendi ağacından yüklendiğini denetler; başka ağaçtan yüklendiyse durur.

## 7. `karadul/config.py`'ye taşınacak sabitler (bu işte eklenenler)

`CODE_LIMIT_BYTES`, `CODE_HEAD_BYTES`, `CODE_TAIL_BYTES`, `EVIDENCE_MAX_CALLEES`, `EVIDENCE_MAX_CALLERS`, `EVIDENCE_MAX_CALLBACKS`, `EVIDENCE_MAX_STRINGS`, `EVIDENCE_STRING_CHARS`, `EVIDENCE_MAX_CONSTANTS`, `EVIDENCE_API_LIMIT` (pilot kopyaları; eşitlik testi yerinde kalmalı), `MAX_TOOL_CALLS`, `MAX_TOOL_CALLS_K1`, `CONTEXT_TOKENS_K2`, `CONTEXT_TOKENS_K2_FALLBACK`, `XREFS_MAX_ROWS`, `BUDGET_*` (altı dilim), `BYTES_PER_TOKEN_CODE`, `BYTES_PER_TOKEN_TEXT`, `LOOP_CODE_LIMIT_BYTES`, `TIME_BUDGET_FACTOR` ve §2 madde 22'deki dokuz sabit. `karadul/config.py`'ye dokunulmadı.

## 8. Doğrulanmayanlar ve riskler

- **Gerçek modelle hiçbir yol koşmadı.** Yeni şemanın derlenmesi, KL-0 + zarf biçimli istemle modelin geçerli cevap üretmesi, Türkçe gerekçe, `kanit` kullanımı: hepsi §6'daki betiği bekliyor.
- **Jeton kestirimi ölçüm değildir.** Bağlam ön denetimi kestirimle yapılır (kuru koşunun "bağlama sığmayan" sayısı da öyle; §5, bu işte koşulmadı). Kaçışlı JSON içindeki kodun gerçek jeton sayısı 1,5 bayt/jeton oranından sapabilir; sapma büyükse sunucu isteği reddeder ve görev `arka_uc_hatasi` ile biter (sessiz kırpma olmaz).
- **K1 / K2 hiçbir modelle denenmedi.** Zarfın `integer` + `minimum` / `maximum` taşıyan argümanları ve K1'in büyük `enum` adres listesi motorda derlenmedi (Aşama 1a notu §2 madde 7 hâlâ geçerli). Kapılar (K-Z1, K-A1…) geçilmeden açılmamalı.
- **Önek önbelleği ile `safe_assistant_content` etkileşimi ölçülmedi.** L3'te araç çağrısı turu yalnız sabit, `enum` ve desenli alanlardan oluştuğu için aynen yazılır; son cevabın gerekçesi `<` taşırsa yeniden yazılır ve o noktadan sonrası önbellekten düşer.
- **Büyük ikili ölçülmedi.** `Workspace.packs` `build_evidence`'ı bütün ikili için bir kez koşturur (ilk ajanın kuru koşusunda tree 0,26 sn, htop 0,75 sn **[doğrulanmadı, §5]**; Z10 büyük ikili için açık). `address_refs` bütün decompile dosyalarını bir kez okur.
- **Çalışma alanı nesne ömrünce değişmez sayılır.** Arayüzden ad değişince (`naming_map.json` güncellenir) `Workspace` yeniden kurulmalı; Aşama 3'ün işi.
- **Ad haritası biçimi:** adlar `reconstructed/src/naming_map.json` `global` bölümünden, etiketler `naming_provenance.json`'dan okunur. Temiz çıktının 1.1 biçimli haritası (`mappings` / `candidates`) okunmuyor; ikisi ayrışırsa araç çalışma alanı haritasını gösterir.
- **Körlük taraması hedefin adını dizgi ve kod alanlarında aramaz** (pilot §12: dizgideki eşleşme meşru kanıt). Kod ham Ghidra çıktısıdır; hedefin Karadul adı bir ithal adıyla aynıysa kodda görünür ve bu taramaya girmez (kanıt alanındaki `apis` taraması o durumu yakalar ve istemi durdurur).
- **Denetim günlüğünde araç argümanları** (adres, yön, satır numarası) yazılır; ikili içeriği değildir ama hangi fonksiyonlara bakıldığını gösterir.
- **`Agent._run`'daki `WorkspaceError` dalı bugünkü akışta erişilemez.** Paket araçları `Workspace.packs` hatasını kayıt katmanında `ic_hata`'ya çeviriyor (paket kurulamaz, görev `paket_hatasi`); K1'in `_neighbours`'ı paketler başarıyla kurulduktan sonra çağrıldığı için önbellekten okur. Dal savunma amaçlı duruyor; testi ve mutantı yok.
- **`k0_duman.py`'nin gerçek ve kuru kipi koşulmadı** (§5, §6).
- **Motor sınırı:** `karadul/lm/` dışındaki hiçbir `karadul/` modülü, `ui/` ya da `scripts/` `karadul.lm`'i içe aktarmıyor (2026-11-12 `grep`). Ters yönde `karadul/lm/tools/__init__.py` motordan iki modül okuyor: `karadul.core.naming_labels` (etiket sözlüğü) ve `karadul.reconstruction.tarif.evidence.build_evidence` (ilk kullanımda, işlev içinde). Tasarım §2.1 bunu öngörüyor ("bu paket motor modüllerinden okuyabilir; tersi yasaktır"); K-M1 Aşama 3'te `karadul analyze`'ın içe aktarma grafiğiyle ölçülecek.
- Mutasyon koşusu sırasında görülenler §4'te.
