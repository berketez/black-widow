# KaradulLM: yerel model zemininin ölçümü (2026-11-11)

Kapsam: tasarım belgesinin (`../tasarim.md`) §2.2, §8 ve §9.1'deki yerel model zemini. Model Qwen3.8-27B Q4_K_M (`~/.lmstudio/models/lmstudio-community/Qwen3.8-27B-GGUF/Qwen3.8-27B-Q4_K_M.gguf`), çalıştırıcı LM Studio'nun llama.cpp motoru 2.60.0 içindeki `llama-server` (`version: 0.7.0-dev (build 1, commit 2a66703)`). Harness ve istemler değiştirilmedi. Ghidra ya da Karadul hattı koşturulmadı. GT ve kör setler okunmadı.

## 0. Kısa sonuç

- **Kapılar:** Qwen3.8 kuru koşusunun eksikleri harness değişmeden tamamlandı. `kapilar --model qwen38`: K-1…K-5 **hepsi geçti** (K-3 `ret` 0 / 40; K-5 bellek denemesi C 5 / 5, C-D 2 / 2, tepe 17,63 GiB ≤ 20; bugünkü kayıtların tepesi 17,43). Pilot yine de başlamaz: protokol §8.1 iki modelin kuru koşusunu ister, Gemma 4 hiç koşmadı; K-6 hesaplanmadı.
- **Hız:** önek 106,8, üretim 10,1 jeton/sn (22 çağrı). Ekim'in yük altı sayıları 117,3 ve 10,9. **Bu boş makine ölçümü değil:** koşu sırasında başka bir oturumun eğitim ve kalibrasyon işleri vardı, yük ortalaması ortalama 17,67 (§1). Boş makine hızı ölçülemedi.
- **Önek önbelleği:** model karma mimaride (`qwen35`, dört katmandan biri tam dikkat). Ajan döngüsünün büyüyen konuşmasında ("ek") pilotun yalın bayrakları **zaten** önek kullanıyor (2.637 jetonun 2.600'ü; 0,83 sn; tepe 17,46 GiB). Ortak sistem istemiyle yeni konuşmada ("dal", pilotun deseni) önek yalnız llama.cpp öntanımlılarıyla geldi (2.593'ün 2.559'u; tepe 18,56 GiB). `--ctx-checkpoints 1` yetmedi. Ara seçenek ölçülmedi.
- **Şema:** düz `anyOf` zarfı bu motor sürümünde derlendi; 10 / 10 şemaya uygun, ortalama 5,11 sn.

## 1. Ortam: makine boş DEĞİLDİ (sapma)

Görev "makine boş" varsayımıyla verildi. Ölçüm sırasında makinede başka bir oturumun işleri koşuyordu:

- 10:02'de `ps`/`top`: iki eğitim süreci (`runs_oz/karalama_20261111/h0_egit.py`, 09:49'dan beri; `ki2_ince_ayar.py`, 09:56'dan beri), bir kalibrasyon betiği (`kalibrasyon.py`) ve çok süreçli bir Python işi; her biri %35-95 CPU.
- Yük ortalaması (1 dk): başlangıçta 6,78 (09:57, `uptime`), koşu boyunca ortalama 17,67, en çok 26,46 (§3).
- GPU istemcileri (10:03 ve 10:18): `ioreg -r -c AGXDeviceUserClient -d 1 -w 0 | grep -o '"IOUserClientCreator" = "[^"]*"'` → `llama-server`'ın yanında Python süreçleri (10:03'te `pid 90549` = `ki2_ince_ayar.py`; 10:18'de `pid 90549` ve `pid 1954`, ikincisinin komutuna bakılmadı). Metal istemcisi olmak GPU'yu yoğun kullanmak demek değil.
- GPU kullanımı (`ioreg -r -d 1 -w 0 -c IOAccelerator`, `"Device Utilization %"`, 15 sn aralıkla 74 örnek, 10:03-10:21): sunucu çalışırken çoğunlukla 88-100; **sunucu kapalıyken alınan dört örnekte 0, 4, 10, 9** (10:17:56, 10:19:57, 10:21:28, 10:21:43). Öbür işler GPU'yu sürekli doldurmuyordu; yavaşlamanın GPU yarışından geldiği gösterilemedi. CPU yükü kesin vardı.
- 10:21'de iki eğitim süreci (90549, 94554) bitmişti; yük ortalaması 11,54. Bu süreçlere dokunulmadı (başka oturumun işi).

Bu yüzden §3'teki hız sayıları **boş makine sayısı değildir**; başka işlerle yüklü makinenin sayısıdır. Bellek ve kapı sonuçları bundan etkilenmez (bellek yalnız `llama-server` sürecinin RSS + footprint'idir; ret ve geçerlilik içerikle ilgilidir).

## 2. Yarım kalan kapılar (K-3, K-5)

**Koşu:** 09:57:49-10:17:53. Harness kaldığı yerden sürdü: sonda adımı 25 tamamlanmış kaydı atladı, 15'ini koştu; bellek denemesi C'de 5, C-D'de 2 çağrı. Sürücü çıktısı:

```text
=== 2026-11-11 09:57:49 qwen38 sonda (kaldığı yerden; --yukle)
llama-server hazır (pid 91251, 20 sn)
{"yapilan": 15, "atlanan": 25, "en_yuksek_bellek_gb": 16.305, "sure_sn": 573.6162483692169}
=== 2026-11-11 10:07:51 qwen38 bellek C
{"yapilan": 5, "atlanan": 0, "en_yuksek_bellek_gb": 16.294, "sure_sn": 338.3540463447571}
=== 2026-11-11 10:13:33 qwen38 bellek C-D
{"yapilan": 2, "atlanan": 0, "en_yuksek_bellek_gb": 16.265, "sure_sn": 251.13041591644287}
=== 2026-11-11 10:17:47 qwen38 boşalt
{"yapilan": 0, "atlanan": 1, "en_yuksek_bellek_gb": 0.0, "sure_sn": 0.0}
```

**`python scripts/measurement/llm_pilot.py kapilar --kok workspaces/2026-10-19_g6_pilot --model qwen38` (10:18):**

| Kapı | Sonuç | Sayılar (komut çıktısından) |
|---|---|---|
| K-1 Yükleme ve şablon | Geçti | kuru çağrı 40 / 40; düşünmesiz çağrılarda düşünme metni 0 |
| K-2 JSON geçerliliği | Geçti | 20 / 20 |
| K-3 Reddetme | **Geçti** (bugün tamamlandı) | `ret` 0 / 40 (beklenen 40) |
| K-4 Belirlenimcilik | Geçti | 40 / 40 aynı ham çıktı |
| K-5 Bellek | **Geçti** (bugün tamamlandı) | bellek denemesi C 5 / 5, C-D 2 / 2; tepe 17,63 GiB ≤ 20 |
| K-6 Süre | Hesaplanmadı | `saat_tahmini: null`, `dusunme_alt_kumesi: 50` (harness'ın öntanımlı çıktısı; §7) |
| hepsi (K-1…K-5) | **true** | |

- **K-5 ayrıntısı.** `kapilar` tepesi (17,63 GiB) Ekim kayıtlarından geliyor. Bugünkü 22 kaydın tepesi 17,43 GiB (`bellek_ust_gb`; RSS + footprint); bellek denemesinin kendi tepesi C'de 17,425, C-D'de 17,397 GiB. En uzun istemler 6.132-6.934 jeton (Qwen tokenizer'ıyla; protokolün ~7,6K tahmini Gemma tokenizer'ıyla yapılmıştı). C-D yanıtları 450 ve 808 jeton; bağlam en çok 7.742 jetona çıktı (sınır 10.240). Bağımsız bekçi (`bekci.py`, 3 sn, 354 örnek) tepeyi 17,46 GiB ölçtü (10:16:17; RSS 16,33 + footprint 1,13); 22 GiB eşiği hiç aşılmadı, olay yok (`bekci_kapilar.json`).
- **Sonda.** Bugünkü 15 çağrının ayrıştırma durumu hepsi `gecerli`; toplam sondada `ret` 0.
- **Pilot bu modelle başlayabilir mi?** Protokol §8'e göre birincil model K-1…K-5'i geçmeli: **Qwen3.8 geçti.** Ancak pilot yine başlamaz, çünkü protokol §8.1 "Pilot, kuru koşu iki modelde de tamamlanmadan başlamaz" diyor ve Gemma 4'ün kuru koşusu hiç koşmadı. Ayrıca K-6 (süre) hesaplanmadı. Karar ana oturumda.
- **Harness çıktı dizini:** `/Users/apple/Black_Widow/workspaces/2026-10-19_g6_pilot/` (git dışı). Bugün eklenenler: `ham/qwen38/sonda/…` (15 dosya), `ham/qwen38/bellek/…` (7 dosya), `ilerleme.jsonl` satır 112-133, `llama_server.log` satır 1283'ten sonrası, `llama_server.pid` (boşaltmada silindi).

## 3. Hız

Yöntem tasarım Ek A'nınki: sunucu günlüğündeki `prompt eval time = … ms / N tokens` ve `eval time = … ms / N tokens` satırlarının toplam jetonu bölü toplam süre. Yalnız bu koşunun satırları okunur (günlükte 1283. satırdan sonrası; ilerleme kaydında 112-133). Günlükteki 22 çağrı ilerleme kaydının 22 satırıyla sıra ve girdi jetonu bakımından birebir eşleşti (`siralama_eslesmesi: true`; günlükte işlenen istem jetonu 100.931 = ilerleme kaydındaki girdi jetonu 100.931, yani hiçbir çağrıda önek atlanmadı; `cached_tokens > 0` olan kayıt 0 / 22). Komut §8'de; çıktı `hiz_kapilar.json`.

| | Ekim (2026-10-19; Ek A) | Bugün (2026-11-11; makine başka işlerle yüklüyken) |
|---|---|---|
| Çağrı | 111 | 22 (sonda 15, bellek C 5, bellek C-D 2) |
| Önek hızı, toplam | 117,3 jeton/sn | **106,8** jeton/sn (100.931 jeton) |
| Üretim hızı, toplam | 10,9 jeton/sn | **10,1** jeton/sn (2.199 jeton) |
| İlk çağrı(lar) | önek 185,9 ve 179,1; üretim 18,8 ve 18,6 (yeniden başlatma sonrası 187,8 ve 18,0) | önek 152,1, üretim 15,1 (sonda C, 4.089 jeton istem); ikinci çağrı 154,8 ve 16,0 |
| Kırılım | — | sonda B 112,4 / 10,5; sonda C 106,4 / 10,6; bellek C 103,2 / 10,0; bellek C-D 107,5 / 9,9 (önek / üretim) |
| Yük ortalaması (1 dk) | 33-45 (protokol §8.1) | ortalama 17,67, en az 6,2, en çok 26,46 (`os.getloadavg`, 3 sn aralıkla 354 örnek, 09:57:41-10:18:04) |

**Okuma:**
- Bugünkü sayılar Ekim'in yük altı sayılarıyla aynı bantta (önek ~107 / ~117, üretim ~10 / ~11). İlk çağrı Ekim'in ilk çağrılarından da yavaş (152 / 186).
- Bu, "boş makinede hız" değildir (§1). Hız çağrı çağrı düştü: önek ilk üç çağrıda 152-157, dördüncüde 143, sonraki 18 çağrıda 84-111 jeton/sn (günlük, 1283+ satırlar: `grep "prompt eval time"`). Aynı aralıkta yük ortalaması 6,8'den 20'nin üstüne çıktı.
- Yavaşlamanın kaynağı ayrıştırılmadı. Sunucu kapalıyken GPU kullanımı %0-10'du (§1), yani GPU yarışı gösterilemedi; CPU yükü ya da ısıl kısma da olabilir (`pmset -g therm` kayıt göstermedi). Tasarım §8'deki "sınıf A" hız varsayımları için boş makinede yeniden ölçüm gerekiyor.

## 4. Önek önbelleği

**Neden 111 çağrının 111'inde önek kullanılmadı (model dosyasından):** GGUF başlığı (`general.architecture = qwen35`, `qwen35.full_attention_interval = 4`, `qwen35.ssm.state_size = 128`, `qwen35.ssm.inner_size = 6144`, `qwen35.block_count = 65`): model karma (hibrit) mimaride; dört katmandan biri tam dikkat, kalanı özyineli durum (SSM/doğrusal dikkat) taşıyor. Özyineli durum geriye sarılamaz: sunucu ortak öneki tutmak için yuvanın durumunu önek sonuna kesemez, ancak o noktada kaydedilmiş bir **bağlam kontrol noktası** varsa oradan sürer. Pilot `--ctx-checkpoints 0` ile koştu. Komut (model dosyasının yalnız başlığı okunur):

```text
$ python3 -I docs/arge/2026-11-11_karadullm/zemin/gguf_basligi.py ~/.lmstudio/models/lmstudio-community/Qwen3.8-27B-GGUF/Qwen3.8-27B-Q4_K_M.gguf
general.architecture = qwen35
qwen35.block_count = 65
qwen35.attention.head_count_kv = 4
qwen35.attention.key_length = 256
qwen35.nextn_predict_layers = 1
qwen35.ssm.state_size = 128
qwen35.ssm.inner_size = 6144
qwen35.full_attention_interval = 4
(kısaltıldı; tam çıktı komutla)
```

Bu bir **açıklama önerisidir**, ölçüm değil; ölçüm aşağıdaki yoklamadır. Yoklama bu açıklamayla uyumlu çıktı: geri sarma gerektirmeyen "ek" deseninde kontrol noktası olmadan da önek kullanıldı, geri sarma gerektiren "dal" deseninde kullanılmadı (tablo aşağıda). Pilotun her çağrısı "dal" desenindeydi (aynı sistem istemi, farklı fonksiyon); 111 / 111'in açıklaması budur.

**Yoklama (`onbellek_yoklamasi.py`).** Her yapılandırma ayrı bir `llama-server` süreci; bayraklar pilotun kendi komut kurucusundan alınır (`llm_pilot.LlamaSunucu.komut`), yalnız `--cache-ram` ve `--ctx-checkpoints` yapılandırmaya göre değişir; port 8139, `--host 127.0.0.1`, her koşuda rastgele `--api-key`. Girdi yapay: sabit tohumla üretilmiş 1.200 sözcüklük numaralı satırlar (sistem iletisi) + kısa kullanıcı sorusu; düşünme kapalı, sıcaklık 0, en çok 24 jeton. Üç ardışık istek:

- **r1:** sistem + u1 (soğuk).
- **r2 "ek":** r1'in iletileri + r1'in yanıtı (asistan) + u2. Ajan döngüsünün büyüyen konuşması.
- **r3 "dal":** aynı sistem + farklı u3. Pilotun deseni (ortak sistem istemi, farklı fonksiyon).

**Sonuçlar (10:18-10:20; her satır `onbellek_<ad>.json`; "yeniden işlenen" = `timings.prompt_n`, "önekten" = `timings.cache_n` = `usage.prompt_tokens_details.cached_tokens`):**

| Yapılandırma (pilot bayraklarına ek) | r1 soğuk: istem / süre | r2 "ek": yeniden işlenen / önekten / süre | r3 "dal": yeniden işlenen / önekten / süre | Bellek tepesi (RSS + footprint) |
|---|---|---|---|---|
| (a) `--cache-ram 0 --ctx-checkpoints 0` (pilot) | 2.594 / 25,78 sn | **37 / 2.600 / 0,83 sn** | 2.593 / **0** / 22,30 sn | **17,46 GiB** (16,34 + 1,12) |
| (c) `--cache-ram 0 --ctx-checkpoints 1` | 2.594 / 23,65 sn | 37 / 2.600 / 0,86 sn | 2.593 / **0** / 23,29 sn | 17,80 GiB (16,57 + 1,23) |
| (b) öntanımlılar (`--cache-ram` 8192 MiB, `--ctx-checkpoints` 32; `--help` çıktısı) | 2.594 / 23,64 sn | 37 / 2.600 / 1,22 sn | **34 / 2.559 / 0,69 sn** | **18,56 GiB** (16,56 + 2,00) |

- Bekçi eşiği (22 GiB) hiçbir yapılandırmada aşılmadı (`sigmadi: false`). Sunucu hazır olma süresi 3,0-4,1 sn (ağırlıklar sayfa önbelleğindeydi).
- Kontrol noktası boyutu sunucu günlüğünde: `erasing old context checkpoint (… size = 149.626 MiB)` (yapılandırma c). Kontrol noktaları istem işlenirken birden çok konumda açılıyor; aynı günlüğün silme satırlarındaki konumlar (`n_tokens`): r1 sırasında 2.078 ve 2.559, r2 sırasında 2.590, 2.600 ve 2.602, r3 sırasında 2.077 ve 2.559. `--ctx-checkpoints 1` en yenisini tutup eskisini sildiği için r3'ün ortak öneki (~2.559 jeton) için kontrol noktası kalmadı; (b)'de r3 tam 2.559 jetonu önekten aldı, yani 2.559. konumdaki kontrol noktasından sürdü.
- (b)'nin footprint'i istek başına büyüdü: hazırda 1,00, r1'den sonra 1,56, r2'den sonra 2,00 GiB. 32 kontrol noktası × 149,6 MiB ≈ 4,7 GiB ve 8.192 MiB istem önbelleği üst sınırlarıyla, uzun bir oturumda tavan 17,35 + 4,7 + 8 ≈ 30 GiB **[hesap, ölçülmedi]**; bu kısa yoklamada 18,56 GiB'ta kaldı.

**Cevap:**
- **Ajan döngüsünün büyüyen konuşması ("ek") için önek yeniden kullanımını veren en düşük bellekli yapılandırma pilotun kendi bayraklarıdır (a):** 2.637 jetonun 2.600'ü önekten geldi, ikinci istek 0,83 sn sürdü (soğukta 25,8 sn); tepe 17,46 GiB, 20 GiB kapısına sığıyor. Koşul: istemci geçmişi bayt bayt aynı yeniden göndermeli (şablonun geçmiş asistan turunu aynı jetonlarla yazması gerekir; bu yoklamada öyleydi).
- **Ortak sistem istemiyle yeni konuşma ("dal", pilotun deseni) için** (a) ve (c) önek vermedi; yalnız (b) verdi (2.593 jetonun 2.559'u, 0,69 sn), tepe 18,56 GiB, bu kısa yoklamada kapıya sığdı ama sınırı yapılandırmayla bağlı değil (yukarıdaki hesap). Aradaki "birkaç kontrol noktası, istem önbelleği kapalı" seçeneği (ör. `--cache-ram 0 --ctx-checkpoints 4-8`) üç yapılandırma sınırı yüzünden ölçülmedi; (c)'nin günlüğü tek istekte üç kontrol noktası açıldığını gösterdiği için küçük bir N'nin dal önekini koruyacağı da garanti değil. Bu satır **yön gösterici**; ölçülmesi gereken bir sonraki yapılandırma bu.

## 5. Şemaya zorlama

`sema_denemesi.py` (10:20:29-10:21:27): pilotun yalın bayrakları + `--api-key`, 127.0.0.1:8139. Zarf şeması tasarım §3.1 Yol A'daki gibi düz: en üstte `anyOf` ile dört araç nesnesi (`get_evidence`, `get_decompiled`, `get_xrefs`, `propose_name`) ve bir `final` nesnesi; ortak `properties` yok; adres `pattern` `^0x[0-9a-f]{1,16}$`, ad `^[A-Za-z_][A-Za-z0-9_]{0,63}$`, `additionalProperties: false`. `response_format: {"type": "json_schema", "json_schema": {"strict": true, "schema": …}}`. 10 yapay görev (uydurma adresler), düşünme kapalı, sıcaklık 0, en çok 256 jeton.

| Ölçü | Sonuç |
|---|---|
| HTTP hatası / şema derleme hatası | 0 (sunucu şemayı kabul etti; Z5'in "bu motor sürümünde derleniyor mu" sorusu: evet, bu şema için) |
| Geçerli JSON | 10 / 10 |
| Şemaya uygun (elle yazılmış katı doğrulayıcı: tam bir dala uyma) | **10 / 10** |
| Şemaya uygun (`jsonschema` 4.23.0) | 10 / 10 |
| Bitiş nedeni | 10 / 10 `stop` |
| Süre | ortalama **5,11 sn**; 9 çağrı 3,99-4,87 sn (25-34 jeton), 1 çağrı 12,32 sn (111 jetonluk `final` metni) |
| Bellek tepesi | 17,40 GiB (RSS 16,37 + footprint 1,03) |

- Dilbilgisi sözdizimini güvenceledi; anlamı güvencelemedi (tasarım §3.1'in öngördüğü gibi). Yön gösterici gözlem (doğrulayıcısı yok): "kimler çağırıyor" görevinde `direction: "from"`, "çağırdığı fonksiyonlar" görevinde `"to"` seçildi; iki "ad öner" görevinde model `propose_name` yerine önce `get_decompiled` çağırdı. `to`/`from`'un anlamı istemde açıklanmamıştı; bu, araç sözleşmesinde yön adlarının açık yazılması gerektiğini gösteriyor, modelin hatası diye okunmamalı.
- Süreler başka işlerle yüklü makinede (§1).

## 6. Sunucunun kapalı olduğu

- Her başlatmadan önce: harness'tan önce `pgrep -fl llama-server` boş (09:57); yoklama ve şema betikleri başlamadan önce `pgrep` ile denetler ve doluysa durur. Dört yoklama sunucusunun her biri bittikten sonra `sonra_pgrep` alanı boş (`onbellek_a/b/c.json`, `sema_denemesi.json`).
- Harness sunucusu `--bosalt` adımında kapandı (10:17:53); PID dosyası silindi.
- İşin sonunda:

```text
$ date '+%F %T %z'; pgrep -fl llama-server; echo "pgrep çıkış $?"; lsof -nP -iTCP -sTCP:LISTEN | grep -c llama-ser
2026-11-11 10:22:43 +0300
pgrep çıkış 1
0
```

(`pgrep` çıkış kodu 1 = eşleşen süreç yok; dinleyen `llama-server` soketi 0.) Bellek bekçisi ve GPU örnekleyici durduruldu.

## 7. Yapılmayanlar ve sınırlar

- **Boş makinede hız ölçülemedi.** Koşu boyunca başka bir oturumun eğitim ve kalibrasyon işleri açıktı (§1). Hız sayıları "yüklü makine" etiketiyle okunmalı; tasarım §8'in boş makine sınıfı için yeniden ölçüm gerekir.
- K-6 (süre) yeniden hesaplanmadı; hız bu koşuda kirli.
- `kunye` adımı (`kuru_kosu3.sh`'de bellekten sonra) koşturulmadı; görev kapsamı K-3 ve K-5'ti. Gemma 4 kuru koşusu hiç koşmadı (pilot iki modeli de istiyor, protokol §8.1).
- Yoklamanın 3 yapılandırma sınırı yüzünden "birkaç kontrol noktası, istem önbelleği kapalı" ara seçeneği ölçülmedi (§4).
- Önbellek yoklamasında her yapılandırma tek kez koştu (tekrar yok); süreler yüklü makinede ölçüldü. Bellek, `llama-server`'ın RSS + footprint'i; ~1,5 sn aralıkla örneklendiği için kısa tepeler kaçabilir.
- Yoklamanın "ek" deseninde ikinci isteğin önek uzunluğu, sohbet şablonunun geçmiş asistan turunu nasıl yazdığına bağlıdır; şablon pilotunkiyle aynıdır (`workspaces/2026-10-19_g6_pilot/sablon/qwen38_chat-template.jinja`).
- §4'teki "özyineli durum geriye sarılamaz" açıklaması model başlığından ve llama.cpp davranışı bilgisinden çıkarımdır; llama.cpp kaynağında doğrulanmadı.

## 8. Yeniden üretim

Kapılar (protokol §8, `kuru_kosu3.sh`'nin Qwen adımları; tek fark: sunucu kapalı olduğu için sonda adımı `--yukle` ile başlatıldı, `kuru_kosu2.sh`'deki gibi). Harness kaldığı yerden sürer (`tamam` olan ham kayıtları atlar):

```zsh
cd /Users/apple/Black_Widow; export PYTHONDONTWRITEBYTECODE=1; K=workspaces/2026-10-19_g6_pilot
P() { python3 scripts/measurement/llm_pilot.py "$@"; }
P kos --kok $K --model qwen38 --istemci llama --kume sonda --kosullar B,C --tekrar 1 --yukle
P kos --kok $K --model qwen38 --istemci llama --kume bellek --kosullar C --tekrar 1
P kos --kok $K --model qwen38 --istemci llama --kume bellek --kosullar C-D --tekrar 1 --en-fazla 2
P kos --kok $K --model qwen38 --istemci llama --kume bellek --kosullar C --tekrar 1 --en-fazla 1 --bosalt
P kapilar --kok $K --model qwen38
```

Bellek bekçisi (harness'ın kendi 20 GiB eşiğine ek, 22 GiB'ta sonlandırır):
`python3 -I docs/arge/2026-11-11_karadullm/zemin/bekci.py --cikti docs/arge/2026-11-11_karadullm/zemin/bekci_kapilar.json --dur <dosya> --esik 22 --aralik 3`

Hız: `python3 -I docs/arge/2026-11-11_karadullm/zemin/hiz_ozeti.py --bas 1282 --ilerleme-bas 111 --bekci docs/arge/2026-11-11_karadullm/zemin/bekci_kapilar.json --cikti docs/arge/2026-11-11_karadullm/zemin/hiz_kapilar.json` (1282 ve 111: koşudan önce `wc -l` ile alınan günlük ve ilerleme satır sayıları).

Önbellek yoklaması (her yapılandırma ayrı süreç, sırayla):

```zsh
Z=docs/arge/2026-11-11_karadullm/zemin
python3 -I $Z/onbellek_yoklamasi.py --ad a --sozcuk 1200 --cikti $Z/onbellek_a.json --gunluk <a.log> -- --cache-ram 0 --ctx-checkpoints 0
python3 -I $Z/onbellek_yoklamasi.py --ad c --sozcuk 1200 --cikti $Z/onbellek_c.json --gunluk <c.log> -- --cache-ram 0 --ctx-checkpoints 1
python3 -I $Z/onbellek_yoklamasi.py --ad b --sozcuk 1200 --cikti $Z/onbellek_b.json --gunluk <b.log>
```

Şema: `python3 -I $Z/sema_denemesi.py --cikti $Z/sema_denemesi.json --gunluk <sema.log>`

Sunucu günlükleri (yoklama ve şema) depo dışında, oturum scratchpad'inde kaldı; sayılar JSON dosyalarına aktarıldı.
