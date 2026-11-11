# "Yeniden hesapla" fizibilitesi: toplu geçişin fonksiyon başı sınırları

Tarih: 2026-11-11 · Kod: HEAD 93a2956 (ürün kodu değiştirilmedi) · Veri: saklı koşular (salt okunur)

## Hüküm

Bugünkü üründe "yeniden hesapla" düğmesi **gerçek değil, süs olur**. Toplu geçişte fonksiyon başına
bütçe kesen hiçbir sınır, tek fonksiyon için büyük bütçeyle yeniden koşulunca anlamlı oranda yeni kanıt
üretmedi:

- Derleme zaman aşımı (30 sn) yedi ikilinin 14.376 fonksiyonunun hiçbirine takılmamış (başarısız derleme 0).
- En çok fonksiyona dokunan üç sınırın örneklemlerinde (30'ar fonksiyon) yeni kanıt:
  - derin iz "ilk 3 hedef": 0/30,
  - `decompiled.json` 500 kesmesi (Ghidra high-var tip kanalı): 0/30,
  - mühendislik alan kapısı: 13/30. Bu 13 fonksiyonun hepsinde gelen etiket `rc4`. Kapı açılınca
    `rc4` Mac htop fonksiyonlarının %99,2'sine, Mac tmux'unkilerin %98,3'üne yapışıyor; fonksiyonu
    ayırt etmeyen gürültü.
- Tek gerçek ama küçük kazanç, aynı analizdeki **gövde 5000 karakter kırpmasında** çıktı. Kırpılan 417
  fonksiyonun 28'i (%6,7) yeni algoritma etiketi aldı (49 çift); örneklemde oran 3/30. API tabanlı
  18 çiftin hepsi openssl'de. Bu kazanç bir düğmeyle değil toplu geçiş düzeltmesiyle alınır: kırpmayı
  kaldırmak ikili başına 0,02–0,51 sn ekliyor.
- Ghidra düzeyinde ölçülmemiş tek aday var: "jumptable kurtarılamadı" uyarısı. Mac htop
  fonksiyonlarının %24,4'ünde, Mac tmux'takilerin %8,5'inde görülüyor. Bu çalışmada deneyi yapılmadı
  (aşağıda gerekçe).

## Yöntem ve veri

- İkililer:
  - Debian (eski ürün a10fde3 koşusu, `~/karadul_olcum/n1_debian13`): tmux, openssl, sqlite3, redis-cli, tree.
  - Mac (`workspaces/olcum_mac/runs/ol7-c-b7faeac`): tmux, htop.
- Koşu günlükleri (`kosu.log`, `karadul.log`) yalnız Rich özet tablosunu taşıyor (36–37 satır); logger
  uyarıları saklanmamış. Bu yüzden hiçbir sayı günlükten okunmadı. Her sayı şu iki yoldan biriyle elde
  edildi:
  - saklı çıktıdan (`decompiled.json`, `pipeline_result.json`, `.c` dosyaları) okundu;
  - ya da sınır koşulu saklı girdide ürünün kendi koduyla yeniden değerlendirildi. Koşullar belirlenimci
    olduğu için toplu geçişte de aynı fonksiyonlara takılırlar.
- Eski koşunun Ghidra çıktıları yeni ürünle aynı mı? Yalnız tree'de denetlendi, çünkü yeni ürün
  koşusunda yalnız tree ve zstd bitmişti:
  - `static/ghidra_output/decompiled` 0 dosyada farklı; `cfg.json` ve `call_graph.json` birebir aynı.
  - `deobfuscated/decompiled` 153/250 dosyada farklı. Yeni ürün Ghidra uyarı yorumlarını koruyor;
    algoritma taraması bu yorumları `_strip_ghidra_warnings` (c_algorithm_id.py:836-843) ile ayıkladığı
    için tarama girdisi değişmiyor.
  - Eski `algorithms.json` kullanılmadı: tree'de eski ürün 78 tespit veriyordu, yeni ürün 0. Bütün
    algoritma tespitleri HEAD koduyla yeniden üretildi.
- GT (gerçek ad) ve kör setler okunmadı. Yeni etiketlerin doğruluğu ölçülmedi. "Gürültü" hükmü GT'siz
  iç tutarlılığa dayanıyor: bir etiket ikilideki fonksiyonların büyük kısmına yapışıyorsa o etiket
  fonksiyon hakkında bilgi taşımaz.

## 1. Sınır envanteri

"Takılan" sütunu yedi ikilinin toplamıdır; ikili başına dökümü 2. bölümde.

| # | Sınır | Yer (dosya:satır) | Öntanımlı | Takılan fonksiyona ne olur | Takılan (7 ikili) |
|---|---|---|---|---|---|
| 1 | Fonksiyon başı derleme zaman aşımı | `karadul/ghidra/headless.py:919` (`FUNC_TIMEOUT = 30`, sabit kodlu). `config.py:499` `max_decompile_timeout_per_func=30` hiçbir yerde okunmuyor. | 30 sn | `success: False` + hata metni. Sayaç: `decompiled.json` `failed`. `.c` dosyası yazılmaz. | **0** (failed = 0, 7 ikili) |
| 2 | Parça (chunk) toplam zaman aşımı | `headless.py:1028-1040`; değer `config.py:271` `timeouts.ghidra`, 100 MB üstünde ×4 (`config.py:519-522`) | 7200 sn | Parçanın bütün fonksiyonları başarısız sayılır; `logger.warning`. | **0** |
| 3 | `decompiled.json` 500 kaydında kesilir | `headless.py:1055` (paralel), `headless.py:1330` (seri). Tüketici: `c_type_recoverer.py:1667-1742` (high-var okuma) → `:2217-2241` (2e katmanı). | 500 | 500'ü aşan fonksiyonların `pcode_high_vars` verisi tip kurtarmaya ulaşmaz. **Sessiz**: pyghidra yolunda `functions_truncated` bayrağı yok. Aynı veri `pcode.jsonl`'de eksiksiz duruyor. | **11.126** |
| 4 | Ghidra jumptable giriş tavanı | Karadul `DecompileOptions()` öntanımlısını kullanır (`headless.py:996`, `:1278`). Ghidra: `DecompileOptions.java:299`, `jumptable.cc:1445`, `:1723`, `:2642`. | 1024 | C'de `WARNING: Could not recover jumptable ... Too many branches` yorumu; switch dolaylı çağrıya döner. Sayaç yok. | **528** (üst sınır; aşağıdaki nota bak) |
| 5 | Ghidra tip yayılımı tur sınırı | Ghidra `coreaction.cc:5441-5446` (sabit kodlu, seçenekle değişmez) | 7 tur | `WARNING: Type propagation algorithm not settling`. | **64** |
| 6 | Ghidra komut sayısı tavanı | `DecompileOptions.java:298`; `flow.cc:402` | 100.000 | `Exceeded maximum allowable instructions` | **0** |
| 7 | Algoritma taramasında gövde 5000 karakter kırpması | `karadul/reconstruction/c_algorithm_id.py:1171`; `karadul/reconstruction/engineering/analyzer.py:1002` | 5000 karakter | Sabit/yapı/API taraması gövdenin yalnız ilk 5000 karakterini görür. **Sessiz.** | **417** (13.991 gövdeden) |
| 8 | Mühendislik taraması alan kapısı | `engineering/analyzer.py:276-281`; `_detect_domain` `:846-893`, ilk 10 dosya örneklemi `:877-878` | — | Kapı kapalıysa sabit ve yapı katmanı **hiçbir** fonksiyonda koşmaz, yalnız API katmanı koşar. Kayıt yalnız `logger.info`. Not: ad denetimi (`:862-875`) `functions.json`'un üst anahtarlarını (`functions`, `program`, `total`) geziyor, fonksiyon adlarını değil. Kapı fiilen alfabetik ilk 10 `.c` dosyasıyla karar veriyor. | **13.991** (7/7 ikilide kapı kapalı) |
| 9 | Derin iz "ilk 3 hedef" | `pipeline/steps/_deep_tracing_helpers.py:304-310` (`max_depth=8`, `top_n=3`, sabit kodlu). `config.py:610-611` (`max_trace_depth=10`, `max_trace_targets=5`) okunmuyor. | 3 hedef | Diğer fonksiyonlar için iz yok; çıktı yalnız `call_traces.md`. Ek not: izleyici adsız `FUN_` fonksiyonları kökte bile budar (`deep_tracer.py:743-746`). | **14.360** (eski koşu; `N − trace_targets`) |
| 10 | Derin iz içi sınırlar | `engineering/deep_tracer.py:49-52` (300/600 sn, 5000 düğüm, 100 çağrılan), `:344` `algo_priority_depth=5` | — | `TraceResult.errors`'a "Node limit reached" yazılır. | **0** (izlerde en çok 360 düğüm) |
| 11 | CFG-iso VF2 düğüm tavanı / zaman aşımı / top-K | `config.py:706-707`, `config.py:695`; `computation/cfg_iso/vf2_matcher.py:46-48` | 30 sn, 500 düğüm, K = 10 | VF2 atlanır; zaman aşımında yalnız `reasons` listesine yazılır (saklanmaz). | Düğüm tavanı: **10**. Zaman aşımı: türetilemiyor (gerekçe tablonun altında). Eşleşme 0/14.376. |
| 12 | Hesaplama füzyonu kabul eşiği | `computation/config.py:67` | 0,90 | Eşik altı reddedilir. **Bütçe değil eşik.** | 3.106 adayın 0'ı kabul |
| 13 | c_namer sezgisel aşama zaman aşımı | `reconstruction/c_namer.py:2117` (toplam 1200 sn), `:2121` (300 sn) | 1200 / 300 sn | `errors` listesine "Heuristik timeout". | **0** (en uzun ad aşaması 28,0 sn) |
| 14 | Tip kurtarma ayrıştırma/uygulama zaman aşımı | `c_type_recoverer.py:1137-1151`, `:1262-1275` | 1200 / 300 / 600 sn | `errors` listesi | **0** (en uzun 7,2 sn) |
| 15 | Geri besleme döngüsü tur zaman aşımı | `config.py:533` (3 tur), `config.py:536` | 600 sn | Sonraki turlar atlanır. Program düzeyi, fonksiyon başı değil. | **0** (en uzun döngü 84,8 sn) |
| 16 | Paralel adlandırma parça zaman aşımı | `config.py:773`; `config.py:770` `parallel_naming=False` | 60 sn | Yol kapalı. | **0** |
| 17 | BSim fonksiyon başı aday sayısı | `config.py:587`; gölge mod `config.py:591`, `use_bsim_fusion=False` `:596` | 5 | Fazla aday düşer; gölge modda ad kanalına hiç girmez. | 1.240 fonksiyon tavanda (etkisiz) |
| 18 | Veri akışında çok erişilen alan atlama | `engineering/data_flow.py:1780` | 500 erişim | Alan çifti atlanır. Program düzeyi. | Türetilmedi |
| 19 | Kompozisyon düğüm/kök tavanı | `engineering/composition_analyzer.py:1475`, `:1220` | 50.000 / 10 kök | Program düzeyi | 0 (en büyük çağrı grafiği 2.820 ad) |
| 20 | Kapalı derin katmanlar (bütçe değil bayrak) | `config.py:653` `computation_recovery.enabled=False` (`--deep`/`--compute`); `computation/config.py:51` MaxSMT kapalı | kapalı | Hiç koşmaz. İçlerinde `max_functions_for_formula=2000` gibi kendi kırpmaları var. | Ölçülmedi |
| 21 | Ghidra projesi saklanmıyor | `analyzers/macho.py:937` → `ghidra/project.py:47-62` (`rmtree`) | siliniyor | Tek fonksiyonu yeniden derlemek için ikili baştan içe aktarılmalı (4. bölüm). | Bütün fonksiyonlar |

Tablo notları:

- **Satır 4:** "Too many branches" iletisi `recoverModel` model bulamadığında her durumda çıkar
  (`jumptable.cc:2639-2643`). 1024 tavanı bu nedenlerden yalnız biri (`:1445`, `:1723`). Bu yüzden 528
  bir üst sınırdır.
- **Satır 11, zaman aşımı neden türetilemiyor:** `reasons` listesi diske yazılmıyor. Eşleşmenin 0
  çıkmasının kod okumasından görülen nedeni bütçe değil:
  - Adım Ghidra CFG'sini tek kovalı `{"instr": n}` histogramına çeviriyor (`cfg_iso_match.py:30-80`, histogram satır 66).
  - 315 şablonun düğümleri x86 mnemonik histogramı taşıyor (`mov`, `cmp` …); VF2 düğüm eşleyicisi
    anahtar kümesi eşitliği istiyor (`vf2_matcher.py:82-112`, satır 101).
  - API/dizgi çapaları boş veriliyor (`cfg_iso_match.py:80`).

## 2. GT'siz sayım (ikili başına)

Komut: `python docs/arge/2026-11-11_yeniden_hesapla/say_sinirlar.py --out docs/arge/2026-11-11_yeniden_hesapla/sayim.json`
(14 sn).

| İkili | Fonksiyon | Derleme başarısız | `decompiled.json` dışı | Jumptable uyarısı | Tip yayılımı | Gövde > 5000 / taranan | Alan kapısı | İzlenmeyen (eski koşu) | VF2 > 500 blok |
|---|---|---|---|---|---|---|---|---|---|
| Debian tmux | 2.588 | 0 | 2.088 | 13 | 21 | 121 / 2.547 | kapalı | 2.585 | 2 |
| Debian openssl | 5.672 | 0 | 5.172 | 12 | 13 | 60 / 5.405 | kapalı | 5.669 | 7 |
| Debian sqlite3 | 1.144 | 0 | 644 | 62 | 2 | 33 / 1.132 | kapalı | 1.141 | 1 |
| Debian redis-cli | 1.111 | 0 | 611 | 6 | 6 | 41 / 1.095 | kapalı | 1.108 | 0 |
| Debian tree | 250 | 0 | 0 | 2 | 1 | 7 / 248 | kapalı | 247 | 0 |
| Mac tmux | 2.821 | 0 | 2.321 | 240 | 19 | 134 / 2.800 | kapalı | 2.820 | 0 |
| Mac htop | 790 | 0 | 290 | 193 | 2 | 21 / 764 | kapalı | 790 (iz yok) | 0 |
| **Toplam** | **14.376** | **0** | **11.126** | **528** | **64** | **417 / 13.991** | **13.991** | **14.360** | **10** |

Sayım kaynakları:

- **Fonksiyon:** `functions.json` `total`.
- **Derleme başarısız:** `decompiled.json` `failed`.
- **`decompiled.json` dışı:** fonksiyon sayısı − listelenen kayıt.
- **Ghidra uyarıları:** her `.c` dosyasının kod kısmı (`// --- DISASSEMBLY` öncesi) tarandı.
- **Gövde:** algoritma taramasının girdisi olan `deobfuscated/decompiled` (`binary_prep.py:57-59`)
  üzerinde, ürünün `_FUNC_RE` ifadesi ve sınırsız ayraç eşlemesiyle ölçüldü.
- **Alan kapısı:** ürünün `_detect_domain` yöntemi saklı girdiyle çağrıldı.
- **İzlenmeyen:** `pipeline_result.json` `trace_targets`. Mac htop'ta bu alan yok; HEAD kodu da htop
  için 0 hedef seçiyor.

## 3. Deneyler

Seçim: sayımda en çok fonksiyona dokunan üç sınır.

1. Derin iz (14.360)
2. Alan kapısı (13.991). Aynı analizdeki gövde kırpması (417) bu deneyin ikinci kolu olarak ölçüldü:
   iki sınır da aynı fonksiyon başı algoritma taramasının kapsamını daraltıyor.
3. `decompiled.json` 500 kesmesi (11.126)

Örneklem kuralı her deneyde koşmadan önce betiğin başına yazıldı:

- Havuz (ikili, adres/ad) sırasına dizilir.
- `random.Random(20261111).sample(havuz, 30)` ile seçilir.

Deneylerin hepsi çevrimdışı koştu (Ghidra yok) ve ürün modüllerini değiştirmeden çağırdı. Bütün havuz
sayımı ucuz olduğu için ayrıca yapıldı. Bu sayım örneklemin yerine geçmez, onu denetler.

### Deney 1 — derin iz, ilk 3 hedef dışı

Komutlar:

```
python docs/arge/2026-11-11_yeniden_hesapla/deney1_derin_iz.py --out docs/arge/2026-11-11_yeniden_hesapla/deney1_sonuc.json
python docs/arge/2026-11-11_yeniden_hesapla/deney1_tam_sayim.py
```

- **Girdi:** saklı çağrı grafiği + HEAD algoritma tespitleri. İkili başına 0–72 tespit, 0–64 fonksiyonda.
- **Kollar:**
  - ürün ayarı: `max_depth=8`, `algo_priority_depth=5`;
  - büyük bütçe: 64 / 64, düğüm ve çağrılan tavanı 10⁶.
- **Yeni kanıt tanımı:** kökün kendi etiketinde olmayan, alt ağaçtan gelen algoritma etiketi.
- **Örneklem (havuz 9.705 ad):**
  - Ürün ayarında 0/30, büyük bütçede 0/30.
  - Büyük bütçe ek kazanç 0.
  - Süre: en çok 0,0316 sn (ürün); medyan 0,0038 sn, en çok 0,0044 sn (büyük).
  - Medyan iz büyüklüğü 1 düğüm.
- **Bütün havuz:** 9.705 fonksiyonun 2'sinde (redis-cli) alt ağaç etiketi var. Büyük bütçe ek 0.
- **Nedenler:**
  - Çağrı grafiğindeki 9.721 adın 6.419'u `FUN_…` ve izleyici bunları kökte budar (`deep_tracer.py:743-746`).
  - Tespitler seyrek.
  - Üstelik iz yeni gözlem değildir: başka fonksiyonlarda zaten hesaplanmış etiketlerin çağrı ağacı
    boyunca toplanmasıdır.
- **Hüküm:** süs.

### Deney 2 — algoritma taraması: alan kapısı ve gövde 5000 kırpması

Komutlar:

```
python docs/arge/2026-11-11_yeniden_hesapla/deney2_algoritma_tarama.py --out docs/arge/2026-11-11_yeniden_hesapla/deney2_sonuc.json
python docs/arge/2026-11-11_yeniden_hesapla/deney2_ozet.py
```

- **Kollar:**
  - kripto tanımlayıcı (`CAlgorithmIdentifier`): kırpmalı / sınırsız gövde;
  - mühendislik tanımlayıcı: kapı kapalı-açık × kırpmalı-sınırsız.
- **Yeni kanıt tanımı:** büyük bütçe kolunda olup ürün kolunda olmayan (fonksiyon, etiket) çifti,
  güven ≥ 0,40.

**Alan kapısı (havuz 13.991 gövde)**

- **Örneklem:** 30 fonksiyonun 13'ü yeni etiket aldı; 13'ünün hepsinde `rc4`.
- **Bütün havuz:** yalnız kapı açık kolunda 19.213 yeni çift (≥ 0,40). Kapı açık + sınırsız gövde
  kolunda 7.770 fonksiyon (%55,5) en az bir etiket aldı (20.215 çift).
- **Gürültü kanıtı:** en yaygın etiketin ikilideki fonksiyonlara yayılma oranı (`deney2_ozet.json`):

| İkili | `rc4` yapışan fonksiyon oranı | İkinci etiket |
|---|---|---|
| Mac htop | %99,2 | `halton_sequence` %35,2 |
| Mac tmux | %98,3 | `halton_sequence` %51,0 |
| Debian tmux | %74,5 | `halton_sequence` %45,4 |
| Debian redis-cli | %55,4 | `halton_sequence` %30,2 |
| Debian tree | %46,8 | `halton_sequence` %39,1 |
| Debian sqlite3 | %37,9 | `halton_sequence` %37,0 |
| Debian openssl | %18,9 | `halton_sequence` %8,3 |

- Gövde kırpması örnekleminde kapı açılınca fonksiyon başına 2–21 farklı algoritma etiketi geliyor.
- **Hüküm:** kapı gürültüyü doğru biçimde tutuyor. Tek fonksiyon için açmak zararlı, süs.

**Gövde 5000 kırpması (havuz 417 gövde)**

- **Örneklem:** 3/30 fonksiyon yeni etiket aldı:
  - Mac tmux `FUN_100034c2c`: "Galois field operations";
  - openssl `FUN_001a170c`: "CSPRNG (OpenSSL)";
  - sqlite3 `FUN_001097c0`: "Galois field operations".
- **Bütün havuz:** 28 fonksiyonda 49 yeni çift; ≥ 0,70 güvenli 34 çift.
  - openssl: 33 çift, 15 fonksiyon. Bunların 18'i API tabanlı (`TLS encrypted read/write`, `PBKDF2`,
    `CSPRNG (OpenSSL)` …), 15'i yapısal.
  - Öteki ikililer: yalnız yapısal; sqlite3 6, redis-cli 2, Mac tmux 4, Mac htop 4, Debian tmux 0, tree 0.
- **Kaybolan çift:** 0.
- **Mühendislik tanımlayıcı, kapı kapalıyken:** sınırsız gövde 0 yeni çift verdi.
- **Doğruluk:** ölçülmedi. tmux/htop/sqlite3'teki yapısal "Galois field / Feistel" etiketleri bu
  programların işleviyle uyuşmuyor; şüpheli.
- **Süre:**
  - Tek fonksiyon yeniden tarama (kripto tanımlayıcı): medyan 0,0056 sn, en çok 0,059 sn.
  - Kırpmayı toplu geçişte kaldırmanın maliyeti (`identify` süresi, kırpmalı → sınırsız):
    - Debian tmux 2,02 → 2,46 sn
    - openssl 3,33 → 3,84 sn
    - sqlite3 0,56 → 0,84 sn
    - redis-cli 0,67 → 0,82 sn
    - tree 0,12 → 0,14 sn
    - Mac tmux 2,17 → 2,52 sn
    - htop 0,42 → 0,48 sn
- **Hüküm:** gerçek ama küçük kazanç. Yeri düğme değil, toplu geçiş.

### Deney 3 — `decompiled.json` 500 kesmesi → Ghidra high-var tip kanalı

Komut:

```
python docs/arge/2026-11-11_yeniden_hesapla/deney3_highvar_500.py --out docs/arge/2026-11-11_yeniden_hesapla/deney3_sonuc.json --tmp ~/karadul_olcum/runs/yeniden-hesapla-2026-11-11/deney3_tmp
```

- **Büyük bütçe girdisi:** kesilen fonksiyonların `pcode.jsonl`'deki eksiksiz high-var verisi.
- **Ürün kodu zinciri:** `_load_ghidra_high_vars` → 2e döngüsünün birebir eşi →
  `_apply_per_func_replacements`.
- **Ölçülen:** bildirimde kaç satır değişirdi.
  - Ürüne sadık metin: `reconstructed/merged`, yani tip kurtarmanın iter0 girdisi.
  - En elverişli metin: ham Ghidra C.

**Sonuçlar**

- **Kontrol kolu (kanalın gerçekten çalıştığı listedeki fonksiyonlar):** `merged` üzerinde 7 ikilinin
  hepsinde **0** satır değişiyor. Kanal bugün çalıştığı yerde de hiçbir şey değiştirmiyor.
- **Kesilen 11.126 fonksiyon:** `merged` üzerinde toplam **17** satır (16 dosya); ham C'de 102 satır.
- **Örneklem:** 0/30 (`merged`), 0/30 (ham).
- **Örnek değişiklikler (Mac tmux):** `undefined8 uVar10;` → `uint uVar10;`. Gösterilen 10 değişikliğin
  8'i 8 baytlık bildirimi 4 baytlık tipe çeviriyor. Ghidra yerel adları birleştirmeler arasında
  kararlı olmadığı için bu değişikliklerin bir kısmı yanlış olabilir (ölçülmedi).
- **Süre:** örneklemde fonksiyon başına medyan 4,2 sn, en çok 33 sn. Bunun neredeyse tamamı deney
  düzeneğinin bütün dosyaları taramasından geliyor. Kanalın tek dosyadaki süresi ayrıca ölçülmedi.
- **Hüküm:** süs.

## 4. Tek fonksiyon yolu

**Hazır mekanizma yok.**

- **CLI:** komutlar `analyze, batch, benchmark, bsim, clean, config, diff, info, list, rtti, run,
  score, version`. Tek adres alan bir alt komut yok; `--stage` yalnız aşamada durur.
- **Arayüz:** `/api/decompiled/FUN_x` (`ui/server.py:1999-2010`) saklı `.c` dosyasını okur, hesaplama
  yapmaz.
- **Ghidra betikleri:** `karadul/ghidra/scripts/decompile_all.py` bütün fonksiyonları gezer; adres
  süzgeci yok.
- **Ghidra projesi:** analiz sonunda silinir (`macho.py:937`).

**Ghidra maliyeti** (ölçüm `tek_fonksiyon_maliyet.py`; tek Ghidra süreci, yığın 4 GB; yük ortalaması
7–16, süreler bu yük altında):

| | tree (132 KB, 250 fn) | htop (231 KB, 790 fn) |
|---|---|---|
| JVM başlatma | 1,88 sn | 1,60 sn |
| İçe aktarma + otomatik çözümleme (proje yokken zorunlu) | 5,78 sn | 7,32 sn |
| `DecompInterface.openProgram` | 0,22 sn | 0,22 sn |
| Tek fonksiyon derleme, 30 örnek (medyan / en çok) | 0,0019 / 0,0129 sn | 0,0018 / 0,032 sn |
| Proje saklansaydı disk | 2,95 MB | 4,69 MB |
| Saklı projeyi çözümlemesiz açma + bir fonksiyon derleme | 0,075 + 0,226 sn | 0,080 + 0,224 sn |

Komut:

```
GHIDRA_INSTALL_DIR=~/Library/BlackWidowBuild/ghidra_12.1.2_PUBLIC JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home \
  python docs/arge/2026-11-11_yeniden_hesapla/tek_fonksiyon_maliyet.py <ikili> <deney_dizini> <çıktı.json>
```

İlk ölçüm tur 6,89 / 8,15 sn içe aktarma verdi; tablodaki değerler yük biraz düştüğünde yapılan ikinci
turdan.

Büyük ikililer (tmux, openssl) kural gereği Ghidra'da açılmadı:

- İçe aktarma + çözümleme payları ölçülmedi.
- Saklı `ghidra_duration` (Ghidra aşamasının tamamı, bütün çıkarımlar dahil): Debian tmux 549,8 sn,
  openssl 344,2 sn, Mac tmux 716,2 sn.
- Bunlar tek fonksiyon için üst sınırdır; gerçek pay bilinmiyor.

**Aşamalara göre ayrım (kod okuması):**

- **Tek fonksiyonun C metniyle yeniden koşabilenler:**
  - algoritma taraması (sabit/yapı/API; `_scan_*` yöntemleri yalnız gövde alır);
  - mühendislik taraması;
  - tip kurtarmanın fonksiyon içi 2e katmanı;
  - Ghidra'nın tek fonksiyon derlemesi (proje varsa).
- **Bütün program bağlamı isteyenler:**
  - c_namer: çağrı grafiği yayılımı, dizgi başvuruları, geçiş parametresi mirası, ikilide başka
    fonksiyona ait ad reddi (93a2956);
  - ad birleştirici (fonksiyonlar arası çakışma);
  - tip kurtarmanın struct çıkarımı (alan erişimleri fonksiyonlar arası);
  - veri akışı, kompozisyon, derin iz, parametre yayılımı;
  - BSim (veritabanı), hesaplama füzyonu, geri besleme döngüsü.

## 5. Eylem değerlendirmesi ve ilk sürüm önerisi

| Aday eylem | Ölçülen getiri | Fonksiyon başı süre | Durum |
|---|---|---|---|
| Daha uzun zaman aşımıyla yeniden derle | 0 başarısız derleme / 14.376 | — | Süs |
| Kesilen high-var verisiyle tip ver | Örneklemde 0/30; bütün havuzda 17 satır / 11.126 fn; kontrol kolunda 0 | ms (ayrıca ölçülmedi) | Süs |
| Bu fonksiyonu derin izle | Örneklemde 0/30; bütün havuzda 2 / 9.705 | ≤ 0,03 sn | Süs |
| Alan kapısını açarak tara | 13/30 etiket alıyor ama `rc4` fonksiyonların %19–99'una yapışıyor | ≤ 0,01 sn | Zararlı süs |
| Gövdenin tamamını tara | 3/30; 28/417 fn, 49 çift (18 API, hepsi openssl) | medyan 0,0056 sn | Gerçek, küçük; **toplu geçişe** ait |
| Jumptable tavanını büyüterek Ghidra'da yeniden derle | Ölçülmedi | Proje varken ≈ 0,3 sn; yokken küçük ikilide ≈ 9 sn | Belirsiz |

**Öneri: düğme koyma (0 eylem).** Yerine:

1. **Gövde kırpmasını toplu geçişte kaldır.**
   - Yer: `c_algorithm_id.py:1171`; mühendislik tarafında `analyzer.py:1002` ölçüldü ve 0 kazanç verdi.
   - Beklenen: 7 ikilide 28 fonksiyon, 49 etiket.
   - Maliyet: ikili başına ≤ 0,51 sn.
   - Kod işi: bir satır + test.
   - Ön koşul: yapısal etiketlerin doğruluğu kör setle ölçülmeden açılmamalı.
2. **Jumptable deneyi.** Gerçek bir Ghidra düzeyi "yeniden hesapla" için tek aday.
   - Yöntem: htop'ta tek Ghidra; 193 uyarılı fonksiyondan 30'u `setMaxJumpTableEntries` büyütülerek
     yeniden derlenir; kurtarılan switch sayılır. Tahmini süre birkaç dakika.
   - Olumluysa iki yol var: proje saklanır (küçük ikilide 3–5 MB; büyükte ölçülmedi) ya da her istekte
     yeniden içe aktarılır.
3. **Kapalı derin katmanlar.** `--deep` katmanlarının (constraint solver, CFG fingerprint, formül
   çıkarımı, MaxSMT) tek fonksiyon getirisi ayrı ölçülmeden düğme konmaz.

## 6. Doğrulanmayanlar ve sınırlar

- Yeni etiketlerin hiçbirinin doğruluğu ölçülmedi (GT ve kör set okunmadı). "Gürültü" ve "şüpheli"
  hükümleri iç tutarlılığa dayanıyor.
- Eski koşu Ghidra çıktısının yeni ürünle aynılığı yalnız tree'de denetlendi.
- Günlüklerde logger çıktısı yok. Zaman aşımı ve kırpma iletileri günlükten sayılamadı; bütün sayımlar
  çıktıdan ya da koşulun yeniden değerlendirilmesinden.
- Satır 4'teki 528 jumptable uyarısı "1024 tavanına takılan" için üst sınır; gerçek tavan payı
  bilinmiyor.
- CFG-iso VF2 zaman aşımı sayısı türetilemedi (`reasons` saklanmıyor). Büyük bütçeli CFG-iso koşusu
  yapılmadı; 0 eşleşmenin yapısal nedeni kod okumasından.
- Satır 18 (veri akışı 500 erişim) sayılmadı. Satır 20'deki kapalı katmanlar ölçülmedi.
- Ghidra süreleri yük altında ölçüldü. Büyük ikililerde içe aktarma süresi ve proje boyutu ölçülmedi.
- Tekrar açılan projede `getFunctionCount()` 316 / 976 dönüyor, ilk oturumdaki gezinme 250 / 790
  sayıyordu. Fark farklı sayım çağrısından olabilir; doğrulanmadı.
- Deney 1'in havuzu çağrı grafiğindeki adlardır (9.705), fonksiyon sayısı (14.376) değil; izleyici adla
  çalışıyor.

## 7. Yan bulgular (kapsam dışı, ayrı iş adayı)

- `config.py:499` `max_decompile_timeout_per_func` ve `config.py:610-611` `DeepTraceConfig` derinlik ve
  hedef sayısı ölü ayar. Gerçek değerler sabit kodlu (`headless.py:919`, `_deep_tracing_helpers.py:304`).
- Alan kapısının ad denetimi JSON üst anahtarlarını geziyor (`analyzer.py:862-875`).
- Derin izleyici `FUN_` köklerini budadığı için soyulmuş ikilide pratikte iz üretmiyor.
- CFG-iso adımı mnemoniksiz histogram ve boş çapalarla şablonlara hiç eşleşemiyor.
- High-var 2e katmanı 8 baytlık bildirimi 4 baytlık tipe çevirebiliyor; boyut denetimi yalnız
  `undefined4` için var (`c_type_recoverer.py:2233-2236`).
- `decompiled.json` kesmesi pyghidra yolunda sessiz.

## Dosyalar

- `say_sinirlar.py` → `sayim.json`
- `deney1_derin_iz.py` → `deney1_sonuc.json`; `deney1_tam_sayim.py` → `deney1_tam_sayim.json`
- `deney2_algoritma_tarama.py` → `deney2_sonuc.json`; `deney2_ozet.py` → `deney2_ozet.json`
- `deney3_highvar_500.py` → `deney3_sonuc.json` (geçici girdiler: `~/karadul_olcum/runs/yeniden-hesapla-2026-11-11/deney3_tmp/`)
- `tek_fonksiyon_maliyet.py` → `tek_fonksiyon_tree.json`, `tek_fonksiyon_htop.json` (ikili kopyaları ve
  geçici Ghidra projeleri `~/karadul_olcum/runs/yeniden-hesapla-2026-11-11/tek_fonksiyon/`; projeler silindi)
