# KaradulLM araç sözleşmeleri v2

- **Tarih:** 2026-11-18. **Paket:** P22d (KaradulLM v2 tasarımı §3.5, §3.4, §3.9, §4.1). **Durum:** kodda; gerçek modelde koşulmadı.
- **Önceki sözleşme:** `docs/arge/2026-11-11_karadullm/arac_sozlesmeleri.md` (O1-O3 ve ortak kurallar). Bu belge onun §1'ini **aynen** devralır; yalnız farkları ve yeni araçları yazar. Çelişkide kod (`karadul/lm/tools/`) ve testler (`tests/test_lm_tools_v2.py`) geçerlidir.
- **Kod:** kayıt ve sınırlar `karadul/lm/tools/__init__.py`; yeni araçlar `karadul/lm/tools/read_more.py`; R1'in ters dizini `karadul/lm/tools/index.py`. Gerçek veri sayımları: `docs/arge/2026-11-18_onarim/P22d.md`.
- **İşaretler:** [tasarım] v2 tasarımının ya da eski sözleşmenin değeri; [seçim] Berke'ye bırakılmış başlangıç değeri; [bu iş] P22d'de konmuş, gerekçesi P22d.md'de.

## 1. Ortak kurallar (eski §1 + v2 farkları)

### 1.1 Sınıflar ve izin eylemi

| Sınıf | Ne yapar | İzin eylemi (tasarım §3.9) | Kayıtlı araç |
|---|---|---|---|
| **O** (okuyan) | Saklı çalışma alanının dosyalarını okur; bir fonksiyon ya da ikili geneli | `oku` | O1-O3, O5, O7, O7b, O8, O10, O11 |
| **R** (ters arama) | Saklı dosyaları okur; ikilinin bütününe "kim kullanıyor" diye sorar, adres almaz | `oku` | R1 |
| **Ö** (öneri) | Yalnız öneri kaydı açar | `oner` | yok (P22e / P22c) |
| **H** (yeniden hesapla) | — | — | **Kayıt defterine giremez** (`ToolRegistry` reddeder) |

- Hiçbir araç süreç başlatmaz, ağa çıkmaz, dosya yazmaz, hedefi çalıştırmaz. Kaynak düzeyinde testle kilitli (`test_arac_paketi_surec_ag_yazma_yok`: yasak modül / çağrı listesi P22d.md kalem 6'da); işlevsel olarak da (`test_araclar_calisma_alanini_degistirmez`: çalışma alanı bayt bayt aynı).
- Hiçbir araç dosya yolu, komut, URL ya da **düzenli ifade** almaz. Metin argümanları düz alt dizgidir ve `in` / `str.find` ile aranır; kullanıcı metninden desen derlenmez (felaket geri izleme olanaksız).

### 1.2 Argümanlar

- `addr` (ve O7b'de `to`): `^FUN_[0-9a-fA-F]{3,16}$`; sunucu adresin `ghidra_functions.json`'da olduğunu denetler, yoksa `bilinmeyen_adres`.
- Bilinmeyen anahtar reddedilir (`additionalProperties: false`). Desen taşımayan her metin argümanının `maxLength`'i vardır (testle).
- Sayfalama: `offset ≥ 0`, `limit` araca özgü tavanla; yazılmayan isteğe bağlı argümanın öntanımı `ToolSpec.defaults`'tadır (tekrar tespiti aynı çağrıyı aynı anahtara indirir).
- K1'in kapalı adres listesi (`schemas(addr_enum=…)`) yalnız `addr`'ı daraltır; O7b'nin `to`'su desenle kalır.

### 1.3 Sonuç zarfı ve hata kodları

Zarf eskisiyle aynı: `id`, `tool`, `ok`, `data`, `kind`, `source`, `limits`, `truncated`. Kırpma sessiz değildir: liste, satır, yol, kenar ya da alan kesilirse `truncated` (ve çoğu araçta `data` içinde toplam sayı) bunu söyler; metin kesilirse sonunda `…[+N]` ya da `…` işareti ve `cut: true` vardır. Tavanı aşan sonuç modele gitmez (`ic_hata`).

| Kod | Anlam | Geçersiz çağrı mı (K-A1) |
|---|---|---|
| `bilinmeyen_adres` | adres çalışma alanında yok | evet |
| `gecersiz_arguman` | şemaya uymuyor ya da anlamsız birleşim (O7b'de aynı uç, R1 dizgide 3'ten kısa, O11'de satır sonu) | evet |
| `arac_kapali` | araç kayıtlı değil / bu kipte yok / körlük kipinde kapalı | evet |
| `bilinmeyen_ad` **(v2)** | R1: ithal adı ikilinin ithal listesinde yok (uydurma boş liste dönmez) | evet |
| `veri_yok` | adres biliniyor ama istenen saklı dosya ya da düğüm yok (çağrı grafiği yok; thunk'ın decompile dosyası yok; `ghidra_types.json` yok) | hayır |
| `veri_bayat` **(v2)** | `ghidra_functions.json` oturum açıldıktan sonra değişti: çalışma alanı yeniden açılmalı | hayır |
| `butce_asildi`, `tekrar`, `ic_hata` | eskisi gibi (ajan) | hayır |

### 1.4 `kind` değerleri

`olgu`, `vekil`, `cikarim`, `olgu+cikarim` eskisi gibi; **yeni** `olgu+vekil` (O5: CFG olgusu + imzadan okunan parametre sayısı).

### 1.5 Körlük kipi

Eskisi gibi: adres listesi veren her araçta etiketler `Workspace.name_lookup(blind_target)` ile kurulur (hedefin adı, aynı adlı komşu, `manual` / `model` ve kaydı başka adı anlatan adlar gösterilmez). O8 hedef için `arac_kapali`; körlükte gizlenen bir komşu adı O8 ile de açılmaz (`arac_kapali`). O11 Ghidra'nın ham decompile metnini arar (Karadul adı içermez).

### 1.6 Olay akışı: `hedef` ve `dokunulan` (tasarım §4.1, §4.5)

- `arac_basladi.hedef` ajan tarafından argümanların `addr`'ından kurulur (`Agent._args_target`). Bu yüzden adres alan her araç adresini `addr` adıyla alır (O7b'de başlangıç ucu). İkili geneli araçlarda (R1, O10, O11) `hedef` `null`: örümcek yer değiştirmez.
- `arac_bitti.dokunulan` = `events.touched_refs(zarf)`: yalnız Karadul'un yazdığı adres alanları. **Bütün yeni araçlar sonuçtaki program fonksiyonlarını `items[].addr`'de taşır**; başka bir adres alanı açılmadı, `events.py`'ye yama gerekmedi. İkiliden gelen metin (dizgi, kod satırı, tip adı, köken gerekçesi) başka anahtarlardadır ve taranmaz: ikiliye gömülü `FUN_…` metni örümceği oynatamaz (testle).

| Araç | `hedef` | `dokunulan` |
|---|---|---|
| O5 `get_function_facts` | `addr` | boş |
| O7 `get_call_graph` | `addr` | gösterilen düğümler |
| O7b `find_path` | `addr` (başlangıç) | gösterilen yollardaki düğümler (başlangıç hariç, `to` dahil) |
| R1 `find_refs` | yok | bu sayfadaki çağıranlar / kullananlar |
| O11 `search_code` | yok | eşleşen satırların fonksiyonları |
| O8 `get_name_provenance` | `addr` | boş |
| O10 `get_types` | yok | boş |

## 2. Yeni okuyan araçlar

Sınırların hepsi `karadul/lm/tools/__init__.py`'de tek yerde tanımlıdır; tablo değerleri oradan. O1 `get_evidence`, O2 `get_decompiled`, O3 `get_xrefs` değişmedi (eski sözleşme §2; `read.py`); olaydaki `hedef` / `dokunulan` davranışları P22a'nındır.

### O5 `get_function_facts(addr)`

| | |
|---|---|
| **Kaynak** | `static/ghidra_cfg.json` (`functions[]`: `block_count`, `edge_count`, `cyclomatic_complexity`, `blocks[].instruction_count`, `loop_headers`, `back_edges`), `static/ghidra_functions.json` (`size`, `param_count`), decompile dosyası (imza, Ghidra uyarıları) |
| **`data`** | `addr`, `size_bytes`, `blocks`, `edges`, `cyclomatic`, `loops` (döngü başlığı sayısı), `back_edges`, `instructions`, `params_ghidra`, `params_signature`, `variadic`, `lines`, `ghidra_warnings` (≤ 8 × 160), `ghidra_warning_total`, `missing` |
| **Sınır** | sonuç ≤ 3 000 bayt [bu iş] |
| **`kind`** | `olgu+vekil` |
| **Hata** | `bilinmeyen_adres`; kaynak eksikse hata değil: alan `null` ve `missing` dosyayı / kaydı adlandırır |
| **Notlar** | `params_ghidra` jenerik fonksiyonda çoğu kez 0'dır ve "parametresiz" demek değildir (geliştirme setinde 20 813 / 23 963); `params_signature` imzadan (çok satırlı imza birleştirilir; dönüş tipinde parantez olan imzada parantez adın ardından aranır; `(void)` → 0; `...` sayılmaz, `variadic: true`); imza okunamazsa `null` |

### O7 `get_call_graph(addr, direction, depth, max_nodes)`

| | |
|---|---|
| **Kaynak** | `static/ghidra_call_graph.json` (`Workspace.call_edges`; arayüzle aynı) |
| **Argüman** | `direction` ∈ `callees` (aşağı) / `callers` (yukarı); `depth` 1-2 (öntanım 2) [tasarım]; `max_nodes` 1-40 (öntanım 40) [tasarım] |
| **`data`** | `addr`, `direction`, `depth`, `items` [{`addr`, `name_tag`, `depth`}] (sıra: derinlik, adres), `edges` [[çağıran, çağrılan]] gösterilen düğümler arası ≤ 80 [bu iş], `coverage` {`reached`, `shown`, `omitted`, `edges_total`, `edges_omitted`} |
| **Sınır** | sonuç ≤ 16 000 bayt [bu iş] |
| **`kind`** | `olgu` |
| **Hata** | `bilinmeyen_adres`; grafik yok / başka koşunun / adresin decompile dosyası yok → `veri_yok` |
| **Notlar** | Öz çağrı düğüm ve kenar değildir. Dolaylı çağrı ve veri yuvası grafikte yoktur. Yalnız `FUN_*.c` dosyası olan program fonksiyonları düğümdür |

### O7b `find_path(addr, to, max_depth)`

| | |
|---|---|
| **Kaynak** | O7 ile aynı |
| **Argüman** | `addr` (başlangıç) çağırır … çağırır `to`; `max_depth` 1-6 (öntanım 6) [seçim] |
| **`data`** | `addr`, `to`, `max_depth`, `found`, `length` (çağrı sayısı), `paths` (en kısa yollar, ≤ 3 [seçim], adres sırasıyla belirlenimci), `paths_total` (bütün en kısa yolların sayısı), `items` [{`addr`, `name_tag`}] |
| **Sınır** | sonuç ≤ 8 000 bayt [bu iş] |
| **`kind`** | `olgu` |
| **Hata** | `bilinmeyen_adres`; aynı uç → `gecersiz_arguman`; grafik / düğüm yok → `veri_yok`. **Yol yoksa hata değil:** `found: false`, `paths: []`, `length: null` |
| **Notlar** | Yolun yokluğu çağrı ilişkisinin yokluğu değildir (dolaylı çağrı). İthal fonksiyona yol için önce R1 ile çağıranlarını bul (açıklamada yazılı) |

### R1 `find_refs(target, value, offset, limit)`

| | |
|---|---|
| **Kaynak** | `static/ghidra_xrefs.json` (`function_xrefs[].functions_called`, `strings_used`) + `static/ghidra_functions.json` (dış / thunk); ithal ayrımı ve ad yazımı `evidence.build_evidence` ile aynı (`get_evidence.apis` ile aynı küme ve sayı: geliştirme setinde 15 722 / 15 722) |
| **Argüman** | `target` ∈ `import` / `string`; `value` 1-128 karakter; `string`'de 3-64 [tasarım]; `limit` ≤ 30 [bu iş] |
| **`data`** | `target`, `value` (ithalde baştaki alt çizgileri atılmış ad), `items` [{`addr`, `name_tag`, `calls`}] ya da [{`addr`, `name_tag`, `matches` (≤ 3 × 120 karakter), `matches_total`}], `total`, `offset` |
| **Sınır** | sonuç ≤ 24 000 bayt [bu iş] |
| **`kind`** | `olgu` |
| **Hata** | ithal ikilide yok → `bilinmeyen_ad`; dizgi 3'ten kısa / 64'ten uzun → `gecersiz_arguman`; kaynak yok / bozuk → `veri_yok`; adres tablosu değişti → `veri_bayat`. Çağıranı olmayan ithal hata değil: boş liste |
| **Notlar** | Yalnız doğrudan çağrı kenarı (adresi alınarak kullanım yok). Dizgi araması düz alt dizgi, harf duyarlı; `ghidra_strings.json` kullanılmaz |
| **Ters dizin** | Çalışma alanı nesnesi başına bir kez kurulur, bellekte durur, diske yazılmaz. Her sorguda iki `stat`: `ghidra_xrefs.json` değiştiyse yeniden kurulur; `ghidra_functions.json` değiştiyse `veri_bayat` |

### O11 `search_code(text, limit)`

| | |
|---|---|
| **Kaynak** | `static/ghidra_output/decompiled/FUN_*.c`, Karadul başlık yorumları atılmış (`strip_header`) |
| **Argüman** | `text` 3-64 karakter [tasarım], düz metin, harf duyarlı, satır sonu yok; `limit` ≤ 20 [tasarım] |
| **`data`** | `text`, `items` [{`addr`, `line_no`, `line` (≤ 160 karakter, eşleşmeyi ortalayan pencere; kesildiyse uçlarda `…` ve `cut: true`)}], `total` (bütün eşleşen satırlar), `functions`, `scanned_functions`, `functions_total` |
| **Sınır** | çağrı başına okunacak decompile metni ≤ 64 MiB [bu iş]; aşılırsa tarama durur, `truncated.scan_stopped: true` (o durumda `total` yalnız taranan fonksiyonlarındır); sonuç ≤ 23 168 bayt (en kötü kaçışla) |
| **`kind`** | `vekil` |
| **Hata** | `gecersiz_arguman` (uzunluk, satır sonu) |
| **Notlar** | `line_no` `get_decompiled`'in satır numarasıdır (`part: "aralik"` ile çevresi okunur). Yorum ve dizgi sabiti içindeki eşleşme koddan ayrılmaz. Ghidra'nın adlandırdığı fonksiyonların (FUN_ olmayan) dosyaları aranmaz |

### O8 `get_name_provenance(addr)`

| | |
|---|---|
| **Kaynak** | `reconstructed/src/naming_map.json`, `reconstructed/src/naming_provenance.json` (`global`, P12a `role_evidence`), `reconstructed/param_naming_map.json` (P05 şema 2; eski çıktıda şema 1) |
| **`data`** | `addr`, `name`, `tag` (`proven` / `verified` / `unverified` / `manual`; öbür araçlarla aynı `name_tag` kuralı), `record` (`eslesti` / `bayat` / `yok`; adsızda `null`), `channel` (`naming_labels.provenance_channel`), `strategy`, `evidence` (KS-1'de `{rol, kanit_sayisi}`), `reason` (≤ 160), `runners_up` (≤ 3, yinelenmesiz), `n_candidates`, `params` [{`param`, `name`, `source`, `reason`}] ≤ 20 + `params_total`, `roles` [{`local`, `role`, `api`, `arg_index`}] ≤ 10 + `roles_total`, `missing` |
| **Sınır** | sonuç ≤ 16 000 bayt [bu iş] |
| **`kind`** | `cikarim` |
| **Hata** | `bilinmeyen_adres`; körlükte hedef ya da gizlenen komşu adı → `arac_kapali`. Dosya / alan yoksa hata değil: `null` + `missing` (1.22.1 çıktısında `role_evidence` yok) |
| **Notlar** | **Sayısal güven hiçbir alanda yok** (v2 tasarımı §1). `bayat` = ad sonradan elle verildi; başka adın kanalı gösterilmez (arayüzün `_provenance` kuralı). `param_naming_map` anahtarı eski çıktılarda fonksiyonun adıdır; Karadul ya da Ghidra adıyla eşlenir. Yerel değişken adları bu sonuçta yok |

### O10 `get_types(query, kind, offset, limit)`

| | |
|---|---|
| **Kaynak** | `static/ghidra_types.json` (`structures`, `enums`, `typedefs`) |
| **Argüman** | `query` 1-64 karakter, düz alt dizgi, harf duyarlı, isteğe bağlı; `kind` ∈ `structure` (struct + union) / `enum` / `typedef` / `all` (öntanım); `limit` ≤ 10 [bu iş] |
| **`data`** | `query`, `kind`, `items` [{`name`, `kind`, `size`, `category`, + `fields` (≤ 12) + `fields_total` / `values` (≤ 12) + `values_total` / `base_type`}], `total`, `offset`, `fields_shown_max` |
| **Sınır** | sonuç ≤ 16 000 bayt [bu iş]: aşılırsa alan tavanı yarılanır, sonra satır düşer; ikisi de `truncated`'da |
| **`kind`** | `olgu` |
| **Hata** | dosya yok → `veri_yok`; boş `query` → `gecersiz_arguman` |
| **Notlar** | İkili genelidir; tipin hangi fonksiyonda kullanıldığı yok. `category` başlık / DWARF kaynağını gösterir |

### Kayıtlı olmayanlar (tasarım §3.5)

O9 `find_similar` (vekil benzerlik; yön gösterici), S1 `get_summary` (P22b özet deposu), N1 `get_notes` (P22e defter), D1 `ask_dataflow` (ertelendi: fonksiyon içi akış verisi yok), Ö1-Ö5 (P22e / P22c), H sınıfı. Bunlar bu pakette yazılmadı.

## 3. Kip başına araç kümesi (tasarım §3.4)

`MODE_TOOLSETS` (kod) — **model** tarafı sabit önekin tanım satırlarına ve zarfın araç dallarına girer; **sunucu** tarafı paket kurarken çağrılır.

| Kip | Model tarafı | Sunucu tarafı | Sabit önekte araç bloğu |
|---|---|---|---|
| `kesif` | O1, O2, O3, O5, O7, O7b, R1, O11, O8, O10 (10) | O1, O2 | var |
| `acikla` | — | O1, O2, O5 | yok |
| `adlandir` | — | O1, O2 | yok |
| `plan` | — | O7, R1 | yok |

- Sıra kipten bağımsız `full_registry` sırasıdır (`ToolRegistry.subset`).
- `default_registry()` (O1-O3) değişmedi: bugünkü K0 / K1 / K2 öneki ve araç kümesi sürümü aynı. K1'in "komşuya bakış" kapısı bu tabloda değil.
- Keşif ve plan kiplerinde `öner` deny: kümelerde yalnız `oku` eylemli araç var (testle).
- Her kip kümesinin sürümü (`registry_for_mode(kip).version()`) ayrıdır ve koşu künyesine yazılmalıdır.

## 4. Jeton maliyeti (tahmin)

Ajanın kendi kestirimiyle (`context.estimate_text_tokens`, P21 LM-04 düzeltmesi; gerçek jetonlayıcı değil) bugünkü K2 sabit öneki O1-O3 ile **5 292 bayt, 1 247 jeton**; keşif kümesinin 10 aracıyla **8 573 bayt, 2 027 jeton** **[hesap, 2026-11-18, `fixed_prefix("K2", …)`]**: yeni 7 tanım ≈ 780 jeton (araç başına ≈ 111). K2 bütçe tablosunda sabit önek dilimi 2 200 (tasarım §3.7): kestirimle sığıyor ama pay %8. Tokenizer çalıştırılmadı; gerçek önek boyu P22e'de `usage`'tan ölçülmeli. Keşif istemi eklenince (P22e) dilim aşılabilir: o zaman ya tanımlar kısaltılır ya da dilim yeniden dağıtılır.

## 5. Doğrulanmayanlar

- Gerçek model araçları doğru seçiyor mu, argümanları doğru yazıyor mu (A-2): model koşusu yok.
- Araç tanımlarının jeton sayısı (§4).
- `bayat` ve `yok` köken dalları gerçek veride hiç görülmedi (yalnız sentetik test).
- Ghidra'nın adlandırdığı (FUN_ olmayan) fonksiyonlar O7 / O7b / O11'de düğüm ya da arama kapsamı değil; bunun analiste maliyeti ölçülmedi.
