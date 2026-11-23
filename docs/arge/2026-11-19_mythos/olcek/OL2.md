# OL2 — ÖL-2: Ghidra köprüsünde adım bütçeleri ve BSim koşulları (ilerleme dosyası)

Paket: uygulama oturumu 2, akşam dilimi, OL2 (`docs/arge/2026-11-23_dalga1/gonderim/OL2.md`). Plan: `docs/arge/2026-11-19_mythos/olcek/PLAN.md` "ÖL-2" (gönderim metnindeki hükümlerle).
Taban: main `0b4d948` (`git merge --ff-only main` sonrası; ürün kodu `152176b` ile aynı, arada yalnız belge). Başlangıç: 2026-11-23 19:37. Sert son: 22:05.
Koşu kökü: `~/karadul_olcum/runs/dalga1-2026-11-23/OL2/` (özetler `ozet/`). Ürün ağacı: `~/karadul_olcum/urun-d83f100` (kod commit'i `d83f100`; altı bağ; kökte S8 için `karadul.yaml`).

## Kalemler

| # | Kalem | Durum | Commit |
|---|---|---|---|
| 1 | Kod: döküm işlevlerine adım bütçesi + adım içi `suruyor` (`headless.py`) | bitti | `d83f100` |
| 2 | Kod: BSim boş depo sorusu, ingest bütçesi, sorgu bütçe denetimi (`bsim.py` + `headless.py` BSim bloğu) | bitti | `d83f100` |
| 3 | Testler (`tests/test_ol2_adim_butcesi.py` 39, `tests/test_ol2_bsim_kosul.py` 24) | bitti: 63 / 63 | `0fff66d` |
| 4 | Mutasyon (`mutation_specs_ol2.json` 33 / 33) + sekiz eski tanım (161 / 161) | bitti | `47947da` |
| 5 | `config.py` yaması (`yamalar/OL2__config.py.patch`; `git apply --check` temiz; uygulanmadı) + `test_p16b_bsim.py` yaması | bitti | `0fff66d`, `84d222b` |
| 6 | Ön kayıt (`on_kayit_ol2.md`; ölçümden önce ayrı commit) | bitti | `1740d82` |
| 7 | sqlite3 (H2) | bitti: **TUTTU** (çıkış 3; sınırsız adımların en uzunu 2,069 sn) | bu commit |
| 8 | S8 (H3, H5) | kuyrukta (20:08'den beri) | — |
| 9 | T25 (H1, H4) | kuyruğa giriyor | — |
| 10 | Tam takım (yamasız) | koşuyor (20:04'ten beri, arka planda) | — |

**20:09 — bekliyorum:** S8 (8 ikili, tek kök `…/OL2/s8`, sıra ORTAK_D0 §6) ikinci yuvada PUV5 ile sırayla; birinci yuvayı ana oturumun Ollama koşusu tutuyor (19:36'dan beri, TAHMİN 1,5–2 sa). T25 kuyruğa giriyor: yuva boşalınca (büyük olasılıkla ana oturumun koşusu bitince) başlar. TAHMİNİ bitiş: S8 20:45–21:15; T25 başlangıcı 21:05–21:35, süresi 45–60 dk (yük altında; BSim'e kadar ~28 dk + ingest ≤ 900 sn), bitiş 21:50–22:05 (sert son 22:05: yetişmezse "kalan"). Tam takım arka planda (TAHMİN 12–20 dk).

## Kalem 1–2 — kod (`d83f100`)

### `karadul/ghidra/headless.py`

- **`_AdimDenetcisi`** (tek denetim noktası): döngü her birimin başında `denetle(islenen[, toplam])` çağırır. Adımın başlangıcı + bütçe geçildiyse `True` (döngüden çık) ve kesildiği andaki gerçek sayaçlar saklanır (`islenen` = biten birim, `toplam` biliniyorsa). Geçilmediyse ve adımın son olayından beri `analysis.bekci_aralik_sn` geçtiyse aynı noktada `ILERLEME … durum=suruyor islenen=n [toplam=N] gecen_sn=…` (ÖL-1'in `_ilerleme` / `ilerleme_satiri` yolu; yeni günlükçü / biçim yok). Zamanlayıcıyla olay yok. `neden()` = `"adım bütçesi (S sn) doldu"` (+ gerekirse `; <ek>`). `kismi_alanlari()` bütçe dolmadıysa `{}` (çıktı bayt bayt aynı), dolduysa `{"kismi": true, "islenen": n, ["toplam": N,] "neden": …}`.
- **Tek zamanlayıcı:** denetçi `_AdimSaati.denetci(adim, butce_sn, aralik_sn, toplam)` ile kurulur ve başlangıcını `_AdimSaati.basla` anından alır (başlamamış adıma denetçi kurulamaz). `_AdimSaati.bitti`, adım sürerken eklenen hata varsa ve denetçi dolduysa kısmi olaya denetçinin gerçek sayaçlarını ekler. Çağrı noktalarındaki `saat.bitti(ADIM_…)` satırları değişmedi (HZ-1 mutantı `hz1_cfg_bitisi_yanlis_yerde` bu satırı tutuyor).
- **Ayarlar** (kodda sabit sayı yok; A-9): `timeouts.ghidra_adim` (adım bütçesi), `analysis.bekci_aralik_sn` (olay aralığı), `bsim.ingest_butcesi_sn`; `getattr` ile okunur, yok / 0 = kapalı. Küçük birimli iki döngüde (P-code komut sayımı, xref'in genel sembol sayımı) saat `KUCUK_BIRIM_DENETIM_ADIMI = 1024` birimde bir okunur; öbür döngülerde her birimde (plan "500 fonksiyonda bir" diyordu; birim başına birkaç Java çağrısı varken bir `time.monotonic()` ihmal edilir, sınır daha sıkı).
- **Döküm işlevleri** (`_extract_strings` veri, `_extract_call_graph` / `_extract_xrefs` / `_extract_cfg` / `_extract_function_id_matches` / `_extract_pcode` fonksiyon, `_extract_types` veri tipi, `_extract_pcode_stats_only` komut): isteğe bağlı `denetci` parametresi (plan `son_an` diyordu; denetçi son anı taşır ve olayları da üretir). Bütçe dolunca döngü birim sınırında biter, çıktıya kısmi alanlar eklenir; birim sınırında kesildiği için her liste P16e'nin sıra kuralını korur (fonksiyon listeleri giriş adresi sırasında, çağıran listeleri `caller_sort_key` ile). `toplam` fonksiyon döngülerinde `functions` adımının `total`'ı (= `getFunctions(True)` yinelemesinin uzunluğu); dizgi / tip / komutta bilinmiyor → yazılmaz. `_extract_xrefs` iki bölümlü: bütçe fonksiyonlarda dolarsa genel sembol sayımı koşmaz (`neden` "…; genel sembol sayımı yapılmadı"), sayımda dolarsa "…; genel sembol sayımı yarıda (k sembol)".
- **`_analyze_pyghidra`**: her döküm adımında `_denetci(ADIM_…)`; bütçe dolunca `step_errors[<adım>] = neden` + `WARN` satırı (bitiş olayı `durum=kismi islenen=… toplam=… neden="<adım>: adım bütçesi (S sn) doldu"`; önek ÖL-1'in `_AdimSaati.bitti` biçimi). `static` aşaması adım hatasını kısmi sayar (çıkış 3). Decompile, otomatik analiz, functions, GDT, PDB adımlarına dokunulmadı.
- **BSim bloğu:** ingest denetçisi bütçesi `min(timeouts.ghidra_adim, bsim.ingest_butcesi_sn)` (sıfır olmayanların küçüğü; H2'de 2 sn bütçe ingest'e de uygulanır), sorgu denetçisi `timeouts.ghidra_adim`. Denetçi `BSimDatabase`'e **öznitelikle** verilir (`bsim_db.denetci = …`): yöntem imzaları değişmedi (HZ-1'in sahte köprüsü ve P16b / P16c'nin sahte `_native`'leri konum argümanlı; yeni anahtar argüman onları kırardı). Bütçe dolunca `step_errors["bsim_ingest"]` / `["bsim_query"]` (ayrı anahtar: ingest kısmıysa sorgunun kendi kısmi olayı da görünsün). Boş depoda atlanan sorgu adım hatası DEĞİL (her taze koşu çıkış 3 olurdu); `durum=atlandi neden=…` olayı üretilir. `saat.bitti(ADIM_BSIM_INGEST)` / `saat.bitti(ADIM_BSIM_QUERY)` kuyruk satırları değişmedi (HZ-1 mutantı).

### `karadul/ghidra/bsim.py`

- `STATUS_ATLANDI = "atlandi"`, `STATUS_KISMI = "kismi"`, `BOS_DEPO_NEDENI`.
- **`BSimDatabase.bos_depo_durumu(program, db)`** (hüküm 7): köken kaydı (`_ProvenanceStore.load`) okunur, programın kimliği `_Exclusion.classify` ile dışarıda tutulur (md5 = kendisi, sha256 = aynı dosya, derleme kimliği = aynı yapı); kalan kayıt yoksa `bos: true`. Atlanmaz (neden yazılır): kayıt bozuk / okunamıyor (`load_error`), karantinada yedeği var (`*.provenance.json.bozuk-*`), kayıt yokken depo dosyası var (`<db>.mv.db` ya da lite dizini). Karar `ingest_program` içinde, depo kilidi alındıktan sonra ve ingest'ten ÖNCE verilir (eşzamanlı bir koşunun kaydı yarıda okunmasın); ingest'siz sorguda (CLI) sorgu anında. Ayar `bsim.bos_depoda_sorgu_atla` (`getattr`; kapalıysa hiç okunmaz).
- **`query_all_functions`**: ayar açık + depo boş → sorgu çağrılmaz; `_atlanan_sorgu` aynı şemada sonuç: `total_matches 0`, `matches []`, **`total_queries 0`** (atlanan sorgu "sorgulandı" sayılmaz), `bsim_status atlandi` (ingest kısmıysa `kismi` kalır), `bsim_detail.sorgu_atlandi true`, `bsim_detail.neden`. Depo dolu → bugünkü yol, durum alanlarına yeni anahtar eklenmez (S8'in 7 ikilisinde ham eşitlik için). Karar verilemediyse sorgu koşar, `bsim_detail.bos_depo_denetimi` = neden. Depo kilidi alınamadıysa (`skipped_busy`) ya da liste düştüyse (`failed`) atlama yolu devreye girmez.
- **Ingest bütçesi** (hüküm 6; tarama döngüsü yeniden yazılmadı): `_BSimNativeWrapper.ingest_program`'da `_iter_real_functions` listesi bir kez alınır, döngünün başına denetim + sayaç; dolunca tarama durur, **taranan kısım eklenir** (`InsertRequest`; gelecek koşuların sorgusu için, "kapsam küçültülmez"), `last_ingest_kismi = {islenen, toplam}`. `BSimDatabase` durumu `kismi`, `neden "ingest: adım bütçesi (S sn) doldu"`, `ingest_islenen`, `ingest_toplam`. Lite ingest'te aynı denetim (toplam bilinmiyor). `InsertRequest.execute` tek Java çağrısıdır, bütçeye dahil değildir ve kesilmez.
- **Sorgu bütçesi** (hüküm 5): fonksiyon başına yolda (native tekli, lite) parça sınırında; dolunca eldeki eşleşmelerle `kismi`, `total_queries` = sorgulanan, `sorgu_islenen` / `sorgu_toplam`. Toplu yolda (`query_functions`) tarama döngüsü Python'da fonksiyon başına ilerliyor: orada denetim; ayrıca **`QueryNearest.execute`'tan hemen önce** kalan bütçe denetlenir. Dolduysa çağrı yapılmaz (`last_query_kismi`, eşleşme 0, `neden` "…; toplu sorgu çağrılmadı (t / N fonksiyon tarandı)"). **`QueryNearest.execute` tek bir Java çağrısıdır ve kendisi kesilemez** (bölünmesi HZ-2'nin alanı): bütçe çağrı başlamadan önce yetiyorsa çağrı bitene kadar sürer.
- Dokunulmayan: `_Exclusion`, `_matches_from_notes`, `_bsim_shadow.py`, `bsim_match.py`, eşleşme / dışlama mantığı.

## Kalem 3 — testler (`0fff66d`)

- `tests/test_ol2_adim_butcesi.py` (39): denetçi birimi (sınırda eşit dolmaz, bütçe 0, toplam yok, olay aralığı ve gerçek sayaç, aralık 0, dolunca olay yok, en küçük bütçe), `_AdimSaati.denetci` (başlamamış adım reddi, kısmi olay sayaçları, dolmayan denetçi alan eklemez); yedi döküm işlevi sahte programla: denetçisiz ve bütçesiz çıktı **bayt eşit**, bütçe dolunca birim sınırında kısmi ve geçerli JSON (fonksiyon döngülerinde toplam, öbürlerinde yok), birim sayılarının tutarlılığı, xref'in iki bölümü, P-code komut adımı, döngü içi olay; köprü (HZ-1'in sahte köprüsü): bütçe / aralık / toplam ayardan ve functions adımından, bütçe dolunca adım hatası + kısmi olay + kısmi JSON + `WARN` satırı, altı döküm adımının bağlı olduğu, BSim ingest / sorgu denetçilerinin bütçesi (900 / 3 600; 2 sn'de ikisi de 2), ingest dolunca `bsim_ingest` hatası ve kısmi olay, boş depoda `atlandi` olayı ve adım hatası olmadığı, öntanım bütçede hiçbir çıktıya alan eklenmediği.
- `tests/test_ol2_bsim_kosul.py` (24; P16c'nin sahte BSim dünyası): boş depo kararı (taze, aynı ikili ikinci kez, aynı yapının kopyası, başka program, bozuk kayıt dosyaya dokunmadan, karantina, kayıtsız depo dosyası); sorgu atlama (çağrı yok, aynı anahtar sırası, `total_queries 0`), ayar kapalı, dolu depoda durum alanları ayar kapalıyla aynı, okunamayan kayıtta sorgu + neden, kararın ingest'ten önce verildiği (ingest sırasında başka program kaydı düşse de), ingest'siz sorgu, meşgul depo; gerçek `_BSimNativeWrapper.ingest_program` tarama döngüsünde bütçe (taranan kısım eklenir), bütçesiz hepsi; `BSimDatabase` ingest kısmi durumu + boş depoda iki neden birlikte; tekli sorgu parça sınırında kesilir / bütçe dolmazsa alan yok; toplu sorgu taramada ya da çağrı öncesi dolarsa `QueryNearest` kurulmaz; bütçe içinde eski yolla aynı eşleşmeler; toplu kısmi tekli yola düşmez; ingest döngüsünde `suruyor` olayı.
- 63 / 63 geçti; ilgili eski testler (hz1, ol1, p16b, p16c, bsim, p16e, p16c analiz, p13a, p16a) 225 / 225.

## Kalem 4 — mutasyon

- `scripts/measurement/mutation_specs_ol2.json`: **33 mutant, 33 öldü**, hata 0 (üretici `~/karadul_olcum/runs/dalga1-2026-11-23/OL2/betik/spec_uret.py`: her `find` tekil, `replace` farklı uzunlukta). Günlük `…/OL2/mutasyon/ol2.log`.
- **Sekiz eski tanım** (`headless.py` / `bsim.py`'de `find` tutan) değişiklikten sonra yeniden koşuldu, tanımlara dokunulmadı: hz1 13 / 13, ol1 29 / 29, p13a 22 / 22, p16a 33 / 33, p16c 16 / 16, p16d 11 / 11, p16e 13 / 13, p16b 24 / 24 öldü (**161 / 161**); hata 0; **bayatlayan `find` yok**; `git diff` temiz. Günlükler `…/OL2/mutasyon/{hz1,ol1,p13a,p16a,p16c,p16d,p16e,p16b}.log`, özet `eski_ozet.txt`. Not (bu paketten önce de böyleydi): p16b'nin `p16b_mesgul_lite` (`if _is_busy_error(exc):`) ve `p16b_yuva_eki_yok` (`query.max = …`) `find` metinleri `bsim.py`'de iki kez geçiyor ve tanımda `occurrence` yok (ilk eşleşme mutasyona uğrar); taban `0b4d948`'de de iki kez geçiyordu, bu paket sayıyı değiştirmedi.

## Kalem 5 ek — `test_p16b_bsim.py` yaması (`84d222b`)

Yamalı öntanımda (`bos_depoda_sorgu_atla: True`) iki P16b testi boş depoda aynı programı ingest edip sorgunun koştuğunu bekliyor: `TestGhidra01Kilit::test_oturum_kilidi_ingestten_sorgu_sonuna_kadar` (`total_queries == 2` → 0) ve `TestGhidra02Kimlik::test_ingest_kaynak_kaydi_yazar` (`excluded.self >= 2` → 0). İkisi de ÖL-2'nin bilerek değiştirdiği davranış (boş depoda sorgu kendi kendine eşleşirdi). Dosya listemde değil → yama `docs/arge/2026-11-23_dalga1/yamalar/OL2__test_p16b_bsim.py.patch`: dosyanın `_cfg` yardımcısında `cfg.bsim.bos_depoda_sorgu_atla = False` (dosya sorgunun kendisini sınıyor). Denetim worktree DIŞINDA bir kopyada (`…/OL2/yamali_kopya/`, `patch -p1`; ağaca uygulanmadı): yalnız config yamasıyla BSim / bütçe alanlarına dokunan 13 test dosyasında 426 testten 2 kırmızı (bu ikisi), iki yamayla `test_p16b_bsim` + `test_bsim` + `test_p16c_bsim_toplu` + `test_ol2_bsim_kosul` 89 / 89. **Ana oturum config yamasını uygularken bu yamayı da uygulamalı.**

## Kalem 7 — sqlite3 (H2)

- Koşu 20:07:05–20:08:01 (kuyruk `OL2 H2:debian/sqlite3`, yuva 2; 1 dk yük 23,65 → 20,63; **yük altında**). `python -m karadul analyze <S8 raw kopyası> --stage static --config ol2_h2.yaml` (`timeouts.ghidra_adim: 2`, `bos_depoda_sorgu_atla: true`, `ingest_butcesi_sn: 900` → ingest bütçesi 2), taze `KARADUL_CACHE_DIR`, ürün ağacı `urun-d83f100`. Ölçüm `betik/h2_olc.py` → `ozet/h2_sqlite3.json`.
- **Çıkış kodu 3** ("analiz kısmi tamamlandı … static: Ghidra adımı başarısız (bsim_ingest): adım bütçesi (2 sn) doldu").

| Adım (HZ-1 saati, sn) | sqlite3, bütçe 2 sn | ≤ 7 sn? | Not |
|---|---|---|---|
| ghidra.strings | 0,140 | evet | bütçe dolmadı |
| ghidra.call_graph | 1,102 | evet | bütçe dolmadı |
| ghidra.types | 0,023 | evet | |
| ghidra.xref | 1,347 | evet | bütçe dolmadı |
| ghidra.pcode | 0,032 | evet | JSONL yolu (Ghidra döngüsü yok) |
| ghidra.cfg | 0,992 | evet | |
| ghidra.function_id | 0,009 | evet | |
| **ghidra.bsim.ingest** | **2,069** | evet | **kesildi**: 253 / 429 fonksiyon tarandı ve eklendi; `bsim_status: kismi` |
| ghidra.bsim.query | 0,241 | evet | taze depo: sorgu atlandı (`sorgu_atlandi: true`) |
| (sınırsız olmayanlar) jvm 4,512 · içe aktarma 5,418 · otomatik analiz 19,147 · functions 0,081 · decompile 11,654 · combined 0,009 · kapatma 0,037 | | | |

- Kesilen adımın çıktısı geçerli JSON: `bsim_matches.json` `json.loads` ile okunuyor; `bsim_status: "kismi"`, `bsim_detail.neden` "ingest: adım bütçesi (2 sn) doldu; depoda başka program yok; sorgu kendi kendine eşleşirdi ve dışlanırdı", `ingest_islenen 253`, `ingest_toplam 429`, `ingested_functions 253`. BSim'in kısmi işareti ön kayıttaki `kismi: true` değil `bsim_status: kismi` (BSim şemasında durum alanı; tasarım).
- Olaylar: `ghidra.bsim.ingest durum=kismi islenen=253 toplam=429 gecen_sn=2.069 neden="bsim_ingest: adım bütçesi (2 sn) doldu"`, `ghidra.bsim.query durum=atlandi neden=…`.
- Karşılaştırma için (salt okunur, aynı ikili, bütçesiz): P16e `s8_sonra_3` sqlite3'te ingest 11,788 sn, sorgu 11,775 sn.
- **Hüküm H2: TUTTU** (her sınırsız adım ≤ 7 sn: en uzun 2,069 sn; bütçesi dolan adımın çıktısı geçerli JSON ve kısmi işaretli; çıkış 3). **Sınır:** sqlite3'te döküm adımları zaten 2 sn'nin altında; bu koşuda bütçesi gerçekten dolan tek adım BSim ingest. Döküm işlevlerinin kesilme yolu gerçek Ghidra'da bu koşuyla SINANMADI (birim testlerinde sınandı); ön kayıt dışı ek koşu aşağıda (koşulursa).

## Kalem 5 — `config.py` yaması (`0fff66d`)

`docs/arge/2026-11-23_dalga1/yamalar/OL2__config.py.patch` (`betik/yama_uret.py`, `difflib`; dosyaya dokunulmadı): `timeouts.ghidra_adim` 0 → **3600** (`# okuyan: ghidra/headless.py _analyze_pyghidra (ÖL-2)`), `bsim.bos_depoda_sorgu_atla` False → **True** (`# okuyan: ghidra/bsim.py BSimDatabase (ÖL-2)`), `bsim.ingest_butcesi_sn` 0 → **900** (`# okuyan: ghidra/headless.py _analyze_pyghidra (ÖL-2)`); `INERT_SETTINGS`'ten `# ÖL-2 (Dalga 2)` grubu (başlık + üç satır) silinir. `git apply --check` temiz (A-34: uygulanmadı).
