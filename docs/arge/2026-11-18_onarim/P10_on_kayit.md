# P10 — ön kayıt (mühendislik yapı kurtarması ve MaxSMT yolu)

Bu belge kod değişmeden ÖNCE yazıldı ve commit'lendi. Taban sayıları yeniden oynatma betiğinin değişmemiş kodla (40f0f20; kodun dondurulmuş kopyası `~/karadul_olcum/runs/onarim-2026-11-18/P10/taban_agac/` ölçülen ağaç olarak kullanılır) ürettiği değerlerdir ve `P10.md`'ye yazılır; "sonra" sayıları her kalemden sonra aynı betikle, aynı girdilerle alınır. Bir beklenti tutmazsa "tutmadı" yazılır, eşik sonradan gevşetilmez.

## 1. Araç ve girdiler
- Betik: `~/karadul_olcum/runs/onarim-2026-11-18/P10/p10_olc.py kos` (paket dosya listesinde `scripts/` yeri olmadığı için ölçüm kökünde; ana oturum depoya taşıyabilir). Kayıtlı ürün koşusunun `reconstructed/typed/` dizinini (yapı kurtarma adımının girdisi `final_decompiled_dir`) ölçülen ağacın `StructRecoveryEngine.recover`'ına verir; `--blok` ile `stages.py`'deki ikinci çağrıyı (girdi = çıktı = `struct_recovered`, BORU-01) da oynatır; ardından Faz 3'ün ilk adımı `InlineDetectionStep`'i ölçülen ağacın koduyla oynatır (önbellek = `typed/` içeriği, üründeki gibi). Ghidra koşmaz. JSON yolları `ghidra_metadata._resolve_json_paths` kuralıyla.
- **Yeniden oynatma doğrulaması (koşul):** taban koduyla oynatılan `struct_recovered/` (C dosyaları + `originals/` + `types.h`) kayıtlıyla bayt bayt aynı, `struct_recovery.json` yol dizgileri dışında aynı ve `inline_patterns_detected` kayıtlı `pipeline_result.json` değeriyle aynı olmalı.
- **G seti:** `~/karadul_olcum/runs/genel-tarama-2026-11-18` (14 ikili; e9d2d08 = 1.23.1 çıktısı; bu paketin dosyaları o günden beri değişmedi).
- **D seti:** `~/karadul_olcum/runs/urun-yeni2-f30ac9a` (119 ikili; 1.22.1 çıktısı; `git log f30ac9a..HEAD` bu paketin dört dosyasında ve `inline_detector.py`'de değişiklik göstermiyor).
- Uçtan uca denetim (Ghidra'lı, en çok 3 ikili, `--paralel 1`): `urun_kos.py --yalniz …` ile; `out/` ağacı tabanla karşılaştırılır.

## 2. Ölçüler (ikili başına; toplamlar `ozet.json`'da)
- `rapor_rewritten_files` (`struct_recovery.json`), `c_cikti_ust` (çıktı dizininin üst düzey `.c` sayısı), yeni alan `rapor_output_files`.
- `ghidra_alan` / `ghidra_alan_ad_ezilen`: Ghidra (`ghidra_types.json`) kökenli yapıların alanları ve `semantic_name != raw_name` olanlar.
- `rapor_total_structs` (= `stats.structs_enriched`), yeni alanlar `rapor_candidate_structs`, `rapor_reference_structs`, `rapor_proposed_rewrites`.
- `aday_ortusen` (alanları üst üste binen aday), `aday_tek_kaynak` (kaynağı tek fonksiyon + tek değişken).
- `kaynak_agac_girdiyle_ayni`: Faz 3'e giden ağacın `.c` dosyaları (INLINE satırları ayıklanınca) girdiyle aynı.
- `originals_kaynak_icinde` / `originals_kaynak_disinda`.
- `inline_patterns_detected` (adımın sayacı) ve `inline_yorum_kaynak_agac` (Faz 3 ağacının üst düzey `.c` dosyalarındaki `/* INLINE:` sayısı).
- `blok_basari`: `--blok` ikinci çağrısının başarısı.

## 3. Beklentiler (kalem başına)
**Kalem 1 — BORU-04 (MaxSMT adayları adım tarafından).**
- Bayrak kapalıyken (öntanım) G ve D'de bütün ölçüler bu kalemden önceki değerle aynı.
- Bayrak açıkken: `struct_recovery` adımı `computation_struct_recovery`'nin `recovered_struct_candidates` / `computation_struct_result` yapıtlarını okur ve motora `computation_structs` olarak verir (anahtarlar motorun okuduğu biçimde: `total_size`, alan `type`, `source_functions` = adayın fonksiyonu). Birim testi: aday `struct_recovery.json`'da görünür; çözücü adım düzeyinde fonksiyon başına bir kez çağrılır. Gerçek çıktıda ölçülmez (bayrak kapalı; TIP-03 nedeniyle adayların ofsetleri bugün anlamsız, P11).
- Tutmadı: bayrak kapalıyken herhangi bir ölçü değişirse.

**Kalem 2 — BORU-02 (yedek kaynak ağacın dışında; `inline_detection` yalnız kaynak).**
- `originals_kaynak_icinde` = 0 (G ve D; tabanda = `.c` sayısı).
- `inline_patterns_detected` = `inline_yorum_kaynak_agac` (her ikili; tabanda 2 katı).
- `inline_yorum_kaynak_agac` tabanla aynı (Faz 3 ağacının içeriği değişmez).
- Motor girdi = çıktı dizini çağrısını reddeder (`--blok` ikinci çağrısı `blok_basari = False`, hata metniyle); ilk çağrının raporu ezilmez.
- Tutmadı: yukarıdakilerden biri sağlanmazsa.

**Kalem 3 — TIP-04 (Ghidra adları korunur; taban koddan; bağlanmayan sayılmaz; K-1 bekletme).**
- `ghidra_alan_ad_ezilen` = 0 (tabanda = `ghidra_alan`).
- Ghidra yapıları `reference_structs` olarak ayrı; `total_structs` (= `structs_enriched`) yalnız koda bağlanan yapı sayısı. K-1 sürdükçe koda yazım yapılmadığı için 0 (tabanda G 712 — hepsi Ghidra yapısı).
- Koddan çıkarma her ikilide çalışır: aday yapılar `rapor_candidate_structs` ve aday dosyasında (`struct_candidates.txt`, kaynak ağacın dışında). Sayı için önceden beklenti yok (tabanda bu yol hiç çalışmadı); sayı yazılır.
- `kaynak_agac_girdiyle_ayni` = `.c` sayısı (K-1: Faz 3'e giden ağaçta yapı kurtarma kaynaklı değişiklik yok).
- `struct_recovered/types.h`'de Karadul'un kurduğu (koddan / hesaplamadan) yapı tanımı 0; `out/` ağacı (uçtan uca denetim) tabanla aynı.
- Tutmadı: Ghidra alan adı ezilirse, Faz 3 ağacına tek bir yapı kurtarma değişikliği girerse, ya da bağlanmayan yapı `total_structs`'a sayılırsa.

**Kalem 4 — TIP-05 (anahtar (fonksiyon, değişken); fonksiyon kapsamı; tip uyumu).**
- `aday_ortusen` = 0; `aday_tek_kaynak` = `rapor_candidate_structs` (her aday tek (fonksiyon, değişken)'den).
- Önerilen yeniden yazım (`rapor_proposed_rewrites`) yalnız adayın kendi fonksiyonunda ve erişimin tipi alanın tipiyle aynı genişlikte olduğunda; biçim `((S *)taban)->alan /* was: … */` (taban değişkenin bildirimi değişmez; tanım dolgulu, ofsetler kesin). Gerçek çıktıda en az 20 öneri elle okunur (ofset, tip, fonksiyon).
- Birim testleri: iki fonksiyonda farklı ofsetlerle erişilen iki `param_1` iki ayrı aday; A'nın yapısı B'nin kodunda öneri üretmez; ölçek (`int *p; *(int *)(p + 2)` → bayt 8; bildirimi bilinmeyen taban kanıt sayılmaz); genişliği tutmayan erişim yeniden yazılmaz.
- Tutmadı: örtüşen aday > 0, iki fonksiyondan kurulmuş aday > 0, ya da okunan öneriler içinde ofseti / tipi yanlış olan bulunursa (sayısı yazılır).

## 4. Kapsam dışı (bilerek)
- `stages.py` 4867-5140 bloğunun silinmesi (BORU-01; P-S2). Bu paket yalnız MaxSMT yolunu adım tarafına taşır ve bloğun ne kopardığını `P10.md`'ye yazar.
- MaxSMT çıkarıcısının ofset kök nedeni (TIP-03: LOAD/STORE `input0` = adres alanı kimliği 433; P11).
- `inline_detection`'ın yapı kurtarma öncesi önbellekten okuması ve `semantic_naming` ile aynı düzeyde koşması (BORU-11; P14).
- Bekletmenin kaldırılması (koda yazım): masum ikili kapısı ve yapı yerleşiminin DWARF'la ölçümü sonrası, ana oturumun kararı.
