# Ön kayıt — ÖL-2 (adım bütçeleri ve BSim koşulları)

Yazıldı: 2026-11-23, ölçümden ÖNCE (bu dosyanın commit'i hiçbir OL2 Ghidra koşusundan önce; koşular `~/karadul_olcum/ghidra_kuyruk.log`'da `OL2` satırlarıyla). Kod commit'i: `d83f100` (ürün ağacı `~/karadul_olcum/urun-d83f100`). Tutmayan beklenti silinmez; eşik sonradan değişmez.

## Plan metni (gönderim metnindeki düzeltmelerle; sayılar ana oturumun, değiştirilmedi)

> "T25 BSim ≤ 930 sn, eşleşme 0 → 0; sqlite3 2 sn bütçede her adım ≤ 7 sn; alt küme çıktısı (BSim durum alanları hariç) aynı; 119 ad haritası 119 / 119 aynı."

- **H1 (T25):** BSim adımı (ingest + sorgu) ≤ 930 sn (bugünkü ürün aynı dilimde 1 781 sn); `bsim_matches.json` `total_matches` 0 → 0, `bsim_status` `atlandi` (taze depo) ve ingest bütçeyi aşarsa `kismi`.
- **H2 (sqlite3, `timeouts.ghidra_adim: 2`):** her sınırsız adım ≤ 2 + 5 sn'de biter; bütçesi dolan adımın çıktısı geçerli JSON ve `kismi: true`; koşu çıkış kodu 3.
- **H3 (S8, tek kökte, ORTAK_D0 §6 sırasıyla, yamanın öntanımları YAML'da):** taban `~/karadul_olcum/runs/dalga1-2026-11-23/P16e/s8_sonra_3`. Depo kökte biriktiği için sorgu atlama yalnız İLK ikilide (cat) beklenir: orada `bsim_matches.json` yalnız `bsim_status` / `bsim_detail` alanlarında farklı; öbür 7 ikilide BSim dosyaları dahil ham eşit. Bütün ikililerde `decompiled/*.c`, öbür `ghidra_output/*.json` ve `out/naming_map.json` ham eşit 8 / 8.
- **H4:** T25'te statik aşama boyunca en uzun `ILERLEME` sessizliği: decompile dışındaki adımlarda ≤ 60 sn (hüküm 3). Decompile içindeki sessizlik ayrıca raporlanır (HZ-3'ün işi; hüküm yok).
- **H5:** Bütçe öntanımında (3 600 sn) S8'de kesilen adım 0.
- **Kabul (d)** (119 birleşik koşusunda ad haritası aynı): bu pakette ölçülmez; kapanış ölçümüne bırakıldı.

## Ölçümden önce bilinen, tasarımdan gelen fark (H3'e ek satır; H3'ün metni değişmedi)

- Boş depoda sorgu atlanınca `bsim_matches.json`'da `total_queries` **sorgulanan fonksiyon sayısıdır, yani 0** (atlanan sorgu "sorgulandı" diye sayılmaz: yalan sayaç yasağı, ONARIM_BRIF §1). Taban cat'te bu alan sorgulanan fonksiyon sayısıydı. Bu yüzden cat'in `bsim_matches.json`'unda `bsim_status` / `bsim_detail` dışında **`total_queries` de farklı** olacak (N → 0). H3 metne göre hükme bağlanır (bu fark H3'ü cat'te "tutmadı" yapar); ayrıca "`total_queries` dışında" satırı ayrı raporlanır.
- `bsim_shadow.json` `bsim_status` / `bsim_detail`'i ham veriden kopyalar (`_bsim_shadow.build_shadow_payload`); cat'te o dosyada da aynı iki alan farklı olacak. `static/ghidra_bsim.json` (köprü çıktısının kopyası) `bsim_matches.json` ile aynı farkı taşır. Bunlar "BSim durum alanları" sayılır.
- `ghidra_status.json`'da adım süreleri değişebilir (süre; `s8_esitlik.py` kıyas dışı tutar). `step_errors` S8'de boş beklenir (H5).

## Ölçüm düzeni (ölçümden önce sabit)

- Ayar YAML'ları koşu kökünde (`~/karadul_olcum/runs/dalga1-2026-11-23/OL2/`): yamanın öntanımlarının eşdeğeri `timeouts.ghidra_adim: 3600`, `bsim.bos_depoda_sorgu_atla: true`, `bsim.ingest_butcesi_sn: 900`. sqlite3'te yalnız `timeouts.ghidra_adim: 2` farklı. T25'te ek olarak ana oturum koşusunun `analysis` bölümü (`ghidra_disabled_analyzers`: "Objective-C Message Analyzer", "Objective-C Message").
- S8: `scripts/measurement/urun_kos.py` (ikili başına bir kuyruk çağrısı; sıra cat, sort, tree, sqlite3, htop, debian tmux, zstd, mac/tmux; tek kök, koşuya özel boş `KARADUL_CACHE_DIR`); YAML ürün ağacının kökünde `karadul.yaml` (urun_kos'un `--config`'i yok). Kıyas `scripts/arge/hiz/s8_esitlik.py` (ham; `--sira-normal` yok; taban P16e sonrası olduğu için çağıran listeleri ham belirli).
- sqlite3 ve T25: `python -m karadul analyze <girdi> --stage static --skip-dynamic --config <yaml> --verbose --output-dir <kök>/ws --output <kök>/out`, taze `KARADUL_CACHE_DIR`, süre sınırı `timeout` (sqlite3 1 200 sn, T25 4 500 sn). sqlite3 girdisi `urun-onarim-a62f15e/debian/sqlite3/sqlite3` çalışma alanının `raw/` kopyası (S8 ile aynı).
- H2 ölçümü: `static/ghidra_status.json` `adim_sureleri` (HZ-1 saati) ve `step_errors`; sınırsız adımlar = `ghidra.strings`, `ghidra.call_graph`, `ghidra.types`, `ghidra.xref`, `ghidra.pcode` (koşan yolda Ghidra döngüsü varsa), `ghidra.cfg`, `ghidra.function_id`, `ghidra.bsim.ingest`, `ghidra.bsim.query`. Kısmi çıktılar `ghidra_output/*.json`'da `kismi: true` ve `json.loads` ile okunur.
- H4 ölçümü: `kosu.log`'daki `ILERLEME` satırlarının zaman damgaları (saniye çözünürlüğü); ardışık iki satır arası boşluk, boşluğun içinde koşan adıma göre "decompile" / "decompile dışı" ayrılır; ilk `ILERLEME`'den statik aşamanın son köprü olayına (`ghidra.kapatma bitti`) kadar.
- Süreler "yük altında" etiketli ve `uptime` künyeli; gündüz / akşam yüklü makinede süre hükmü yön göstericidir.
- Bilinen kendiliğinden fark: Ghidra decompiler'ı zstd `FUN_001063c0`'da 6 koşunun 1'inde iki geçici değişkeni yer değiştiriyor (P16e). `.c` farkı görülürse o ikili bir kez daha koşulur, iki sonuç da yazılır.
