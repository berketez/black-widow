# HZ2 — HZ-2: BSim hızlı yol (paralel tarama; çıktıyı değiştirmez)

Önce oku (sırayla, baştan sona): `docs/arge/2026-11-23_dalga1/ORTAK_D1.md` (§5 ve §6 dahil), `docs/arge/2026-11-20_dalga0/ORTAK_D0.md`, `docs/arge/2026-11-18_onarim/ONARIM_BRIF.md`, `docs/arge/2026-11-19_mythos/KARARLAR.md` (A-7, A-8, A-9, A-18, A-19, A-34, A-35), `docs/arge/2026-11-19_mythos/hiz/PLAN.md` "HZ-2" (adımlar 1–6, kabul, ön kayıt: aşağıdaki hükümlerle uygula; satır numaraları eski, işlevleri `grep -n "def <ad>"` ile bul), `docs/arge/2026-11-19_mythos/olcek/OL2.md` (senden hemen önce aynı iki işleve giren paket; özellikle "HZ-2 için notlar"), `docs/arge/2026-11-23_dalga1/gonderim/OL2.md` (ÖL-2'nin sözleşmesi), `docs/arge/2026-11-19_mythos/hiz/HZ1.md`.

## Neden

ÖL-2'den sonra Ollama diliminde (13 160 fonksiyon) köprünün en uzun adımı BSim ingest: 576 sn (otomatik analiz 107, decompile 449, CFG 267, xref 133; hepsi yük altında). Ingest her fonksiyonu tek iş parçacığında tek tek tarıyor (`gen.scanFunction`, her biri bir decompile); sorgu aynı işi bir kez daha yapıyor. Ghidra'nın `GenSignatures.scanFunctions` yolu aynı taramayı paralel decompile kuyruğuyla yapar. Bu paket çıktıyı değiştirmeden o yola geçer. `headless.py` zincirinin ÖL-2'den sonraki halkası; dokunduğu dosya yalnız `bsim.py`.

## Ana oturumun hükümleri (plan metninin önüne geçer)

1. **Çıktı aynı kalır.** `bsim_matches.json` ve `bsim_shadow.json`, zaman alanları ve yeni `scan_mode` alanı dışında bayt eşit; `out/naming_map.json` eşit. Taranan fonksiyon kümesi ve sırası `_iter_real_functions` ile aynı.
2. **ÖL-2'nin sözleşmesi korunur:** ingest bütçesi (`bsim.ingest_butcesi_sn`), adım bütçesi (`timeouts.ghidra_adim`), `last_ingest_kismi` / `kismi` durumları ve alanları, denetçinin öznitelikle iletilmesi (`denetci`), boş depoda sorgunun atlanması, `QueryNearest.execute`'tan hemen önceki bütçe denetimi. Python döngüsü kalkınca bütçe izleyiciye taşınır: kalan süreyle `TimeoutTaskMonitor`; dönüşte iptal / zaman aşımı → kısmi, `islenen` gerçekten taranan fonksiyon sayısı (uydurma değil; okunamıyorsa alan yazılmaz ve neden yazılır). İptalde yarım kalan parçanın depoda ne bıraktığını ölç ve yaz.
3. **Adım içi `suruyor` olayı sahte olmaz.** Paralel tarama Java iş parçacıklarında koşar. Gerçek bir sayaç okunabiliyorsa (izleyicinin ilerlemesi ya da tarama yöneticisindeki fonksiyon sayısı) ÖL-1'deki gibi bir okuyucu iş parçacığıyla `analysis.bekci_aralik_sn` aralığında `durum=suruyor islenen=… toplam=…` üret. Okunamıyorsa olay ÜRETME; bunu "ölçülen sınır" diye yaz (ÖL-2 bu adımda 22 sn'lik en uzun sessizlik ölçmüştü; paralel yolda bu değer büyürse açıkça raporla).
4. **Yedek yol:** paralel tarama istisna atarsa bugünkü tekli yola düş (P16c'deki toplu → tekli düşüşü gibi); `status["scan_mode"]` = `parallel` / `serial_fallback`; düşüş sessiz olmaz (günlük + durum alanı).
5. **Kısmi ingest'in kalıcılığı (ÖL-2'nin açık riski):** bugün kesilen ingest programın md5'ini depoya yazıyor; aynı ikili yeniden koşulunca kalan fonksiyonlar hiç eklenmiyor ve bu hiçbir yerde görünmüyor. En az: köken kaydına `kismi` işareti ve sonraki koşuda durum alanında "önceki ingest kısmi (t / N)" bilgisi. Tamamlama (kalanı ekleme) yolunun fizibilitesini küçük bir deneyle ölç (aynı yürütülebilir için ikinci `InsertRequest` kabul ediliyor mu); oluyorsa uygula, olmuyorsa nedenini yaz ve ÖL-9'a not bırak. Fizibilite için tek küçük Ghidra koşusu yeter.
6. **`config.py`'ye yazmazsın.** Alan var: `bsim.paralel_tarama` (INERT'te, False). Yaman `docs/arge/2026-11-23_dalga1/yamalar/HZ2__config.py.patch`: INERT satırını siler, yorumu düzeltir, öntanımı planın dediği gibi açık yapar (kapalı = bugünkü yol). Yamayı ağacına uygulama; ürün koşularında değeri `--config` YAML'ıyla ver.
7. **Mutasyon tanımları taşınır:** `mutation_specs_ol2.json`'daki `ol2_ingest_kesilmez` ve `ol2_toplu_cagri_oncesi_denetim_yok` `find` metinleri senin değiştireceğin satırlarda; yeni yerlerine taşı (yalnız bu iki tanım) ve tanımın yine öldüğünü göster. `bsim.py`'ye bakan öbür tanımlar: `mutation_specs_{p16b,p16c}.json`.
8. **Süre ölçümü gündüz, yük altında:** makinede başka ajanlar ve ana oturumun koşuları var. Süre hükmü "yük altında" etiketlidir ve aynı koşulda art arda önce / sonra ile verilir; kesin oran boş makine ölçümünde (HZ-9) yeniden alınır. Eşitlik hükmü yükten bağımsızdır ve bu paketin asıl kabulüdür.

## Yazabileceğin dosyalar

`karadul/ghidra/bsim.py`; yeni `tests/test_hz2_bsim_hizli.py`, `scripts/measurement/mutation_specs_hz2.json` (≥ 6 mutant); `scripts/measurement/mutation_specs_ol2.json` (yalnız hüküm 7'deki iki tanım); `docs/arge/2026-11-19_mythos/hiz/on_kayit_hz2.md`, `docs/arge/2026-11-19_mythos/hiz/HZ2.md` (ilerleme dosyası); yama `docs/arge/2026-11-23_dalga1/yamalar/HZ2__config.py.patch`.

**Dokunma:** `karadul/ghidra/headless.py` (ÖL-2 sonrası BSim bloğu değişmez; orada değişiklik gerekiyorsa yama), `karadul/ghidra/_bsim_shadow.py`, `karadul/pipeline/steps/bsim_match.py`, eşleşme / dışlama mantığı (`_matches_from_notes`, `_Exclusion`), `karadul/config.py`, `karadul/stages.py`.

## Ön kayıt (`on_kayit_hz2.md`; ölçümden önce ayrı commit; sayılar ana oturumun)

> H1 (eşitlik, S8, ortak depo senaryosu: tek kök, ORTAK_D0 §6 sırası, `bsim.paralel_tarama: true`): taban `~/karadul_olcum/runs/dalga1-2026-11-23/ANA/s8_taban_534e252b`. `bsim_matches.json` ve `bsim_shadow.json` zaman alanları ve `scan_mode` dışında bayt eşit 8 / 8; `decompiled/*.c`, öbür `ghidra_output/*.json` ve `out/naming_map.json` ham eşit 8 / 8.
> H2 (bayrak kapalı): `bsim.paralel_tarama: false` ile S8'in 2 ikilisinde (cat, zstd) çıktı tabanla ham eşit (zaman alanları dışında).
> H3 (süre, T25: Ollama dilimi, `--stage static`, taze depo, yük altında): ingest süresi ≤ 288 sn (ÖL-2'nin ölçümü 576,3 sn'nin yarısı); `bsim_status` ve eşleşme sayısı aynı (`atlandi`, 0); taranan fonksiyon 13 160 / 13 160.
> H4 (bütçe): sqlite3'te `bsim.ingest_butcesi_sn: 2` ile ingest ≤ 2 + 10 sn'de `kismi` biter; JSON geçerli; `islenen` ≤ `toplam`.
> H5 (olay): T25'te ingest içinde en uzun `ILERLEME` sessizliği — yön bildirilmez, ilk ölçüm (sayaç okunamıyorsa "okunamadı").
> H6 (yedek yol): birim testte paralel tarama istisna atınca tekli yol aynı eşleşme listesini verir; `scan_mode: serial_fallback`.

Bilinen kendiliğinden fark: Ghidra decompiler'ı zstd `FUN_001063c0`'da 6 koşunun 1'inde iki geçici değişkeni yer değiştiriyor (P16e). Bir `.c` farkı görürsen o ikiliyi bir kez daha koş, iki sonucu da yaz.

## Ölçüm

Kendi dalının ürün ağacı (ORTAK_D0 §3). Her Ghidra koşusu kuyrukla (`~/karadul_olcum/ghidra_kuyruk.sh HZ2 <etiket> …`), ikili başına ayrı çağrı, `timeout`'lu, arka planda. Sıra: fizibilite (hüküm 5; tek küçük koşu) → sqlite3 (H4) → S8 (H1, H2) → T25 (H3, H5). Kuyruğa kod, testler ve mutasyon bittikten sonra gir. Koşu kökü `~/karadul_olcum/runs/dalga1-2026-11-23/HZ2/`; özetler `ozet/` altında.

## Sert son

Gönderim iletisinde yazılı. Öncelik: kod + testler + mutasyon → H4 → H1 / H2 → H3 / H5 → tam takım.

## Dönüş mesajı

İlk satır gerçek uygulama sayısı: T25'te ingest kaç saniye (önce 576,3), taranan fonksiyon, `scan_mode`, ingest içi en uzun sessizlik. Sonra H1–H6, kısmi ingest fizibilitesinin hükmü, test / mutant sayıları, taşınan iki tanımın durumu, commit listesi, yama, ÖL-3 + HZ-4a ve ÖL-9 için notlar, koşu kökünün yolu ve boyutu.
