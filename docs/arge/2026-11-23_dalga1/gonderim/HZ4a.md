# HZ4a — HZ-4a: döküm adımlarında tek başvuru geçişi ve yineleyiciler (çıktıyı değiştirmez)

Önce oku (sırayla, baştan sona): `docs/arge/2026-11-23_dalga1/ORTAK_D1.md` (§5 ve §6 dahil), `docs/arge/2026-11-20_dalga0/ORTAK_D0.md`, `docs/arge/2026-11-18_onarim/ONARIM_BRIF.md`, `docs/arge/2026-11-19_mythos/KARARLAR.md` (A-7, A-8, A-9, A-18, A-19, A-34, A-35, A-38), `docs/arge/2026-11-19_mythos/hiz/PLAN.md` "HZ-4a" (adımlar 1–7, kabul, ön kayıt: aşağıdaki hükümlerle uygula) ve "HZ-4b" (koşullu devam; yalnız bağlam), `docs/arge/2026-11-19_mythos/olcek/PLAN.md` "ÖL-3" (senden sonraki paket: akış biçimli yazım; alanına girme), `docs/arge/2026-11-19_mythos/olcek/OL2.md` (aynı döküm işlevlerine dün giren paket: bütçe denetçisi, `suruyor` olayları, kısmi çıktı sözleşmesi), `docs/arge/2026-11-19_mythos/hiz/P16e.md` (liste sıraları), `docs/arge/2026-11-19_mythos/hiz/HZ1.md` (adım saati), `docs/arge/2026-11-19_mythos/hiz/BULGULAR.md`'nin döküm adımları bölümü.

## Neden

Ollama diliminde (13 160 fonksiyon; yük altında, ÖL-2'nin T25 ölçümü) köprünün döküm adımları: CFG 267 sn, xref 133 sn, çağrı grafiği 26 sn — toplam 426 sn; gösteri koşusunda xref 349 sn, CFG 601 sn'ydi. Üç adım aynı başvuru verisini üç kez, gövdedeki her adres için ayrı Python ↔ Java çağrısıyla geziyor. Büyük ikili hedefinde (A-8) bu süre fonksiyon sayısıyla büyür. Bu paket çıktıyı değiştirmeden geçiş sayısını indirir. `headless.py` zincirinin kritik yolundaki halka; HZ-2 (yalnız `bsim.py`) ile aynı anda yazılabilir.

Bu paket ağır mühendislik işidir (Ghidra API'si, belirlenimcilik, dün eklenen bütçe sözleşmesiyle birlikte yaşama): ölç, sonra yaz.

## Ana oturumun hükümleri (plan metninin önüne geçer)

1. **Çıktı bayt bayt aynı kalır.** `ghidra_call_graph.json`, `ghidra_xrefs.json`, `ghidra_cfg.json` (ve `static/` kopyaları) önce ↔ sonra JSON-eşit; alan sıraları, tekilleştirme kuralları ve liste sıraları (P16e) aynı. `decompiled/*.c` başlıklarındaki `// Callers:` satırları dahil.
2. **Önce ölç (plan ÖL-3 adım 1'in profil kısmı sende):** kod yazmadan önce tek bir T25 koşusunda (Ollama dilimi, `--stage static`) üç adımın içini say: Python tarafındaki Java çağrısı sayısı (adım başına sayaç), "bütün simgeler" döngüsünün payı, başvurusu olan adres sayısı ↔ gövdedeki adres sayısı. Baskın neden çağrı sayısı değilse (Java işinin kendisi ya da GC) bunu yaz ve beklentiyi ona göre KURMA: ön kayıt sayıları aşağıda sabit, tutmazsa tutmadı yazılır. Profil ölçümü ürün kodunu değiştirmeden, ayrı bir araştırma betiğiyle (`scripts/arge/hiz/hz4a_profil.py`) ya da geçici sayaçla yapılır; geçici sayaç commit'lenmez.
3. **ÖL-2'nin sözleşmesi korunur.** Her döküm döngüsündeki bütçe denetimi (denetçi nesnesi), `suruyor` olayları (gerçek sayaçla) ve kısmi çıktı alanları (`kismi`, `islenen`, `toplam`, `neden`) yeni döngülerde de çalışır. Denetim fonksiyon sınırında kalır; tek yineleyiciyle gezilen simge sayımında bugünkü gibi 1 024 birimde bir. `tests/test_ol2_adim_butcesi.py` yeşil kalmalı; `mutation_specs_ol2.json`'da senin değiştirdiğin satırlara bakan tanımları yeni yerine taşı (yalnız `find` / `replace` metni) ve öldüklerini göster.
4. **API ezbere yazılmaz.** `ReferenceManager.getReferenceSourceIterator`, `hasReferencesTo`, `Listing.getInstructions(AddressSetView, boolean)` ve kullandığın her imzayı yereldeki Ghidra 12.1.2'den (`$HOME/Library/BlackWidowBuild/ghidra_12.1.2_PUBLIC`; `javap`) doğrula; doğruladığın imzayı ve yineleyicinin sıra güvencesini (artan adres mi) ilerleme dosyana yaz. Sıra güvencesi belgelenmemişse sırayı kendin kur ve bunu test et.
5. **Yedek yol ve bayrak:** `analysis.dokum_tek_gecis` (alan var mı `grep` ile bak; yoksa yamayla eklenir, öntanım açık, kapalı = bugünkü döngüler). Bayrak kapalıyken bugünkü kod yolu aynen çalışır (silinmez; eşitlik testinin karşılaştırma kolu odur). `config.py`'ye yazmazsın: yama `docs/arge/2026-11-23_dalga1/yamalar/HZ4a__config.py.patch`, ağacına uygulama; ürün koşularında değeri `--config` YAML'ıyla ver.
6. **PK-8 alanı (`address_taken_by`) bu pakette eklenmez;** ama tek geçişte "giriş adresine çağrı olmayan başvurular" listesini PK-8'in ek maliyetsiz kullanabileceği biçimde bırak (iç tablo; JSON'a yazılmaz) ve `HZ4a.md`'de nasıl kullanılacağını yaz.
7. **A-38'e hazırlık (yalnız not):** dizgi başvurularının komut içindeki sırası ÖL-3'te döküme yazılacak. Senin başvuru tablon bu sırayı zaten görüyorsa hangi alandan okunacağını `HZ4a.md`'ye yaz; `_extract_strings`'e ve şemaya dokunma.
8. **HZ-4b'nin koşulu için sayı bırak:** paketten sonra T25'te çağrı grafiği + xref + CFG'nin köprü süresi içindeki payı (%). Karar ana oturumda.
9. **Süre ölçümü gündüz, yük altında:** "yük altında" etiketli, `uptime` künyeli; aynı koşulda art arda önce (bayrak kapalı) / sonra (bayrak açık) koşularıyla. Kesin oran boş makine ölçümünde (HZ-9). Eşitlik hükmü yükten bağımsızdır ve asıl kabuldür.

## Yazabileceğin dosyalar

`karadul/ghidra/headless.py` — YALNIZ `_extract_call_graph`, `_extract_xrefs`, `_extract_cfg` ve bunların yeni özel yardımcıları (ortak başvuru tablosu) + `_analyze_pyghidra`'da bu üç çağrının çevresi. Yeni `tests/test_hz4_dokum.py`, `scripts/measurement/mutation_specs_hz4.json` (≥ 8 mutant); `scripts/measurement/mutation_specs_ol2.json` ve `mutation_specs_p16e.json` (yalnız senin değiştirdiğin satırlara bakan tanımların `find` / `replace` metni); `scripts/arge/hiz/hz4a_profil.py`; `docs/arge/2026-11-19_mythos/hiz/on_kayit_hz4a.md`, `docs/arge/2026-11-19_mythos/hiz/HZ4a.md` (ilerleme dosyası); yama.

**Dokunma:** `karadul/ghidra/bsim.py` (aynı anda HZ2'de), `_extract_strings`, `_extract_types`, `_extract_pcode*`, `_extract_function_id_matches`, decompile işlevleri (`_decompile_*`, `_extract_disassembly`, `_extract_func_xrefs`: HZ-3'ün), `_save_output` ve yazım (ÖL-3'ün), `_run_auto_analysis` ve bekçi, `karadul/analyzers/macho.py`, `karadul/ghidra/scripts/*`, `karadul/config.py`, `karadul/stages.py`, `karadul/pipeline/steps/`.

`headless.py`'ye bakan öbür tanımlar: `mutation_specs_{hz1,ol1,p13a,p16a,p16c,p16d,p16e,ol2}.json`. Değişikliğinden sonra sekizini yeniden koş.

## Ön kayıt (`on_kayit_hz4a.md`; profil ölçümünden SONRA ama kod ve "sonra" ölçümünden ÖNCE ayrı commit; sayılar ana oturumun)

> H0 (profil; yön bildirilmez): üç adımda baskın maliyet (≥ %50 pay) Python ↔ Java çağrı sayısı mı, Java işinin kendisi mi, GC mi — ilk ölçüm. Başvurusu olan adres sayısı / gövdedeki adres sayısı oranı — ilk ölçüm.
> H1 (eşitlik, S8, tek kök, ORTAK_D0 §6 sırası, bayrak açık): taban `~/karadul_olcum/runs/dalga1-2026-11-23/ANA/s8_taban_534e252b`. `ghidra_output/*.json`, `static/ghidra_*.json`, `decompiled/*.c` ve `out/naming_map.json` ham eşit 8 / 8.
> H2 (eşitlik, T25): Ollama diliminde `ghidra_call_graph.json`, `ghidra_xrefs.json`, `ghidra_cfg.json` bayrak kapalı ↔ açık JSON-eşit (aynı ağaç, art arda iki koşu).
> H3 (süre, T25, yük altında, art arda): çağrı grafiği + xref + CFG toplamı, açık / kapalı oranı ≤ 0,5.
> H4 (süre, S8): aynı üç adımın toplamı, 8 ikilinin ortancasında açık / taban oranı ≤ 0,8 (taban koşusu başka yük koşulunda alındıysa "karşılaştırılamaz" yaz, hüküm verme).
> H5 (bütçe): sqlite3'te `timeouts.ghidra_adim: 1` ile xref ya da CFG kesildiğinde çıktı geçerli JSON, `kismi: true`, `islenen` ≤ `toplam`; kesilmeyen alanlar tam çıktıyla aynı.
> H6 (olay): T25'te üç adımın içinde en uzun `ILERLEME` sessizliği ≤ 60 sn (ÖL-2'de sağlanıyordu; geriye gitme yok).

Bilinen kendiliğinden fark: zstd `FUN_001063c0`'da decompiler 6 koşunun 1'inde iki geçici değişkeni yer değiştiriyor (P16e). Bir `.c` farkı görürsen o ikiliyi bir kez daha koş.

## Ölçüm

Kendi dalının ürün ağacı (ORTAK_D0 §3). Her Ghidra koşusu kuyrukla (`~/karadul_olcum/ghidra_kuyruk.sh HZ4a <etiket> …`), ikili başına ayrı çağrı, `timeout`'lu, arka planda. T25 koşuları `--stage static` (≈ 25–30 dk, yük altında); en çok üç T25 koşusu (profil, kapalı, açık) — profil koşusu "kapalı" kolun yerine sayılabiliyorsa iki. Sıra: profil (H0) → kod + testler + mutasyon → sqlite3 (H5) → S8 (H1, H4) → T25 (H2, H3, H6). Koşu kökü `~/karadul_olcum/runs/dalga1-2026-11-23/HZ4a/`; özetler `ozet/` altında.

## Sert son

Gönderim iletisinde yazılı. Öncelik: profil → kod + testler + mutasyon → H5 → H1 → H2 / H3 / H6 → tam takım. O saatte koşulamayan ölçümü "kalan" diye yaz.

## Dönüş mesajı

İlk satır gerçek uygulama sayısı: T25'te çağrı grafiği / xref / CFG süreleri kapalı → açık (sn), toplam oran, JSON eşitliği x / 3. Sonra H0–H6, profilin hükmü (baskın neden), doğrulanan API imzaları ve sıra güvencesi, S8 x / 8, HZ-4b koşulu için pay (%), test / mutant sayıları, taşınan tanımlar, commit listesi, yama, ÖL-3 / HZ-3 / PK-8 için notlar, koşu kökünün yolu ve boyutu.
