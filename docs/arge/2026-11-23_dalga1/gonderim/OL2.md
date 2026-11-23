# OL2 — ÖL-2: Ghidra köprüsünde adım bütçeleri ve BSim koşulları

Önce oku (sırayla, baştan sona): `docs/arge/2026-11-23_dalga1/ORTAK_D1.md` (§5 akşam eki dahil), `docs/arge/2026-11-20_dalga0/ORTAK_D0.md`, `docs/arge/2026-11-18_onarim/ONARIM_BRIF.md`, `docs/arge/2026-11-19_mythos/KARARLAR.md` (A-7, A-8, A-9, A-18, A-19, A-34, A-35), `docs/arge/2026-11-19_mythos/olcek/PLAN.md` §1 (ilerleme olayı sözleşmesi: SABİT) ve "ÖL-2" (adımlar 1–7, kabul, ön kayıt: aşağıdaki hükümlerle uygula), `docs/arge/2026-11-19_mythos/olcek/OL1.md` (senden hemen önce aynı dosyaya giren paket; özellikle "ÖL-2 (bütçeler)" notları ve olayların nasıl üretildiği), `docs/arge/2026-11-19_mythos/hiz/HZ1.md` (adım saati), `docs/arge/2026-11-19_mythos/hiz/P16e.md` (döküm listelerinin sıra kuralı), `docs/arge/2026-11-19_mythos/hiz/PLAN.md` "HZ-2" (senden hemen SONRA aynı BSim bloğuna girecek paket), `docs/arge/2026-11-23_dalga1/DURUM.md`'nin "Ollama uçtan uca koşusu" bölümü.

## Neden

Köprünün döküm adımlarının (dizgi, çağrı grafiği, tip, xref, P-code, CFG, FunctionID) ve BSim'in süre sınırı yok: büyük ikilide tek bir adım koşuyu saatlerce tutabilir, analist "takıldı mı" bilemez. BSim bugünkü Ollama koşusunda 1 781 sn sürdü (10:02:41 → 10:32:22; 13 160 sorgu 714 sn) ve 0 eşleşme verdi: depoda başka program yokken sorgu yalnız kendi kendine eşleşir ve dışlanır. Bu paket her sınırsız adıma bütçe koyar, sonuç üretemeyecek BSim sorgusunu atlar, ingest'i bütçeler ve uzun adımların içinden gerçek sayaçla ilerleme olayı üretir. Büyük ikili hedefinin (A-8) ikinci koşulu; `headless.py` zincirinde ÖL-1'den sonraki halka.

## Ana oturumun hükümleri (plan metninin önüne geçer)

1. **`config.py`'ye yazmazsın (A-19, A-34).** Üç alan BAYRAK paketiyle var, INERT'te ve etkisiz değerde: `timeouts.ghidra_adim` (0), `bsim.bos_depoda_sorgu_atla` (False), `bsim.ingest_butcesi_sn` (0). Kodunda 0 = bütçe yok / kapalı anlamına gelir. Yaman `docs/arge/2026-11-23_dalga1/yamalar/OL2__config.py.patch`: üç INERT satırını siler, `# ETKİSİZ` yorumlarını "okuyan: …" diye düzeltir ve öntanımları planın değerlerine çeker (`ghidra_adim` 3600, `bos_depoda_sorgu_atla` True, `ingest_butcesi_sn` 900). Yamayı ağacına UYGULAMA; `git apply --check` ile denetle. Ürün koşularında bu üç değeri `--config` YAML'ıyla ver (yama uygulanmış hâlin eşdeğeri); YAML'ı koşu kökünde sakla.
2. **Zamanlayıcı ve olay yolu tek.** Adım süreleri HZ1'in `_AdimSaati`'nde, olaylar ÖL-1'in `_ilerleme` / `ilerleme_satiri` yardımcılarıyla; yeni günlükçü, yeni biçim, ikinci zamanlayıcı yok. Bütçe aşımında `durum=kismi islenen=… toplam=… neden="adım bütçesi (S sn) doldu"`.
3. **Adım içi `suruyor` olayı (ÖL-1'in bıraktığı iş).** Bütçe denetimini koyduğun her döngüde, aynı denetim noktasında, o adımın son olayından beri `analysis.bekci_aralik_sn` (öntanım 15; ayardan oku, kodda sabit sayı kalmasın) geçtiyse `durum=suruyor islenen=n toplam=N gecen_sn=…` olayı üret. Sayaçlar gerçek döngü sayaçlarıdır; toplam bilinmiyorsa `toplam` alanı yazılmaz. Zamanlayıcıyla boş olay basılmaz (sahte ilerleme yasağı). Olaylar çıktı dosyalarını değiştirmez.
4. **Kısmi çıktı da belirlenimci.** Bütçe dolunca yazılan JSON geçerlidir, P16e'nin sıra kuralını korur (listeler aynı anahtarla sıralı), `kismi / islenen / toplam / neden` alanlarını taşır; bütçe dolmadığında bu alanlar YAZILMAZ (S8 eşitliği için: öntanımda çıktı bayt bayt aynı kalır).
5. **BSim sorgusu da bütçeli.** Plan adım 3 yalnız boş depoyu atlıyor; dolu depoda sorgunun sınırı yok. `timeouts.ghidra_adim` sorgu adımına da uygulanır: sorgu yolu parça parça ilerliyorsa (fonksiyon başına yol) parça sınırında denetle, aşılırsa eldeki eşleşmelerle `bsim_status: "kismi"` yaz. Toplu yol tek bir Java çağrısıysa onu BÖLME (HZ-2'nin alanı): çağrıdan önce kalan bütçeyi denetle, çağrının kendisinin kesilemediğini ilerleme dosyana yaz.
6. **HZ-2 sınırı.** `_BSimNativeWrapper.ingest_program`'daki tarama döngüsünü yeniden yazma; yalnız süre denetimi ve sayaç ekle. HZ-2 o döngüyü `scanFunctions`'a çevirecek: bütçe denetiminin oraya nasıl taşınacağını `OL2.md`'de "HZ-2 için notlar"a yaz. Eşleşme / dışlama mantığına (`_Exclusion`, `_matches_from_notes`) dokunma.
7. **"Depoda başka program var mı" sorusu** ingest'ten ÖNCE, köken kaydından (`_ProvenanceStore.load`) cevaplanır ve programın kendi kimliği (`ExeIdentity`: md5 / sha256 / derleme kimliği; `_Exclusion.classify` ile aynı ölçüt) dışarıda tutulur: aynı ikili ikinci kez koşulduğunda depo "boş" sayılmalı. Köken kaydı okunamıyorsa (bozuk / karantinaya alınmış) sorgu ATLANMAZ (bugünkü davranış) ve neden durum alanına yazılır.
8. **Kabul (d) bu pakette ölçülmez.** 119 birleşik koşusu kapanış ölçümünde; `OL2.md`'ye "ölçülmedi; kapanış ölçümüne bırakıldı" yaz. BSim gölge kipte olduğu için ad etkisi S8'in `out/naming_map.json` eşitliğiyle denetlenir.
9. **Kapsam dışı (not olarak yaz, yapma):** Ghidra SONRASI adımların (yeniden kurma, blok açıklama …) takılma bekçisi; bugün orada bir düzenli ifade koşuyu kilitledi (BA-1). ÖL-6 / ayrı paket.

## Yazabileceğin dosyalar

- `karadul/ghidra/headless.py` — döküm işlevleri (`_extract_strings`, `_extract_call_graph`, `_extract_types`, `_extract_xrefs`, `_extract_pcode`, `_extract_pcode_stats_only`, `_extract_cfg`, `_extract_function_id_matches`) ve `_analyze_pyghidra` içinde bunların çağrı noktaları + BSim bloğu (bugün ≈ 830–892). İşlev adlarını `grep -n "def <ad>"` ile bul; plan metnindeki satır numaraları eski.
- `karadul/ghidra/bsim.py` — boş depo sorusu, ingest bütçesi, sorgu bütçe denetimi, durum alanları.
- Yeni `tests/test_ol2_adim_butcesi.py`, `tests/test_ol2_bsim_kosul.py`, `scripts/measurement/mutation_specs_ol2.json` (≥ 10 mutant).
- Belgeler: `docs/arge/2026-11-19_mythos/olcek/on_kayit_ol2.md`, `docs/arge/2026-11-19_mythos/olcek/OL2.md` (ilerleme dosyası).
- Yama: `docs/arge/2026-11-23_dalga1/yamalar/OL2__config.py.patch`.

**Dokunma:** `karadul/config.py`, `_run_auto_analysis`, `_CozumleyiciBekcisi`, `_decompile_functions` ve alt işlevleri (zaten sınırlı; HZ-3 girecek), `karadul/analyzers/macho.py`, `karadul/pipeline/steps/bsim_match.py`, `karadul/ghidra/_bsim_shadow.py`, `karadul/core/pipeline.py`, `karadul/stages.py`, `karadul/cli.py`, `ui/`.

`headless.py`'de `find` metni tutan mutasyon tanımları: `mutation_specs_{hz1,ol1,p13a,p16a,p16c,p16d,p16e}.json`; `bsim.py`'de: `mutation_specs_{p16b,p16c}.json`. Değişikliğinden sonra sekizini yeniden koş; bayatlayan olursa ilerleme dosyana yaz (düzeltme: yama olarak bırak).

## Ön kayıt (`on_kayit_ol2.md`; ölçümden önce ayrı commit)

Planın metni, şu düzeltmelerle (sayılar ana oturumun; değiştirme):
> H1 (T25): BSim adımı (ingest + sorgu) ≤ 930 sn (bugünkü ürün aynı dilimde 1 781 sn); `bsim_matches.json` `total_matches` 0 → 0, `bsim_status` `atlandi` (taze depo) ve ingest bütçeyi aşarsa `kismi`.
> H2 (sqlite3, `timeouts.ghidra_adim: 2`): her sınırsız adım ≤ 2 + 5 sn'de biter; bütçesi dolan adımın çıktısı geçerli JSON ve `kismi: true`; koşu çıkış kodu 3.
> H3 (S8, tek kökte, ORTAK_D0 §6 sırasıyla, yamanın öntanımları YAML'da): taban `~/karadul_olcum/runs/dalga1-2026-11-23/P16e/s8_sonra_3`. Depo kökte biriktiği için sorgu atlama yalnız İLK ikilide (cat) beklenir: orada `bsim_matches.json` yalnız `bsim_status` / `bsim_detail` alanlarında farklı; öbür 7 ikilide BSim dosyaları dahil ham eşit. Bütün ikililerde `decompiled/*.c`, öbür `ghidra_output/*.json` ve `out/naming_map.json` ham eşit 8 / 8.
> H4: T25'te statik aşama boyunca en uzun `ILERLEME` sessizliği: decompile dışındaki adımlarda ≤ 60 sn (hüküm 3). Decompile içindeki sessizlik ayrıca raporlanır (HZ-3'ün işi; hüküm yok).
> H5: Bütçe öntanımında (3 600 sn) S8'de kesilen adım 0.

Bilinen kendiliğinden fark: Ghidra decompiler'ı zstd `FUN_001063c0`'da 6 koşunun 1'inde iki geçici değişkeni yer değiştiriyor (P16e). Bir `.c` farkı görürsen o ikiliyi bir kez daha koş, iki sonucu da yaz.

## Ölçüm

- Kendi dalının ürün ağacı (ORTAK_D0 §3: `~/karadul_olcum/urun-<kısa-hash>` + altı bağ). Her Ghidra koşusu kuyrukla: `~/karadul_olcum/ghidra_kuyruk.sh OL2 <etiket> …`, ikili başına ayrı çağrı. Kuyrukta başka paketler ve ana oturumun Ollama koşusu var; bekleme sürebilir: kodu, testleri ve mutasyonu bitirmeden kuyruğa girme, kuyruktayken belge yaz.
- **Sıra:** sqlite3 (H2; tek kısa koşu, `--stage static`) → S8 (H3, H5) → T25 (H1, H4).
- **T25:** Ollama dilimi (`~/karadul_olcum/runs/gosteri-2026-11-19/ollama/girdi/Ollama`), `--stage static` (statik aşamada dur), taze `KARADUL_CACHE_DIR`; çözümleyici ayarı bugünkü ana oturum koşusuyla aynı (`~/karadul_olcum/runs/dalga1-2026-11-23/ANA/ollama_ustveri/bayraklar.yaml`'daki `analysis` bölümü: ObjC ileti çözümleyicisi kapalı) + senin üç alanın. O koşuda BSim'e kadar 28 dk sürmüştü (yük altında); süre sınırı 75 dk (`timeout`). Süreler "yük altında" etiketli, `uptime` künyeli.
- Koşu kökü `~/karadul_olcum/runs/dalga1-2026-11-23/OL2/`; özetleri `ozet/` altına topla (A-35).

## Sert son

Gönderim iletisinde yazılı. Öncelik: kod + testler + mutasyon → sqlite3 → S8 → T25 → tam takım. O saatte koşulamayan ölçümü "kalan" diye yaz.

## Dönüş mesajı

İlk satır gerçek uygulama sayısı: T25'te BSim adımı kaç saniye (önce 1 781), sorgu atlandı mı, ingest kaç saniyede / hangi durumla bitti, decompile dışı en uzun `ILERLEME` sessizliği kaç saniye (ölçülmediyse "ölçülmedi"). Sonra H1–H5, sqlite3'te adım adım süre tablosu, S8 x / 8, test / mutant sayıları, sekiz eski tanımın durumu, commit listesi, yama, HZ-2 / ÖL-3 / ÖL-4 için notlar, koşu kökünün yolu ve boyutu.
