# PUV6b — P-ÜV6b: Swift ve C++ RTTI üst verisinin ürün çıktısına bağlanması

Önce oku (sırayla, baştan sona): `docs/arge/2026-11-23_dalga1/ORTAK_D1.md` (§5 akşam eki dahil), `docs/arge/2026-11-20_dalga0/ORTAK_D0.md`, `docs/arge/2026-11-18_onarim/ONARIM_BRIF.md`, `docs/arge/2026-11-19_mythos/KARARLAR.md` (A-2, A-10, A-13, A-14, A-17, A-25, A-27, A-28, A-32, A-34), `docs/arge/2026-11-19_mythos/ustveri/PLAN.md` "P-ÜV6" (kalem 2–6; sınama ve mutasyon düzeni), `docs/arge/2026-11-19_mythos/ustveri/P-UV6a.md` (kurduğu altyapı, ölçüm yöntemi ve "P-ÜV6b'ye bırakılanlar"), `docs/arge/2026-11-19_mythos/ustveri/P-UV3.md` ve `P-UV4.md`'nin "P-ÜV6b için notlar" bölümleri, `docs/arge/2026-11-19_mythos/ustveri/P-UV5.md` ve `docs/arge/2026-11-19_mythos/kimlik/PK-1.md` (senden hemen önce `stages.py`'ye ve `_feedback_naming_candidates.py`'ye giren iki paket).

## Neden

Swift tip üst verisi okuyucusu (PUV3: iTerm2'de 2 627 tipe ad, yanlış 0) ve C++ RTTI taraması (PUV4: llama-server'da 1 994 sınıf adı, 6 990 yuva → sınıf bağı) main'de ama ürün akışına bağlı değil: adımlar Faz 1 listesinde yok, çıktıları hiçbir ada ya da kanıt satırına dönüşmüyor. Berke'nin kuralı (A-27): ikilide ne varsa okunur ve analiste ulaşır. Bu paket PUV6a'nın Go / ObjC için kurduğu kalıpla Swift'i ad kanalı, RTTI'yi kanıt satırı olarak bağlar. P-ÜV6b'nin öbür yarısı (Go tutarlılık damgası, `main` künyesi, `go_pclntab` notları) ayrı pakettir (PUV6c): onlara girme.

## Ana oturumun hükümleri (plan metninin önüne geçer)

1. **Altyapı PUV6a'nınki.** `naming_labels.METADATA_SOURCES` / `MEASURED_METADATA_PRECISION`, `_metadata_gate`, `_add_metadata_candidate`, `ust_veri_kanit`, etiket `üst veriden`, `ozgun_ad`. İkinci bir kalıp kurma; eksik gördüğünü genişlet ve yaz.
2. **Swift = ad kanalı** (`swift_type_accessor`). Aday: `swift_types[i]`'de `ad_yazilabilir is True` olan kaydın erişim fonksiyonu adresi; `ozgun_ad` = `type metadata accessor for <nitelikli_ad>` (HEDEF ölçüm aracının kuralıyla birebir); koda yazılan tanımlayıcı Go / ObjC ile aynı dönüştürücüden. P13b kuralı geçerli: aday yalnız Ghidra'nın o adreste adsız bıraktığı fonksiyona (A-28 istisnası yalnız ObjC'dir). `ad_yazilabilir` olmayan tipler (ayracı ikilide olmayan özel tipler, işlev içi tipler, kısıtlı uzantı) ve `swift_slots` (vtable / geçersiz kılma / tanık) AD ALMAZ: kanıt satırı olur. Ad uydurma yok.
3. **RTTI = kanıt satırı** (A-32). `_add_rtti` bugün `Sınıf_vfunc_N` adı üretiyor (güven 0,6; tam eşitlikte doğruluğu 0): ad üretmeyi bırakır; `static/rtti_classes.json`'ın `islevler[]` kayıtlarından kanıt satırı yazar (`sinif`, `karar`, `yerler`; `belirsiz` kararında sınıf adı yazılmaz, `siniflar` listesi yazılır). Bayrak adı `enable_rtti_naming` kalır (anlamı: "RTTI kanıtını köken kaydına yaz"); yorumunu yama düzeltir. K4'ün `UNMEASURED_SOURCES` kümesinden çıkışı ve sayaçları tutarlı olsun.
4. **Adımlar Faz 1'e:** `swift_metadata_recovery` ve `rtti_recovery`, `objc_metadata_recovery`'den sonra, `type_recovery_consumer`'dan önce; `steps/__init__.py` kaydı. Bayrak kapalıyken adım `kapali` yazar, iş yapmaz (süre ≤ 0,1 sn; ölç).
5. **ObjC güven satırı düzeltilir:** `MEASURED_METADATA_PRECISION`'da ObjC satırı ürün düzeyi aday ölçümünden (iTerm2: 33 611 doğru / 33 885 ad verilen) yazılır; bugün 0,9998 yazıyor (ana oturumun sabahki gönderim hatası). Wilson alt sınırı elle yazılmaz: sınama betikle yeniden hesaplayıp karşılaştırır (`tests/test_p12a_on_ad_guveni.py` örneği). Eşik `AD_ESIGI` içe aktarılır.
6. **Swift güven satırı:** kanal kodu dondurulduktan sonra (dondurma commit'i yazılı) iTerm2'de aday düzeyinde BİR KEZ ölçülür (PUV6a'nın ObjC için kullandığı yöntemle; yöntemi adıyla yaz). Tabloya o sayı girer. Alt sınır < `AD_ESIGI` çıkarsa kanal ad yazmaz, kanıt satırına iner (kod bunu tablodan okuyarak kendisi yapmalı; elle dal yok).
7. **Durum sabitleri tek tanım:** `DURUM_TUTARSIZ` ve `DURUM_KAPALI` `karadul/analyzers/ustveri/goruntu.py`'ye taşınır; `objc.py`, `swift.py`, `go_pclntab.py`, `cpp_rtti_tara.py` oradan içe aktarır (değer aynı; dışarıdan `modül.DURUM_…` diye okuyan yerler kırılmamalı). Bu dört dosyada başka değişiklik yok.
8. **OK1 ile ayrıklık:** `karadul/reconstruction/c_namer.py`, `karadul/reconstruction/tarif/alt_kanal.py`, `scripts/measurement/alt_kanal.py` aynı anda OK1'de: DOKUNMA. Yeni kaynak adı orada bir satır gerektiriyorsa yama bırak (`yamalar/PUV6b__<dosya>.patch`).
9. **`config.py`'ye yazmazsın.** Yama `docs/arge/2026-11-23_dalga1/yamalar/PUV6b__config.py.patch`: `enable_swift_metadata_naming` INERT satırı silinir; `enable_swift_metadata_naming`, `enable_swift_metadata_recovery`, `enable_rtti_recovery`, `enable_rtti_naming` yorumları güncellenir. Öntanımlar KAPALI kalır (öntanımda açma A-14'ün üçüncü programıyla, ayrı pakette). `enable_go_metadata_integrity` ve `enable_macho_entry_main`'e dokunma.
10. **Öntanım davranışı değişmez:** bütün bayraklar kapalıyken çıktı bayt bayt aynı.

## Yazabileceğin dosyalar

`karadul/stages.py` (YALNIZ Faz 1 adım listesi); `karadul/pipeline/steps/__init__.py`; `karadul/pipeline/steps/_feedback_naming_candidates.py` (`K4_CHANNEL_FLAGS`, `_add_rtti`, yeni `_add_swift_types` ve yardımcıları; `_add_bindiff` / `_add_refdiff` PK1'in, `_add_go_pclntab` / `_add_objc_methods` PUV6a'nın: dokunma); `karadul/pipeline/steps/_feedback_naming_merger.py` (yalnız yeni yapıtların girdiye eklenmesi); `karadul/core/naming_labels.py` (kaynak adları, tablo satırları); `karadul/core/output_formatter.py` (yalnız yeni kaynak tanınmıyorsa); `karadul/analyzers/ustveri/{goruntu,objc,swift,go_pclntab,cpp_rtti_tara}.py` (yalnız hüküm 7); var olan testlerde yalnız kaynak / kanal listesini kilitleyen satırlar (her biri gerekçesiyle); yeni `tests/test_puv6b_baglama.py` (≥ 16 test), `scripts/measurement/mutation_specs_puv6b.json` (≥ 10 mutant: bayrak öntanımı açık; adlı fonksiyona aday; `ad_yazilabilir` süzgeci kalkar; etiket `kesin`; `ozgun_ad` yerine tanımlayıcı; güven sabit; RTTI yuvası ad adayı olur; `belirsiz` kararda sınıf adı yazılır; adım tüketiciden sonra; tablo eşiği atlanır); `docs/arge/2026-11-19_mythos/ustveri/on_kayit_PUV6b.md`, `docs/arge/2026-11-19_mythos/ustveri/P-UV6b.md` (ilerleme dosyası); yamalar.

**Dokunma:** `karadul/config.py`, hüküm 8'deki üç dosya, `karadul/analyzers/ustveri/` modüllerinin okuma mantığı, `karadul/analyzers/ustveri/tutarlilik.py` ve `go_tip.py` (PUV6c), `karadul/lm/`, `ui/`.

Dokunduğun dosyalara bakan mutasyon tanımlarını (`grep -l` ile; en az `mutation_specs_{puv6a,puv3,puv4,p13b}.json`) değişiklikten sonra yeniden koş; bayatlayanı yaz.

## Ön kayıt (`on_kayit_PUV6b.md`; ölçümden önce ayrı commit; sayılar ana oturumun)

> H1 (öntanım): bayraklar kapalıyken S8'in 5 ikilisinde (cat, tree, sqlite3, zstd, mac/tmux) `out/naming_map.json`, `decompiled/*.c` ve `out/src` tabanla (`~/karadul_olcum/runs/dalga1-2026-11-23/P16e/s8_sonra_3`; aynı sıra, tek kök) aynı; yeni iki adımın süresi ≤ 0,1 sn. (BSim durum alanları OL2 main'deyse farklı olabilir: ayrı yaz.)
> H2 (bayraklar açık ↔ kapalı, aynı ağaç): aynı 5 ikili + debian `pzstd`'de değişen ad 0; `pzstd`'de RTTI kanıt satırı ≥ 1, RTTI kaynaklı ad 0.
> H3 (Swift, iTerm2, SINAMA, bir kez, dondurmadan sonra): aday düzeyinde yanlış ad oranı ≤ %1 ve Wilson alt sınırı ≥ `AD_ESIGI`; aday sayısı ilk ölçüm (okuyucu 2 627 tipe ad veriyor).
> H4 (RTTI, llama-server, SINAMA, bir kez): kanıt satırı sayısı 6 990 ± 42 (ürün bağı; belirsiz 42); RTTI kaynaklı ad 0.
> H5: üst veri kaynaklı hiçbir ad `kesin` etiketi taşımaz; Swift adlarının hepsinde etiket `üst veriden`, `ozgun_ad` dolu, güven tablodan.
> H6 (hedef seti, ürün koşusu, bayraklar açık): terminal-notifier'da ObjC adı 32 / 32 kalır (geriye gitme yok). Rectangle'da (soyulmuş, GT yok) Swift kanalının yazdığı ad sayısı ilk ölçüm (okuyucu 180 tipe ad veriyor); doğruluk ölçülmez.

## Sıra

1. Ön kayıt → commit. 2. Kod + testler + mutasyon → dondurma commit'i. 3. Ghidra'sız yeniden oynatma: H3, H4 (birer kez), var olan çalışma alanlarında (Ollama `ANA/ollama_ustveri/ws`, terminal-notifier) kanal sayıları. 4. Ürün koşuları kuyrukla (`~/karadul_olcum/ghidra_kuyruk.sh PUV6b <etiket> …`, kendi dalının ürün ağacı): önce kapalı kol 5 ikili (H1), sonra açık kol 6 ikili (H2), terminal-notifier ve Rectangle (H6). 5. Tam takım (yamasız; beklenen tek kırmızı `test_p15a_etkisiz`'in bağladığın alanla ilgili satırı).

## Sert son

Gönderim iletisinde yazılı. Koşulamayan ürün koşusunu "kalan" diye yaz.

## Dönüş mesajı

İlk satır gerçek uygulama sayısı: iTerm2'de Swift kanalı doğru / ad verilen (aday düzeyi), llama-server'da RTTI kanıt satırı sayısı, Rectangle'da yazılan Swift adı, terminal-notifier 32 / 32 duruyor mu. Sonra H1–H6, güven tablosunun yeni satırları, test / mutant sayıları, commit listesi (dondurma commit'i işaretli), yamalar, PUV6c ve açılış ölçümü için notlar, koşu kökünün yolu ve boyutu.
