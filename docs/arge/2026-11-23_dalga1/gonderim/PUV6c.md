# PUV6c — P-ÜV6c: Go üst verisinin tutarlılık damgası, okuyucu düzeltmeleri ve yanıltıcı "kısmi" durumu

Önce oku (sırayla, baştan sona): `docs/arge/2026-11-23_dalga1/ORTAK_D1.md` (§5 ve §6 dahil), `docs/arge/2026-11-20_dalga0/ORTAK_D0.md`, `docs/arge/2026-11-18_onarim/ONARIM_BRIF.md`, `docs/arge/2026-11-19_mythos/KARARLAR.md` (A-10, A-13, A-14, A-17, A-27, A-32, A-34), `docs/arge/2026-11-19_mythos/ustveri/PLAN.md` "P-ÜV6" kalem 5 ve 7, "P-ÜV7", `docs/arge/2026-11-19_mythos/ustveri/P-UV7.md` (tutarlılık denetimi; bozma deneyi; "P-ÜV6b için notlar" bölümü bu paketin girdisidir), `docs/arge/2026-11-19_mythos/ustveri/P-UV6a.md` ve `P-UV6b.md` (senden önce aynı dosyalara giren iki paket; altyapı onların), `docs/arge/2026-11-23_dalga1/DURUM.md`'nin "Ollama kabul koşusu" bölümü.

## Neden

Go adları üründe çıktıya giriyor (Ollama'da 10 475), ama üç şey eksik:

1. **Damga yok:** her Go adının köken kaydında `ust_veri_dogrulama: olculmedi` yazıyor. Tutarlılık denetimi (PUV7: ad ↔ tip verisi çapraz denetimi, K4 / K10 içerik denetimleri) main'de ve üründe çağrılmıyor. Bozuk ya da oynanmış üst veride yanlış adın yazılmasını engelleyen tek düzenek bu (A-10): `tutarsiz` damgalı ad yazılmamalı.
2. **Okuyucuda bilinen üç kusur** (PUV7'nin bulduğu): `oku()` okuyucu nesnesini döndürmüyor (denetim onu yeniden kuruyor), `paket_adi` yükseltilmiş dışa kapalı yöntemlerde paketi yanlış yazıyor (Ollama 4, docker-cli 264 fonksiyon), `FUNC_ID` tablosu tek yerde değil.
3. **Yanıltıcı "kısmi":** evrensel (çok mimarili) ikilide eski Go çözümleyicisi "şişman dosyayı açmıyor" hatası bildiriyor (`karadul/stages.py:114` civarı) ve koşu çıkış 3 ile bitiyor; oysa yeni okuyucu aynı dilimden bütün adları okudu. Analiste "bir şey eksik" deniyor ama eksik yok.

## Ana oturumun hükümleri

1. **Damga bağlanır** (bayrak `binary_reconstruction.enable_go_metadata_integrity`; INERT'te, öntanım kapalı): açıkken `tutarlilik.denetle` koşar; her Go adının köken kaydına `ust_veri_dogrulama` = `cift_kaynak` / `tek_kaynak` / `tutarsiz` yazılır. `tutarsiz` damgalı fonksiyonun adı YAZILMAZ, kanıt satırı olur (nedeniyle). Bayrak kapalıyken davranış bugünküyle bayt bayt aynı (`olculmedi`).
2. **İkili düzeyi karar:** `tutarlilik` kararı `ust_veri_supheli` ise bütün Go adları kanıt satırına iner ve rapora uyarı girer; `uyari` ise adlar yazılır ve rapora uyarı girer (PUV7'nin ölçümü: ayırt edici düzey `uyari`; bozulmamış 11 / 11 `temiz`). Uyarı metni gerçek sayıları taşır (kaç güçlü işaret, hangi denetim); uydurma risk puanı yok. Raporun hangi alanına gireceğini var olan uyarı düzeninden seç (`report.json` + okunur rapor) ve yaz.
3. **Etiket değişmez:** damga ne olursa olsun etiket `üst veriden` kalır (`cift_kaynak` adı `kesin` YAPMAZ: tutarlı sahtecilik hiçbir denetimde görünmüyor; PUV7 D türü). Güven tablosu satırı değişmez.
4. **Okuyucu düzeltmeleri:** (a) `GoSonuc`'a okuyucu nesnesi alanı (`pcln`; serileştirilmez) ve denetimin onu kullanması; (b) `paket_adi`: alıcılı adlarda paket = ilk `.(` ya da tip adından önceki önek (PUV7'nin T2p önek denetimiyle aynı kural; eski ↔ yeni farkı gerçek veride say: Ollama, docker-cli); (c) `FUNC_ID` tek tanım (`go_pclntab.py` ya da ortak modül; `tutarlilik.py` oradan içe aktarır). Ad kanalının verdiği ad (`ozgun_ad`) bu düzeltmelerle DEĞİŞMEMELİ: yalnız `paket` / `sinif` yan alanları değişir (H3).
5. **Yanıltıcı hata:** evrensel ikilide eski Go çözümleyicisinin "açmıyor" iletisi, `go_metadata_recovery` aynı koşuda Go dilimini okuduysa (`go_functions` durumu `calisti`) aşama HATASI sayılmaz; bilgi satırı olarak kalır ("eski çözümleyici evrensel dosyayı açmıyor; ad ve fonksiyon bilgisi yeni okuyucudan"). Yeni okuyucu kapalıysa ya da okuyamadıysa bugünkü hata aynen durur. `stages.py`'de yalnız o iletiyi üreten işlev ve çağrı yeri.
6. **Eski Go kanalı çakışması** (plan kalem 7): `go_demangler` (nm) kanalı `go_pclntab` açıkken aynı adrese ikinci aday üretmez; test.
7. **`config.py`'ye yazmazsın.** Yama `docs/arge/2026-11-23_dalga1/yamalar/PUV6c__config.py.patch`: `enable_go_metadata_integrity` INERT satırını siler, yorumu düzeltir; öntanım KAPALI kalır. Ağacına uygulama.
8. **Kapsam dışı (PUV6d'nin işi; dokunma):** `main` / `entry` işleri (`PUV5__output_formatter.py.patch`, `entry` sözcüğü riski, `main` künyesi), etiketsiz `swift_demangle` adları.

## Yazabileceğin dosyalar

`karadul/pipeline/steps/_feedback_naming_candidates.py` (yalnız `_add_go_pclntab` ve Go damgasının yardımcıları; eski Go kanalının çakışma denetimi), `karadul/pipeline/steps/_feedback_naming_merger.py` (yalnız damganın köken kaydına taşınması), `karadul/pipeline/steps/go_metadata_recovery.py` (denetimin çağrılması, durum alanları), `karadul/analyzers/ustveri/go_pclntab.py`, `karadul/analyzers/ustveri/tutarlilik.py` (yalnız hüküm 4a / 4c'nin gerektirdiği içe aktarma ve imza), `karadul/core/naming_labels.py` (yalnız damga sabitleri gerekiyorsa), `karadul/stages.py` (yalnız hüküm 5), rapora uyarıyı taşıyan tek dosya (hangisi olduğunu yaz); yeni `tests/test_puv6c_go_damga.py` (≥ 16 test), `scripts/measurement/mutation_specs_puv6c.json` (≥ 10 mutant: `tutarsiz` süzgeci kalkar; şüpheli ikilide adlar yazılır; damga `kesin` etiketi verir; bayrak öntanımı açık; `uyari` rapora girmez; yeni okuyucu çalışmışken hata yine yazılır / çalışmamışken hata düşer; `paket_adi` eski kural; iki Go kanalı aynı adrese iki aday); `docs/arge/2026-11-19_mythos/ustveri/on_kayit_PUV6c.md`, `docs/arge/2026-11-19_mythos/ustveri/P-UV6c.md` (ilerleme dosyası); yama.

**Dokunma:** `karadul/config.py`, `karadul/core/output_formatter.py`, `_add_swift_types` / `_add_rtti` / `_add_objc_methods` / `_add_bindiff` / `_add_refdiff`, `karadul/reconstruction/`, `karadul/ghidra/`, `karadul/cli.py`, `ui/`, `karadul/pipeline/runner.py` (GS-1 çalışıyor olabilir).

Dokunduğun dosyalara bakan eski mutasyon tanımlarını (`grep -l`; en az `mutation_specs_{puv6a,puv6b,puv1,puv7,pk1,p13b,puv5,adim3_hat}.json`) yeniden koş; bayatlayanı düzelt ve yaz.

## Ön kayıt (`on_kayit_PUV6c.md`; ölçümden önce ayrı commit; sayılar ana oturumun)

> H1 (bayrak kapalı): S8'in 2 ikilisinde (cat, mac/tmux; taban `~/karadul_olcum/runs/dalga1-2026-11-23/ANA/s8_taban_534e252b`) çıktı tabanla aynı; Ollama'nın Ghidra'sız yeniden oynatmasında (`~/karadul_olcum/runs/dalga1-2026-11-23/ANA/ollama_kabul/ws`; salt okur) Go ad adayları 10 475 ve hepsinde `olculmedi`.
> H2 (bayrak açık, Ollama, Ghidra'sız yeniden oynatma): `cift_kaynak` 3 907, `tek_kaynak` 6 568 ± 130, `tutarsiz` 0 (PUV7'nin okuyucu düzeyi sayımı: 10 600 adın 3 907'si çift, 6 693'ü tek; ad kanalına giren 10 475); yazılan ad 10 475; ikili kararı `temiz`; rapora uyarı 0.
> H3 (okuyucu düzeltmesi): Ollama ve docker-cli'de `ozgun_ad` kümesi düzeltmeden önce ↔ sonra aynı (fark 0); `paket` alanı değişen fonksiyon sayısı Ollama 4, docker-cli 264 (PUV7'nin sayımı; ± 0 değilse nedenini yaz).
> H4 (bozuk üst veri; PUV7'nin bozma düzeneği `scripts/measurement/ustveri_bozma.py`, A türü, `gh`, Ghidra'sız kanal sınaması): ikinci kaynaklı 66 fonksiyon `tutarsiz` damgası alır ve adı YAZILMAZ; ikinci kaynaksız 134 fonksiyonun bozuk adı yazılır (beklenen sınır; kayda geçer); ikili kararı `uyari`, rapora uyarı 1.
> H5 (yanıltıcı hata): Ollama'nın yeniden oynatmasında statik aşamanın hata listesinde "evrensel ikilide go dilimi" iletisi 1 → 0 (bilgi satırına iner); yeni okuyucu kapalı kolda 1 kalır. (Statik aşamayı Ghidra'sız yeniden oynatamıyorsan birim / bütünleşme testiyle göster ve "ürün koşusunda ölçülmedi" yaz.)
> H6: üst veri kaynaklı hiçbir ad `kesin` etiketi taşımaz (damga ne olursa olsun).

## Sıra

1. Ön kayıt → commit. 2. Okuyucu düzeltmeleri (hüküm 4) + H3. 3. Damga bağlama + testler + mutasyon → dondurma commit'i. 4. Ghidra'sız yeniden oynatmalar (H1, H2, H4). 5. Hüküm 5 + 6. 6. Tek ürün koşusu (isteğe bağlı, kuyruk 15 dakikadan kısa bekletiyorsa): terminal-notifier, dört üst veri bayrağı + bütünlük bayrağı açık → ObjC 32 / 32 duruyor mu. Ollama ürün koşusunu ana oturum yapar. 7. Tam takım.

## Sert son

Gönderim iletisinde yazılı.

## Dönüş mesajı

İlk satır gerçek uygulama sayısı: Ollama'da damga dağılımı (çift / tek / tutarsız), yazılan Go adı sayısı (10 475 duruyor mu), bozuk `gh` kopyasında yazılmayan tutarsız ad sayısı, evrensel ikili hatası 1 → ?. Sonra H1–H6, `paket_adi` düzeltmesinin etkilediği fonksiyon sayıları, uyarının raporda göründüğü yer (metniyle), test / mutant sayıları, eski tanımların durumu, commit listesi (dondurma işaretli), yama, PUV6d ve açılış ölçümü için notlar.
