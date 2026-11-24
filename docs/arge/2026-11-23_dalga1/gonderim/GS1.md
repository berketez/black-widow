# GS1 — GS-1: Ghidra sonrası adımların görünmesi ve iptalin kesinleşmesi (A-36)

Önce oku (sırayla, baştan sona): `docs/arge/2026-11-23_dalga1/ORTAK_D1.md` (§5 ve §6 dahil), `docs/arge/2026-11-20_dalga0/ORTAK_D0.md`, `docs/arge/2026-11-18_onarim/ONARIM_BRIF.md`, `docs/arge/2026-11-19_mythos/KARARLAR.md` (A-7, A-8, A-36), `docs/arge/2026-11-19_mythos/olcek/PLAN.md` §1 (ilerleme olayı sözleşmesi: SABİT), `docs/arge/2026-11-19_mythos/olcek/OL4.md` (senden hemen önce `ui/server.py`'ye ve CLI'a giren paket: ayrıştırıcı `karadul/core/ilerleme.py`, artımlı okuma, uygulanmayan `index.html` yaması, "ÖL-8 / OL10-H notları"), `docs/arge/2026-11-19_mythos/olcek/OL1.md` ve `OL2.md` (olay üreticileri), `docs/arge/2026-11-23_dalga1/BA1.md` ve `BA2.md` (takılma sınıfı; "GS-1 için" notları), `docs/arge/2026-11-23_dalga1/DURUM.md`'nin 23 Kasım "Ollama uçtan uca koşusu" bölümleri.

## Neden

23 Kasım'da tek bir düzenli ifade Ollama koşusunu 31 dakika kilitledi ve süreç SIGTERM'e yanıt vermedi. Kalıp onarıldı (BA-1, BA-2) ve tam takıma kalıp denetimi kapısı kondu; ama kapının göremediği sınıflar var (dış girdiden derlenen kalıp, değişkenle taşınan kalıp, çok büyük girdide polinom kalıp) ve `re` eşleşmesi GIL'i bırakmadığı için takılma anında süreç içinden hiçbir bekçi koşamaz. İki açık kaldı:

1. **Görünürlük:** olay yalnız Ghidra köprüsünden geliyor. Yeniden kurma aşaması (dünkü Ollama koşusunda 44 dakika) ve statik aşamanın köprüden sonraki kısmı (≈ 215 sn) tek olay üretmiyor: analist hangi adımın koştuğunu, takılıp takılmadığını göremiyor.
2. **Kesin iptal:** arayüzün "İptal"i yalnız SIGTERM gönderiyor (`ui/server.py` `_kill_proc`). Takılı süreç SIGTERM'e yanıt vermezse arkada dönmeye devam eder.

## Ana oturumun hükümleri

1. **Adım olayları:** boru hattı adım koşucusu (`karadul/pipeline/runner.py`) koşan her adım için sözleşme biçiminde olay üretir: `ILERLEME asama=<aşama> adim=<aşama>.<adım adı> durum=basladi`, bitişte `durum=bitti gecen_sn=…` (adım hata bildirdiyse `durum=kismi neden="…"`, bayrakla atlandıysa `durum=atlandi neden="…"`). Aşama sınırlarında (`karadul/core/pipeline.py`) aşama başı / sonu olayı. Günlükçü `karadul.ilerleme`; satırı kuran yardımcı tek yerde olsun (`karadul/core/ilerleme.py`'ye üretici taşınabilir; `karadul/ghidra/headless.py`'ye DOKUNMA — orada HZ-4a çalışıyor; köprünün kendi üreticisi olduğu gibi kalır, iki üretici aynı biçimi verir ve bunu test kilitler).
2. **Sahte ilerleme yok:** olay yalnız gerçek adım başı / sonunda üretilir. Adım içi `suruyor` olayı bu pakette YOK (adımın gerçek sayacı yoksa uydurulmaz). Zamanlayıcıyla "hâlâ çalışıyor" satırı basılmaz.
3. **Çıktı değişmez:** olaylar günlük satırıdır; `out/`, çalışma alanı dosyaları ve rapor bayt bayt aynı kalır (H2).
4. **Son olayın yaşı gerçek veridir:** `_job_progress` yeni alan `son_cikti_yasi_sn` verir = şimdi − iş günlüğünün son değişme zamanı (dosya yoksa `null`). Arayüz bunu olduğu gibi yazar ("son çıktı 31 dk önce"); eşik, renk, uyarı metni, animasyon EKLEME (yorum analistin).
5. **Kesin iptal:** `cancel_job` / `_kill_proc` süreç grubuna SIGTERM gönderir, `IPTAL_BEKLEME_SN` (modül sabiti; öntanım 5) kadar bekler, süreç hâlâ yaşıyorsa gruba SIGKILL gönderir. Dönen kayıtta hangisinin gerektiği yazılır (`sonlandirma: "term" | "kill"`). Sunucunun kendi süreç grubunu vurmama koruması (bugünkü `pgid == os.getpgrp()` denetimi) korunur. Sunucu kapanışındaki toplu sonlandırma (`_terminate_jobs`) da aynı yolu kullanır. Sınama: SIGTERM'i yok sayan gerçek bir alt süreçle (ve mümkünse C düzeyinde düzenli ifadede takılı bir alt süreçle: BA-2'nin hazır girdisi) iptal ≤ bekleme + 2 sn'de biter, grup üyesi de ölür.
6. **`index.html`:** OL4'ün bıraktığı yamayı uygula (`docs/arge/2026-11-23_dalga1/yamalar/OL4__index.html.patch`; bağlam tutmazsa aynı farkı elle), yanına hüküm 4'ün satırını ve — başka aşamalar artık olay ürettiği için — OL4 notundaki düzeltmeyi (`s.key==='static'` → olayın `asama` alanı; ayrıştırıcının verdiği alanlara `asama` eklenir) ekle. CSP karmasını yenile (`~/karadul_olcum/runs/dalga1-2026-11-23/OL4/betik/csp_karma.py`), `node --check` ve var olan arayüz testleri (`tests/test_ui_*.py`) yeşil; yeni satırlar için içerik testi yaz. Animasyon, dönen simge, "ilerliyor" metni YOK.
7. **SIGTERM'e yanıtsızlığın nedeni ölçülür (ilk ölçüm; ürün kodu değişmeden):** ayrı süreçlerde, Ghidra'sız: (a) yalın Python + takılı düzenli ifade (BA-2'nin girdisi: Ollama dizgisi + `python_binary.py:117` kalıbı, ≈ 10 sn; ya da BA-1'in eski kalıbı) + SIGTERM; (b) aynısı `karadul analyze`'ın kurduğu işaret işleyicileriyle (hangileri kurulu: `signal.getsignal` dökümü); (c) aynısı süreç içi JVM başlatılmışken (pyghidra; JVM kendi SIGTERM işleyicisini kurar mı). Hangi koşulda süreç ölmüyor? Sonucu tabloyla yaz. Neden `cli.py`'de bizim kurduğumuz bir işleyiciyse düzeltmeyi YAMA olarak bırak; JVM ise "süreç içinden çözülemez, dış iptal gerekir" hükmünü yaz.
8. **Kapsam dışı (not olarak yaz):** CLI'da gözetmen süreç (ÖL-5b ile); statik aşamanın köprü dışı alt adımlarının olayları (`karadul/analyzers/macho.py`; ÖL-3'ün dosyası); adım bütçesi / adımı zorla kesme.

## Yazabileceğin dosyalar

`karadul/pipeline/runner.py` (yalnız adım başı / sonu olayları), `karadul/core/pipeline.py` (yalnız aşama başı / sonu olayı), `karadul/core/ilerleme.py`, `ui/server.py` (yalnız `_kill_proc`, `cancel_job`, `_terminate_jobs`, `_job_progress`'in yeni alanı ve yardımcıları), `ui/index.html` (yalnız hüküm 6); yeni `tests/test_gs1_adim_olaylari.py`, `tests/test_gs1_kesin_iptal.py`, `scripts/measurement/mutation_specs_gs1.json` (≥ 10 mutant); `scripts/arge/gs1/` (hüküm 7'nin ölçüm betikleri); `docs/arge/2026-11-23_dalga1/on_kayit_GS1.md`, `docs/arge/2026-11-23_dalga1/GS1.md` (ilerleme dosyası); yamalar.

**Dokunma:** `karadul/ghidra/` (HZ-4a, HZ-2), `karadul/cli.py` ve `karadul/cli_common.py` (gerekiyorsa yama), `karadul/stages.py`, `karadul/pipeline/steps/`, `karadul/analyzers/`, `karadul/config.py`, `karadul/reconstruction/`.

Dokunduğun dosyalara bakan eski mutasyon tanımlarını (`grep -l`; en az `mutation_specs_{ol4,adim3_ui,ui_cagri_kenari,ui_lm_api,p17,pguv,surum_oncesi}.json`) yeniden koş; bayatlayanı düzelt ve yaz.

## Ön kayıt (`on_kayit_GS1.md`; ölçümden önce ayrı commit)

> H1 (adım olayları, debian `cat`, `--verbose`, tek ürün koşusu): yeniden kurma aşamasında koşan her adım için tam bir `basladi` ve bir bitiş olayı (`bitti` / `kismi` / `atlandi`); olay sayısı = 2 × koşan adım sayısı; her aşama için bir baş ve bir son olayı.
> H2 (çıktı): aynı koşunun `out/` ağacı ve `out/naming_map.json`'ı S8 tabanındaki cat ile (`~/karadul_olcum/runs/dalga1-2026-11-23/ANA/s8_taban_534e252b/debian/coreutils/cat`) bayt eşit.
> H3 (kesin iptal): SIGTERM'i yok sayan alt süreç + torunu iptalden sonra ≤ 7 sn'de ölü; `sonlandirma: "kill"`. SIGTERM'e uyan alt süreçte `sonlandirma: "term"` ve ≤ 2 sn.
> H4 (neden): hüküm 7'nin üç koşulundan hangisinde süreç SIGTERM'le ölmüyor — yön bildirilmez, ilk ölçüm.
> H5 (maliyet): adım olaylarının koşu süresine eklediği pay ≤ %0,1 (olay sayısı × satır maliyeti; ölçerek).

## Sıra

1. Hüküm 7'nin ölçümü (Ghidra'sız; sonucu paketin geri kalanını yönlendirir) → ön kayıt → commit. 2. Kesin iptal + testler. 3. Adım ve aşama olayları + testler. 4. `son_cikti_yasi_sn` + `index.html`. 5. Mutasyon. 6. Tek ürün koşusu (cat; kuyrukla `~/karadul_olcum/ghidra_kuyruk.sh GS1 cat …`, kendi dalının ürün ağacı) → H1, H2, H5. 7. Tam takım.

## Sert son

Gönderim iletisinde yazılı.

## Dönüş mesajı

İlk satır gerçek koşu sayısı: `cat` koşusunda yeniden kurma aşamasının adım olayı sayısı ve kapsanan adım sayısı; kesin iptalde SIGTERM'i yok sayan süreç kaç saniyede öldü; SIGTERM'e yanıtsızlığın bulunan nedeni. Sonra H1–H5, arayüzde görünen yeni satırlar (metin olarak), test / mutant sayıları, eski tanımların durumu, commit listesi, yamalar, ÖL-5b / ÖL-6 / ÖL-8 için notlar.
