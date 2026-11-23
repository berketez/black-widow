# OL10A — ÖL-10 alt paketi A: saf çekirdek (seçim kuralı, xref türetme, kuru seçim aracı)

Önce oku (sırayla, baştan sona): `docs/arge/2026-11-23_dalga1/ORTAK_D1.md`, `docs/arge/2026-11-20_dalga0/ORTAK_D0.md`, `docs/arge/2026-11-18_onarim/ONARIM_BRIF.md`, `docs/arge/2026-11-19_mythos/KARARLAR.md` (A-7, A-8, A-9, A-17, A-18, A-33), `docs/arge/2026-11-19_mythos/olcek/OL10_TASARIM.md` — "Berke için özet", §0, §1.3, **§2 (seçim kuralı; birebir uygulanacak)**, §7.0 ve **§7.1 (bu paket: dokunur / dokunmaz, adımlar 1–8, kabul, ön kayıt H-A1 … H-A7, mutasyon)**, Ek B-1 ve B-2 (tasarım turunun kuru sayımı ve komutları).

## Neden

Bugünkü ürün her fonksiyonu decompile ediyor; 26,6 MB'lık Ollama dilimi 129 dakikada kısmi bitti, 100 MB için yalnız Ghidra kısmı TAHMİN 14–39 saat. Büyük ikili kipi (ÖL-10) pahalı adımı yalnız seçilen fonksiyonlarda koşar. Bu paket o kipin Ghidra'sız çekirdeğidir: hangi fonksiyonun seçileceğine karar veren kural ve pahalı xref dökümünü ucuz iki dosyadan türeten modül. Ürün akışına bağlanmaz (o OL10-D / E / F); ama sonraki dokuz alt paketin hepsi bunun üstüne kurulur.

## Ana oturumun hükümleri

1. Tasarım belgesi bağlayıcıdır: sınıflar, basamaklar, anahtarlar, sabitler §2'deki gibi. Kural metniyle Ek B-1'in kuru sayımı çelişirse kural metni geçerlidir; farkı H-A1'in altına yaz, sayıyı tutturmak için kuralı değiştirme.
2. Dosya:satır atıfları main `f2b0db5`'te doğrulandı; o günden beri `headless.py` (P16e) ve ad bağlama dosyaları (PUV6a) değişmiş olabilir: işlev adını `grep -n "def <ad>"` ile yeniden bul.
3. H-A3'te `called_by` karşılaştırması: P16e main'deyse yeni koşularda ham eşitlik beklenir; S8 tabanı (`s8_taban_b6aceb9`) P16e'den önce üretildiği için orada sıra-normal karşılaştır ve hangisini kullandığını yaz.
4. SINAMA ikilileri (docker-compose, iTerm2, llama-server) yalnız H-A6'da, dondurma commit'inden sonra bir kez, yalnız K0 sınıf sayımı için.
5. Ghidra koşusu YOK. Var olan çalışma alanları salt okur.

## Yazabileceğin dosyalar (hepsi yeni)

`karadul/core/tembel_secim.py`, `karadul/core/tembel_girdi.py`, `karadul/core/tembel_xref.py`, `scripts/measurement/tembel_kuru.py`, `tests/test_ol10a_secim.py`, `tests/test_ol10a_xref.py`, `scripts/measurement/mutation_specs_ol10a.json`, `docs/arge/2026-11-19_mythos/olcek/on_kayit_OL10A.md`, `docs/arge/2026-11-19_mythos/olcek/OL10A.md` (ilerleme dosyası).

**Dokunma:** var olan bütün dosyalar (`karadul/config.py`, `karadul/ghidra/`, `karadul/analyzers/`, `karadul/stages.py`, `karadul/pipeline/`); okuyucular yalnız içe aktarılır.

## Sert son

Gönderim iletisinde yazılı.

## Dönüş mesajı

İlk satır gerçek uygulama sayısı: Ollama diliminde sınıf ve basamak sayıları (H-A1 ile aynı mı), seçilebilen küme x / 13 160, xref türetmesi kaç çalışma alanında JSON-eşit (H-A3). Sonra H-A1 … H-A7, okuyucu envanteri (adım 6), test / mutant sayıları, dondurma commit'i, commit listesi, OL10-B / OL10-C / OL10-D için notlar.
