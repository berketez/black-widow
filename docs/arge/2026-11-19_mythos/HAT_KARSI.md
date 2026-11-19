# Hat: KARŞI (karşı görüş ve plan denetimi) — tek tur

Hat dizinin: `docs/arge/2026-11-19_mythos/karsi/`, betikler `scripts/arge/karsi/`, veri `~/karadul_olcum/runs/arge-2026-11-19/karsi/`. Önce `ORTAK_BRIF.md`, `KARARLAR.md`, `YON.md`.

## Neden

Yön kararına itiraz edecek ayrı model (Onuncu Adam) kota yüzünden çalışmadı (`KARARLAR.md` A-5). Üç hat (KİMLİK, ÖZ KOD, ÖLÇÜ) bulgularını ve planlarını yazdı; sonraki oturumda Opus ajanları bu planları olduğu gibi uygulayacak. Uygulanmadan önce birinin onları çürütmeye çalışması gerekiyor. O sensin.

**Görevin onaylamak değil, çatlağı bulmak.** Başlangıç varsayımın: üç hattın ana sonuçları yanlış ya da olduğundan iyi görünüyor, planlar eksik. Bulamadığın çatlağı "bulamadım, şunlara baktım" diye yaz; uydurma itiraz yazma.

## Girdi

- `docs/arge/2026-11-19_mythos/{kimlik,ozkod,olcu}/`: `BULGULAR.md`, `PLAN.md`, `DEFTER.md`; betikler `scripts/arge/{kimlik,ozkod,olcu}/`; çıktılar `~/karadul_olcum/runs/arge-2026-11-19/`.
- Olgu tablosu: `~/karadul_olcum/runs/arge-2026-11-19/olgu/olgu.jsonl.gz` (şema `olgu/SEMA.md`; taban ölçümüyle tutarlılık kapısı tuttu).
- Yayın kapısı ve denetimler: `docs/arge/2026-11-19_yayin/`.
- Onarımın kalanı: `docs/arge/2026-11-18_onarim/gonderim/OKU.md` "2026-11-19 sonrası"; paket metinleri aynı dizinde (`P12d.md`, `P24.md`, …).

## Kalemler (hepsi; zaman kısıtı yok)

1. **Ana iddiaları yeniden türet.** Her hattın en önemli 3–5 sayısını o hattın betiğini kullanmadan, olgu tablosundan ve ham koşu çıktılarından kendi betiğinle yeniden hesapla. Tutmayan her sayı için farkın nedenini bul.
2. **Aşırı uyum ve sızıntı.** Her hatta keşif / sınama bölmesi gerçekten sayılara bakılmadan mı yazıldı (DEFTER'deki sıra ve dosya zamanları)? Sınama tarafı kaç kez görüldü? Kural, sınama tarafı görüldükten sonra değişti mi? "Ölçüm sonrası tanım" diye işaretlenen sonuçlar bulgu gibi mi sunulmuş? Aynı kaynağın iki derlemesi (debian/tmux ↔ mac/tmux) bölmenin iki yanına düşmüş mü?
3. **Çıkarım hataları.** Kâhin (oracle) çapayla ölçülen sayı ürünün ulaşabileceği sayı gibi mi yazılmış? Örnek düzeyi sayı (106 coreutils ikilisindeki tekrar) bağımsız kanıt gibi mi sayılmış? Tek programdan genelleme var mı? Wilson aralıkları doğru birimle mi hesaplanmış?
4. **Yön kararına itiraz.** `YON.md`'yi yanlış varsay: hangi hat boşa gidecek, seçilmeyenlerden hangisi daha çok kazandırırdı? Özellikle şu savı değerlendir: "Geliştirme seti (117 / 119'u Debian 13 AArch64 GCC 14, dinamik bağlı C programı) bu aracın gerçek kullanımını temsil etmiyor; hatlar yanlış nüfusu iyileştiriyor." Gösteri koşusunun bulguları (`YAYIN_KAPISI.md` §5) ve varsa `ustveri/` hattının sayıları bu sav için veri.
5. **Planların uygulanabilirliği.** Her paket yazanı olmadan uygulanabilir mi: dosya yolları ve fonksiyon adları gerçekten var mı (`ls`, `grep` ile doğrula), kabul ölçütü sayısal mı, ön kayıt metni ölçümden önce commit'lenebilir hâlde mi? Eksik olan her paketi adıyla yaz.
6. **Dosya çakışma haritası.** Bütün planların (üç hat + yayın işleri + onarımın kalanı + P24) dokunduğu dosyaları tek tabloda topla; aynı dosyaya değen paketleri işaretle (bunlar aynı anda gönderilemez). Önerilen dalga sırası: hangi paketler birlikte gidebilir.
7. **Yayın önceliği.** Berke yayını erken istiyor. Planlardaki paketlerden hangileri yayından önce şart, hangileri bekleyebilir; gerekçesiyle. Yayın için asıl riskin ne olduğunu tek paragrafta yaz.

## Çıktı

- `KARSI.md`: itirazlar önem sırasıyla; her biri: iddia, kanıt (betik + komut + sayı), önerilen düzeltme (hangi belgenin hangi satırı ya da hangi paketin hangi kalemi).
- `CAKISMA.md`: dosya çakışma haritası ve dalga önerisi.
- `DEFTER.md`, `BERKE.md` (ortak brifteki gibi). `PLAN.md` yazma; düzeltmeleri `KARSI.md`'de öner, hat belgelerini değiştirme.

## Kurallar

- Öbür hatların dosyaları salt okur. Ürün kodu ve ortak ölçüm betikleri salt okur. Ghidra koşma.
- Kilitli setlere ve ÖZ KOD'un "kör" nüfusuna (`~/karadul_olcum/ozkod_nufus/`, `NUFUS.md`'deki "kör" taraf) bakma.
- Her sayı betikten.
