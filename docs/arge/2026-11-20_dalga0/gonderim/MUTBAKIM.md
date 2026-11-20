# MUTBAKIM — 9 bayat mutasyon tanımının bakımı

Önce oku: `docs/arge/2026-11-20_dalga0/ORTAK_D0.md`, `docs/arge/2026-11-18_onarim/ONARIM_BRIF.md` (§4 d).

**Kaynak.** `docs/arge/2026-11-18_onarim/gonderim/OKU.md` "Sonra — mutasyon tanımı bakımı" (2026-11-19 toplu koşusu, main koduyla, P-S4 / P12c / P05c / P22c birleştikten sonra): p20 25 öldü / **1 hayatta**; ps1 33 / 1 hata; adim3_hat 47 / 3 hata; p13a 21 / **1 hayatta**; p12a 14 / 1 hata; ad_gecerliligi 51 / 2 hata; adim3_c_namer 19 / **1 hayatta** / 1 hata; p05 16 / 4 hata; adim3_ui 27 / 3 hata. Ana oturumun bugünkü son doğrulama koşusu (başka tanımlar): `~/karadul_olcum/runs/dalga0-2026-11-20/son_dogrulama/`.

**Yazabileceğin dosyalar.** `scripts/measurement/mutation_specs_{p20,ps1,adim3_hat,p13a,p12a,ad_gecerliligi,adim3_c_namer,p05,adim3_ui}.json`; yeni `tests/test_mutbakim_<tanım>.py` (yalnız gerçek test açığı için); ilerleme `docs/arge/2026-11-20_dalga0/MUTBAKIM.md`.
**Dokunma.** Ürün kodu, var olan test dosyaları, öbür tanımlar. Ghidra yok.

## Kalemler (tanım başına; her tanım ayrı commit)

1. Worktree'nde (ff-merge sonrası main kodu) tanımı koş; OKU.md'deki sonuçla karşılaştır.
2. **"hata"** (find eşleşmiyor ya da birden çok eşleşiyor) = kod değişmiş. Mutantın NİYETİNİ (hangi davranışı bozuyor, hangi test yakalamalı) koru; `find` / `replace`'i yeni koda göre güncelle (tekil, farklı uzunluk). Niyet artık anlamsızsa (kod silinmiş, davranış bilinçli değişmiş) mutantı kaldır; gerekçe olarak kodu değiştiren commit'i yaz (`git log -S '<eski metin>' --oneline`).
3. **"hayatta"**: bayat mı (mutant ölü koda düşüyor ya da davranış bilinçli değişti) yoksa gerçek test açığı mı, ayır. Gerçek açıksa en küçük kilitleyici testi yeni dosyaya yaz (eski kodda yeşil, mutantla kırmızı). Bayatsa tanımı güncelle. Her hayatta mutant için kararı ve kanıtı ilerleme dosyasına yaz.
4. Sonda 9 tanımın hepsi: öldü = toplam, hata 0, hayatta 0. Tam takım 0 hata.

## Kabul

9 / 9 tanım temiz; her değişikliğin gerekçesi ilerleme dosyasında; yeni testler eski kodda yeşil. Süre hedefi 60–90 dk.
