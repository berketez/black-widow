# PUV0 — P-ÜV0 ortak ikili görüntü okuyucu (üst veri hızlı hattı; KARARLAR A-27)

Önce oku: `docs/arge/2026-11-20_dalga0/ORTAK_D0.md` (kurallar aynen geçerli; §4 tablosu Dalga 0'ındır, bu paketin dosyaları aşağıda), `docs/arge/2026-11-18_onarim/ONARIM_BRIF.md`, `docs/arge/2026-11-19_mythos/KARARLAR.md` (A-10, A-27).

**Neden şimdi.** Bugünkü ürün hedef setinde terminal-notifier'da ad bekleyen 40 fonksiyonun 0'ına, Ollama diliminde 13 160 fonksiyonun 17'sine ad veriyor; adlar ikilinin üst verisinde yazılı ama ürün okumuyor (A-27: "her şeyi okuyacak"). P-ÜV1 (Go) ve P-ÜV2 (ObjC) senin `Goruntu` arayüzünün üstüne PARALEL yazılıyor; arayüzü plandaki gibi, adı ve imzası değişmeden kur.

**Plan.** `docs/arge/2026-11-19_mythos/ustveri/PLAN.md` §0 (ortak kurallar, test verisi kuralı, taşınacak betikler) ve "P-ÜV0" (kalem 1–7, kabul, ön kayıt metni, sınama ve mutasyon) — aynen uygula. Başvuru betiği `scripts/arge/ustveri/macho.py` (kopyalama, yeniden yaz: hata yolları, sınır denetimleri, durum). Başvuru verisi `$V` = `~/karadul_olcum/runs/arge-2026-11-19/ustveri` (`envanter.json`, `hedef/` araştırma kopyaları).

**Yazabileceğin dosyalar (hepsi yeni):** `karadul/analyzers/ustveri/__init__.py`, `karadul/analyzers/ustveri/goruntu.py`, `tests/test_puv0_goruntu.py`, `scripts/measurement/mutation_specs_puv0.json`, `docs/arge/2026-11-19_mythos/ustveri/on_kayit_PUV0.md`, `docs/arge/2026-11-19_mythos/ustveri/P-UV0.md` (ilerleme dosyası).
**Dokunma:** var olan bütün `karadul/` dosyaları, `scripts/arge/`, `karadul/config.py`. Ghidra koşusu YOK (yalnız dosya baytları). Hedef ikililer yerinde değiştirilmez, çalıştırılmaz; PATH'teki conda araçları yerine `/usr/bin/...`.

## Sıra

1. Ön kayıt (planın metni aynen) → commit (koddan önce).
2. **Önce arayüz** (`Goruntu` soyut sınıfı + `Bag`; plan kalem 1) → ayrı commit, HEMEN (P-ÜV1 / P-ÜV2 ona yaslanıyor).
3. Mach-O 64 + evrensel dosya (kalem 2–3) → ELF 64 (kalem 4) → PE iskeleti (kalem 5) → sağlamlık (kalem 6) → `python -m karadul.analyzers.ustveri.goruntu` özeti (kalem 7).
4. Kabul (18 Mach-O dilimi `$V/envanter.json` ile; 5 ELF bağımsız sayımla), testler (≥ 12), mutasyon (≥ 6), tam takım.

## Sert son

Berke'nin oturumu 16:00'da bitiyor: **15:15'te dur.** O saate kadar bitmeyen kalemi ilerleme dosyasına "kalan" diye yaz, commit'le, `## PAKET BİTTİ` yazmadan dön (dönüş mesajında söyle). Öncelik sırası: arayüz > Mach-O > kabul > testler / mutasyon > ELF > PE.
