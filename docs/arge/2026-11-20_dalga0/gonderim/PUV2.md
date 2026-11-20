# PUV2 — P-ÜV2 Objective-C yöntem listesi okuyucu ve üretici adım (üst veri hızlı hattı; KARARLAR A-27, A-28)

Önce oku: `docs/arge/2026-11-20_dalga0/ORTAK_D0.md` (kurallar aynen geçerli; §4 tablosu Dalga 0'ındır, bu paketin dosyaları aşağıda), `docs/arge/2026-11-18_onarim/ONARIM_BRIF.md`, `docs/arge/2026-11-19_mythos/KARARLAR.md` (A-10, A-27, A-28).

**Neden şimdi.** Bugünkü ürün terminal-notifier'da ad bekleyen 40 fonksiyonun 0'ına ad veriyor; araştırma okuyucusu aynı ikilinin ObjC üst verisinden 32 adın 32'sini doğru veriyor. Ghidra yöntemleri yalnız seçiciyle adlandırıyor (Ollama 148 / 151); A-28: tam ad onun yerine yazılabilecek (P-ÜV6 bağlar). Bu paketin çıktısı her yöntem için hem tam adı hem seçiciyi taşımalı (P-ÜV6'nın tutarlılık denetimi seçiciyi Ghidra adıyla karşılaştıracak).

**Plan.** `docs/arge/2026-11-19_mythos/ustveri/PLAN.md` §0 ve "P-ÜV2" (biçim, kalem 1–6, kabul, ön kayıt metni, sınama ve mutasyon) — aynen uygula. Başvuru betiği `scripts/arge/ustveri/objc_meta.py` (kopyalama, yeniden yaz). Başvuru verisi `$V` = `~/karadul_olcum/runs/arge-2026-11-19/ustveri` (`objc/<ad>.tsv` / `.json`, `hedef/` araştırma kopyaları). Sembollü GT: `~/karadul_olcum/ustveri_set/` (HEDEF paketi; terminal-notifier keşif, iTerm2 SINAMA).

**Yazabileceğin dosyalar (hepsi yeni):** `karadul/analyzers/ustveri/objc.py`, `karadul/pipeline/steps/objc_metadata_recovery.py`, `tests/test_puv2_objc.py`, `scripts/measurement/mutation_specs_puv2.json`, `docs/arge/2026-11-19_mythos/ustveri/on_kayit_PUV2.md`, `docs/arge/2026-11-19_mythos/ustveri/P-UV2.md` (ilerleme), yama `docs/arge/2026-11-20_dalga0/yamalar/PUV2__config.py.patch`.
**Dokunma:** `karadul/analyzers/ustveri/__init__.py` ve `goruntu.py` (PUV0 paketinin; paralel yazılıyor), var olan bütün `karadul/` dosyaları (özellikle `swift_binary.py`, `macho.py`, `stages.py`, `config.py`). Ghidra koşusu YOK.

## Paralel yazım düzeni (önemli)

- `Goruntu` arayüzü PUV0 paketinde yazılıyor; imzası planda sabit (`ustveri/PLAN.md` "P-ÜV0" kalem 1). Okuyucuyu o arayüze göre yaz; testlerde kendi test dosyanda küçük bir sahte görüntü sınıfı kur (`struct.pack` ile sentetik baytlar; plan §0 test verisi kuralı). Göreli ofset, zincirli düzeltme gibi işler `Goruntu.gosterici()`'nin; okuyucuda yeniden yazma.
- PUV0 main'e girince ana oturum sana mesaj atacak: o zaman **bir kez** `git rebase main` yap (yalnız bu durumda izinli), gerçek `Goruntu` ile bağla ve gerçek ikili kabulünü (6 hedef, `$V/objc/*.tsv`) koş. Mesaj gelmeden gerçek ikili kabulüne geçme; o sürede sentetik testleri, mutasyonu ve üretici adımı bitir.
- Gerçek `Goruntu` gelmeden önce `karadul/analyzers/ustveri/` paket dizini senin dalında yoksa: test dosyanda içe aktarımı geçici bir koşulla çöz, ama `goruntu.py` ya da `__init__.py` YAZMA (çakışır).

## Bayrak ve INERT

- Üretici adım bayrağı okur: `getattr(cfg.binary_reconstruction, "enable_objc_metadata_recovery", False) is True`. Alan BAYRAK paketiyle `config.py`'de var ve `INERT_SETTINGS`'te kayıtlı; okuyunca `tests/test_p15a_etkisiz.py` o kaydın silinmesini ister. `config.py`'ye YAZMA: INERT satırını ve alan satırındaki `# ETKİSİZ` yorumunu kaldıran yamayı `docs/arge/2026-11-20_dalga0/yamalar/PUV2__config.py.patch` olarak commit'le; tam takımı yama geçici uygulanmış hâlde koş, sonra geri al (`git diff` temiz). Ana oturum yamayı birleştirirken uygular. Adım Faz 1 listesine bu pakette EKLENMEZ (P-ÜV6).

## Sıra ve sert son

Ön kayıt (planın metni) → okuyucu + sentetik testler → üretici adım + testleri → mutasyon (≥ 8) → (PUV0 gelince) rebase + 6 hedef kabulü + keşif GT (terminal-notifier) → en son, okuyucu dondurulduktan sonra (dondurma commit'ini yaz) SINAMA GT bir kez (iTerm2) → tam takım.
**15:15'te dur.** Bitmeyen kalemi ilerleme dosyasına "kalan" diye yaz, commit'le, `## PAKET BİTTİ` yazmadan dön.
