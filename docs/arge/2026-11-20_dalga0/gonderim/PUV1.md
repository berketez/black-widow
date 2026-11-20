# PUV1 — P-ÜV1 Go `pclntab` okuyucu ve üretici adım (üst veri hızlı hattı; KARARLAR A-27)

Önce oku: `docs/arge/2026-11-20_dalga0/ORTAK_D0.md` (kurallar aynen geçerli; §4 tablosu Dalga 0'ındır, bu paketin dosyaları aşağıda), `docs/arge/2026-11-18_onarim/ONARIM_BRIF.md`, `docs/arge/2026-11-19_mythos/KARARLAR.md` (A-10, A-27).

**Neden şimdi.** Bugünkü ürün Ollama diliminde 13 160 fonksiyonun 17'sine ad veriyor; aynı dilimin Go `pclntab`'ında 10 601 ad yazılı. Go kanalı hedef setinde en büyük kazanç (docker-cli 35 048 / 35 048 doğru, araştırma okuyucusuyla).

**Plan.** `docs/arge/2026-11-19_mythos/ustveri/PLAN.md` §0 ve "P-ÜV1" (biçim, kalem 1–7, kabul, ön kayıt metni, sınama ve mutasyon) — aynen uygula. Başvuru betikleri `scripts/arge/ustveri/go_pclntab.py`, `go_say.py` (kopyalama, yeniden yaz). Başvuru verisi `$V` = `~/karadul_olcum/runs/arge-2026-11-19/ustveri` (`go/<ad>.tsv` / `.json`, `hedef/` araştırma kopyaları). Sembollü GT: `~/karadul_olcum/ustveri_set/` (HEDEF paketi; `manifest.json`; docker-cli keşif, docker-compose SINAMA).

**Yazabileceğin dosyalar (hepsi yeni):** `karadul/analyzers/ustveri/go_pclntab.py`, `karadul/pipeline/steps/go_metadata_recovery.py`, `tests/test_puv1_go_pclntab.py`, `tests/test_puv1_adim.py`, `scripts/measurement/mutation_specs_puv1.json`, `docs/arge/2026-11-19_mythos/ustveri/on_kayit_PUV1.md`, `docs/arge/2026-11-19_mythos/ustveri/P-UV1.md` (ilerleme), yama `docs/arge/2026-11-20_dalga0/yamalar/PUV1__config.py.patch`.
**Dokunma:** `karadul/analyzers/ustveri/__init__.py` ve `goruntu.py` (PUV0 paketinin; paralel yazılıyor), var olan Go kodu (`go_binary.py`, `go_demangler.py`, `go_reconstructor.py`), `stages.py`, `config.py`, `_feedback_naming_*.py`. Ghidra koşusu YOK.

## Paralel yazım düzeni (önemli)

- `Goruntu` arayüzü PUV0 paketinde yazılıyor; imzası planda sabit (`ustveri/PLAN.md` "P-ÜV0" kalem 1). Okuyucuyu o arayüze göre yaz; testlerde kendi test dosyanda küçük bir sahte görüntü sınıfı kur (`struct.pack` ile sentetik baytlar; plan §0 test verisi kuralı).
- PUV0 main'e girince ana oturum sana mesaj atacak: o zaman **bir kez** `git rebase main` yap (yalnız bu durumda izinli), gerçek `Goruntu` ile içe aktarımı bağla ve gerçek ikili kabulünü (11 dilim, `$V/go/*.tsv`) koş. Mesaj gelmeden gerçek ikili kabulüne geçme; o sürede sentetik testleri, mutasyonu ve üretici adımı bitir.
- Gerçek `Goruntu` gelmeden önce `karadul/analyzers/ustveri/` paket dizini senin dalında yoksa: test dosyanda içe aktarımı geçici bir koşulla çöz, ama `goruntu.py` ya da `__init__.py` YAZMA (çakışır).

## Bayrak ve INERT

- Üretici adım bayrağı planın dediği gibi okur: `getattr(cfg.binary_reconstruction, "enable_go_metadata_recovery", False) is True`. Alan BAYRAK paketiyle `config.py`'de var ve `INERT_SETTINGS`'te kayıtlı; okuyunca `tests/test_p15a_etkisiz.py` o kaydın silinmesini ister. `config.py`'ye YAZMA: INERT satırını ve alan satırındaki `# ETKİSİZ` yorumunu kaldıran yamayı `docs/arge/2026-11-20_dalga0/yamalar/PUV1__config.py.patch` olarak commit'le; tam takımı yama geçici uygulanmış hâlde koş, sonra geri al (`git diff` temiz). Ana oturum yamayı birleştirirken uygular. Adım Faz 1 listesine bu pakette EKLENMEZ (P-ÜV6).

## Sıra ve sert son

Ön kayıt (planın metni) → okuyucu + sentetik testler → üretici adım + testleri → mutasyon (≥ 10) → (PUV0 gelince) rebase + 11 dilim kabulü + keşif GT (docker-cli) → en son, okuyucu dondurulduktan sonra (dondurma commit'ini yaz) SINAMA GT bir kez (docker-compose) → tam takım.
**15:15'te dur.** Bitmeyen kalemi ilerleme dosyasına "kalan" diye yaz, commit'le, `## PAKET BİTTİ` yazmadan dön.
