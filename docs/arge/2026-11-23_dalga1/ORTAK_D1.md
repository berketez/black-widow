# Uygulama oturumu 2 — ortak brif (2026-11-23)

Bağlayıcılık sırası (çelişkide üstteki geçerli): `docs/arge/2026-11-19_mythos/KARARLAR.md` (A-1 … A-31) → bu brif → `docs/arge/2026-11-20_dalga0/ORTAK_D0.md` → `docs/arge/2026-11-18_onarim/ONARIM_BRIF.md` → hat planı (`docs/arge/2026-11-19_mythos/<hat>/PLAN.md`) → ajan tanımın.

**ORTAK_D0 aynen geçerlidir** (ortam, Ghidra kuyruğu, commit / ön kayıt / mutasyon / tam takım, veri, ilerleme dosyası, dönüş). Bu belge yalnız farkları yazar. İkisini de baştan sona oku.

## 1. Bu oturum

- Berke (2026-11-23 08:0x): planlama Mythos'ta (ana oturum), kodu yazanların hepsi Opus; aynı anda en çok **4** ajan, en çok 1'i Mythos (yalnız tasarım belgesi yazar).
- Taban: main `9c9b2d4` (= origin/main). Tam takım `afeaf62`'de 10 756 geçti / 13 atlandı / 0 kaldı (554 sn, boş makine); o commit'ten beri main'e yalnız belge girdi.
- **Kabul ölçütü gerçek uygulamadadır** (A-17, A-27): her ad paketinin raporunun ilk satırı hedef setindeki sayıdır (terminal-notifier, Ollama dilimi, docker-cli …); geliştirme setinin 119 ikilisi yalnız "geriye gitme yok" denetimidir.

## 2. ORTAK_D0'dan farklar

| Konu | Bu oturumda |
|---|---|
| Koşu çıktıların | `~/karadul_olcum/runs/dalga1-2026-11-23/<PAKET>/` (oluştur). Geçici dosyalar da burada; ortak scratchpad'e yazma |
| Yamalar (listende olmayan dosya) | `docs/arge/2026-11-23_dalga1/yamalar/<PAKET>__<dosya_adı>.patch` (kendi dalında commit'li); gerekçesi ilerleme dosyanda |
| İlerleme dosyası | gönderim metninde yazılı; son satır tam olarak `## PAKET BİTTİ` |
| Ghidra kuyruğu | **iki yuva** (A-31): `~/karadul_olcum/ghidra_kuyruk.sh <PAKET> <etiket> <komut> …`; süre ölçen koşu `--tek` ile. Gündüz süre ölçümü yapılmaz |
| Sabit ürün ağacı (bugünkü ürün) | `~/karadul_olcum/urun-be9550e` (Dalga 0'ın ürün kodu; `be9550e`'den sonra main'e giren ürün kodu yalnız `karadul/analyzers/ustveri/` + iki üretici adım, hepsi bayrak arkasında ve Faz 1'e bağlı değil). Kendi dalının ürününü koşacaksan ORTAK_D0 §3'teki gibi `~/karadul_olcum/urun-<kısa-hash>` ağacı aç; silme |
| S8 tabanı | `~/karadul_olcum/runs/dalga0-2026-11-20/s8_taban_b6aceb9/` ve A/A tekrarı `…/s8_taban_b6aceb9_AA/`. Karşılaştırma aracı `scripts/arge/hiz/s8_esitlik.py`. P16e main'e girene kadar çağıran listeleri sıra-normal karşılaştırılır, ham fark ayrıca yazılır |
| `config.py` | Kimse yazmaz (A-19). Bağlayan paket INERT satırını silen ve alan satırındaki `# ETKİSİZ` yorumunu düzelten yamayı bırakır; **yamayı kendi ağacına UYGULAMAZ** (2026-11-23 08:45: `git apply` izin sınıflayıcısınca reddedildi; `config.py`'yi Edit ile de değiştirme). Yama commit'li kalır; uygulanabilirliği `git apply --check <yama>` ile gösterilir (dosya değişmez). Tam takım yamasız koşulur: o durumda yalnız `tests/test_p15a_etkisiz.py`'nin bağladığın alanlarla ilgili başarısızlığı beklenir (adını ve iletisini ilerleme dosyana yaz); başka kırmızı varsa ayır. Yamayı ana oturum main'e alırken uygular ve tam takımı kendisi koşar |
| Sert son | gönderim metninde saatle yazılı. O saatte dur: bitmeyeni ilerleme dosyasına "kalan" diye yaz, commit'le, dön. `## PAKET BİTTİ` yalnız her şey bittiyse |
| Disk | boş alan 08:05'te 191,8 GB. 10 GB'ı aşacak veri üretmeden önce dur ve bildir |
| Koşu çıktısının ömrü (08:40'tan sonra gönderilen paketler) | Ürün koşusunun çalışma alanları (`ws/`, `out/`, `cache/`) kanıt değil ara üründür. Paket bitince dönüş mesajına koşu kökünün yolunu ve boyutunu (`du -sh`) yaz; ölçüm özetini (sayım JSON'u, ad haritaları, fark tabloları) kökün içinde `ozet/` altına topla. Çalışma alanlarını sen silme: ana oturum bağımsız doğrulamadan sonra `ozet/` dışını siler. 13 Ekim – 23 Kasım arasında bu kökler 103 GB birikmişti |

## 3. Değişmeyenler (hatırlatma; ayrıntı ORTAK_D0)

- Kendi worktree'n; ilk iş `git merge --ff-only main`; `python -c "import karadul; print(karadul.__file__)"` worktree'yi göstermeli; ana ağaca yazma; komutlar worktree kökünden `python -m …`; `PYTHONDONTWRITEBYTECODE=1`; Python `/opt/anaconda3/bin/python`.
- Paket kurma, ağa çıkma, `codex` / `gemini` / başka model CLI'ı, alt ajan açma YASAK.
- Commit kendi dalında, iş kalemi başına bir tane; dosyalar adıyla stage; Türkçe `Kategori: başlık`; `Co-Authored-By` satırı YOK; push / merge / rebase YOK.
- Ön kayıt ölçümden önce ayrı commit. Tutmayan beklenti silinmez, eşik sonradan değişmez.
- Mutasyon: `find` tekil, `replace` farklı uzunlukta, aynı worktree'de eşzamanlı koşu yok, bitince `git diff` temiz.
- Tam takım sonda bir kez: `PYTHONDONTWRITEBYTECODE=1 python -m pytest -q -p no:cacheprovider`.
- Kilitli setler ve ÖK-V'nin kör tarafı açılmaz. **Sınama ikilileri** (docker-compose, iTerm2, llama-server) kural yazarken açılmaz; okuyucu / kural dondurulduktan sonra (dondurma commit'i yazılı) bir kez ölçülür.
- Depo herkese açık: üçüncü taraf ikili, çıkarılmış ad listesi, GT adı commit'lenmez (yalnız sayı ve sha256).
- Sahte veri yok: veri yoksa "veri yok / ölçülmedi" yazılır; tahmin "TAHMİN" etiketli ve aralıklı.
- Hiçbir hedef ikili çalıştırılmaz; PATH'te conda araçları önde, her yerde `/usr/bin/{otool,nm,lipo,strip,strings}` tam yolu.
- Türkçe yaz, Türkçe karakterleri doğru kullan; kod simgeleri İngilizce ya da var olan biçemde.

## 4. Dosya sahipliği (bu oturumun ilk dört paketi; kümeler ayrık)

| Paket | Yazabileceği dosyalar (tam liste gönderim metninde) |
|---|---|
| PUV6a | `karadul/stages.py` (yalnız Faz 1 adım listesi), `karadul/pipeline/steps/{__init__,_feedback_naming_candidates,_feedback_naming_merger}.py`, `karadul/core/naming_labels.py`, etiketi okuyan dosyalar, kendi testleri / betikleri / belgeleri |
| P16e | `karadul/ghidra/headless.py`, kendi testleri / betikleri / belgeleri |
| PUV3 | yalnız yeni dosyalar (`karadul/analyzers/ustveri/swift.py`, `karadul/pipeline/steps/swift_metadata_recovery.py`, …) |
| OL10 | yalnız `docs/arge/2026-11-19_mythos/olcek/OL10_TASARIM.md` |

Sonraki paketlerin sırası ve sahipliği `docs/arge/2026-11-23_dalga1/DURUM.md`'de.
