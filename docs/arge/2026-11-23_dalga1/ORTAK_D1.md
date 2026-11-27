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

## 5. Akşam eki (2026-11-23 19:30'dan sonra gönderilen paketler)

- **Taban:** main `152176b` (= origin/main). Tam takım `95d4e3c`'de 10 968 geçti / 18 atlandı / 0 kaldı (670 sn, yük altında); o commit'ten beri main'e yalnız belge girdi. Sabahın yedi paketi (PUV6a, PUV3, PUV4, PUV7, P16e, OL1, OL10 tasarımı) main'de: gönderim metinlerindeki "PUV6a main'e girince" koşulu sağlandı.
- **Bu dilim 6 paket, aynı anda en çok 4:** BA1, PUV5, PK1, OL2 (ilk dört); yer açıldıkça OK1, OL10A. Hepsi Opus.
- **Sabit ürün ağacı (bugünkü ürün):** `~/karadul_olcum/urun-152176b` (main `152176b`; altı bağ kurulu). §2'deki `urun-be9550e` satırı sabah içindir.
- **Ghidra kuyruğu dolu olacak:** ana oturumun Ollama koşusu (`ANA ollama:ba_kapali`) bir yuvayı TAHMİN 1,5–2 saat tutar; PUV5 ve OL2 öbür yuvayı paylaşır. Ghidra'sız yeniden oynatmayla verilebilen her hüküm önce onunla verilir; kuyruğa kod, test ve mutasyon bittikten sonra girilir.
- **ÖL-1'in bekçisi öntanımda açık** (`analysis.cozumleyici_takilma_sn` 600): ürün koşularında çözümleyici 600 sn tepede kalırsa kapatılır ve koşu `kismi` olur; koşunun `ghidra_status.json`'ında görünür. Bunu kendi değişikliğine bağlama.
- **Disk:** boş alan 19:28'de 259,5 GB (kullanılan 706,7 GB).

| Paket | Yazabileceği dosyalar (tam liste gönderim metninde) |
|---|---|
| BA1 | `karadul/reconstruction/engineering/block_annotator.py`, kendi testleri / betikleri / belgeleri |
| PUV5 | `karadul/stages.py` (yalnız `_recover_main_from_entry` ve yardımcıları), kendi testleri / belgeleri |
| PK1 | `karadul/pipeline/steps/_feedback_naming_{bindiff,refdiff}.py`, `_feedback_naming_candidates.py` (yalnız `_add_bindiff`, `_add_refdiff`), yeni `karadul/reconstruction/kimlik/` |
| OL2 | `karadul/ghidra/headless.py` (döküm işlevleri + BSim bloğu), `karadul/ghidra/bsim.py` |
| OK1 | `karadul/reconstruction/c_namer.py` (yalnız `_strategy_string_context`), iki `alt_kanal.py` (yalnız `_is_own_name`) |
| OL10A | yalnız yeni dosyalar (`karadul/core/tembel_*.py`, …) |

## 6. 24 Kasım eki (2026-11-24'te gönderilen paketler)

Dalga 1 aynı klasörde sürüyor: koşu kökün `~/karadul_olcum/runs/dalga1-2026-11-23/<PAKET>/`, yamalar `docs/arge/2026-11-23_dalga1/yamalar/`. §5'teki "taban", "bu dilim", "sabit ürün ağacı" ve "Ghidra kuyruğu" satırlarının yerine bunlar geçerlidir:

- **Taban:** main `534e252b`. Tam takım `b536414d`'de 11 168 geçti / 23 atlandı / 0 kaldı (577 sn); o commit'ten beri main'e yalnız belge girdi. Dün akşam main'e girenler: PK1, BA1, OK1 (P12d etkin; `oz_ad_verbatim` kapalı), OL10A, PUV5 (bayrak kapalı), OL2.
- **Öntanımlar dün değişti (OL2):** `timeouts.ghidra_adim` 3 600 sn, `bsim.bos_depoda_sorgu_atla` açık, `bsim.ingest_butcesi_sn` 900. Taze `KARADUL_CACHE_DIR` ile koşulan ilk ikilide BSim sorgusu atlanır (`bsim_status: atlandi`): kendi değişikliğine bağlama.
- **S8 tabanı YENİ:** `~/karadul_olcum/runs/dalga1-2026-11-23/ANA/s8_taban_534e252b/` (son main'in ürünü; kökte `BITTI` dosyası olunca tamamdır; 2026-11-24 13:10'da başladı). Eski tabanlar (`P16e/s8_sonra_3`, `s8_taban_b6aceb9`) artık geçerli değil: P12d `oz_ad` adlarını, OL2 BSim durum alanlarını değiştirdi.
- **Sabit ürün ağacı (bugünkü ürün):** `~/karadul_olcum/urun-534e252b`.
- **Bu dilim 7 paket, aynı anda en çok 4:** OL4, PUV6b, BA2, HZ2 (ilk dört); yer açıldıkça GS1 (OL4'ten sonra), PUV6c (PUV6b'den sonra), HZ7a (BA2'den sonra). Hepsi Opus.
- **Ghidra kuyruğu:** ana oturumun Ollama kabul koşusu (`ANA ollama:kabul`) bir yuvayı TAHMİN 1,5–2,5 saat tutar; S8 tabanı öbür yuvada ≈ 13:40'a kadar. Kuyruğa kod, test ve mutasyon bittikten sonra gir.
- **Worktree'de eksik çalışma verisi:** tam takımda `vendor`, `scripts/node_modules`, `sigs`, `signatures*.json`, `sigs_macos_system.json`, `signatures.lmdb` bağları yoksa 4–7 test ortam yüzünden kalır (dün dört ajanda görüldü). Tam takımdan ÖNCE geçici symlink kur (ana ağaçtaki aynı adlara), commit'leme, bitince kaldır.
- **Mutasyon tanımları:** dokunduğun dosyaya bakan ESKİ tanımları da yeniden koş (`grep -l '"<dosya yolu>"' scripts/measurement/mutation_specs_*.json`); dün iki paket bunu atladı ve üç tanım bayatladı. Bayatlayan `find` metnini kendi paketinde düzelt (yalnız `find` / `replace` metni) ve yaz.
- **Disk:** boş alan 13:09'da 244,6 GB (kullanılan 721,6 GB).

| Paket | Yazabileceği dosyalar (tam liste gönderim metninde) |
|---|---|
| OL4 | `karadul/cli.py` (yalnız `analyze`), `karadul/cli_common.py`, `ui/server.py` (yalnız `_job_progress` ve yardımcıları), yeni `karadul/core/ilerleme.py` |
| PUV6b | `karadul/stages.py` (yalnız Faz 1 adım listesi), `karadul/pipeline/steps/{__init__,_feedback_naming_candidates,_feedback_naming_merger}.py`, `karadul/core/naming_labels.py`, `karadul/core/output_formatter.py`, `karadul/analyzers/ustveri/` (yalnız durum sabitleri) |
| BA2 | `karadul/reconstruction/c_namer.py` (yalnız kalıp satırları), `recovery_layers/constraint_solver.py`, taramada bulunan ve başka paketin listesinde olmayan dosyalarda yalnız kalıp satırları, yeni `scripts/measurement/kalip_denetimi.py` |
| HZ2 | `karadul/ghidra/bsim.py` |


## 7. 27 Kasım eki (2026-11-27'de gönderilen paketler)

§6'daki "taban", "S8 tabanı", "sabit ürün ağacı", "bu dilim" ve "Ghidra kuyruğu" satırlarının yerine bunlar geçerlidir; §6'nın kalanı (eksik çalışma verisi bağları, eski mutasyon tanımları) aynen.

- **Taban:** main `9062436e` (ürün kodu commit'i `ed28e36b`; ondan sonra main'e yalnız belge girdi). Tam takım `ed28e36b`'de 11 321 geçti / 26 atlandı / 0 kaldı (585 sn). 24 Kasım'da main'e girenler: BA2, OL4, PUV6b, HZ2, HZ4a (kod) + GK-0, ÇA-0 (tasarım belgesi). Gönderim metinlerindeki "… çalışıyor / çalışıyor olabilir" notları bayat: o paketlerin hepsi bitti ve main'de. Dosya listeleri ve "Dokunma" satırları aynen geçerli.
- **Öntanımlar 24 Kasım'da değişti:** `bsim.paralel_tarama` açık (her koşuda `bsim_detail.scan_mode` alanı), `analysis.dokum_tek_gecis` açık, `analyze` ilerleme olaylarını `--verbose` olmadan da basıyor. Bunları kendi değişikliğine bağlama.
- **S8 tabanı YENİ:** `~/karadul_olcum/runs/dalga1-2026-11-23/ANA/s8_taban_ed28e36b/` (2026-11-27 22:2x'te başladı; kökte `BITTI` dosyası olunca tamamdır, TAHMİN 22:55). **Gönderim metninde `s8_taban_534e252b` yazan her yerde bunu kullan:** eskisi `scan_mode` alanı yüzünden bayat. `BITTI` yokken tabanla kıyas yapma; bekle.
- **Sabit ürün ağacı (bugünkü ürün):** `~/karadul_olcum/urun-ed28e36b`.
- **Bu dilim 3 paket, aynı anda en çok 3** (Berke, 27 Kasım 22:1x): GS1, HZ7a, PUV6c. Üçü de Opus. Dosya kümeleri ayrık (aşağıdaki tablo).
- **Ghidra kuyruğu:** ana oturumun S8 tabanı bir yuvayı ≈ 22:55'e kadar tutar. Sarmalayıcı sıra tutmuyor (24 Kasım'da iki kez açlık oldu): uzun tek koşun 10 dakikadan fazla başlayamazsa ilerleme dosyana yaz ve bekle; bekletme dosyasını sen koyma.
- **Süre ölçümü:** saat geç ama üç ajan birlikte çalışıyor: her süre hükmü "yük altında" etiketli ve `uptime` künyeli; kesin oran HZ-9'da.
- **Disk:** boş alan 22:18'de 194,6 GB (kullanılan 772,7 GB).

| Paket | Yazabileceği dosyalar (tam liste gönderim metninde) |
|---|---|
| GS1 | `karadul/pipeline/runner.py`, `karadul/core/pipeline.py`, `karadul/core/ilerleme.py`, `ui/server.py` (yalnız iptal + `_job_progress`'in yeni alanı), `ui/index.html` |
| HZ7a | `karadul/reconstruction/c_namer.py` (yalnız `_strategy_dataflow`, `_strategy_local_var_naming` ve yardımcıları), `karadul/reconstruction/api_param_db.py` |
| PUV6c | `karadul/pipeline/steps/{_feedback_naming_candidates,_feedback_naming_merger,go_metadata_recovery}.py`, `karadul/analyzers/ustveri/{go_pclntab,tutarlilik}.py`, `karadul/core/naming_labels.py`, `karadul/stages.py` (yalnız hüküm 5), rapora uyarıyı taşıyan tek dosya |

Eski mutasyon tanım dosyalarında (`scripts/measurement/mutation_specs_*.json`) yalnız kendi dokunduğun ürün dosyasına bakan mutantın `find` / `replace` metnini düzelt; başka paketin dosyasına bakan mutanta dokunma, yalnız bildir.
