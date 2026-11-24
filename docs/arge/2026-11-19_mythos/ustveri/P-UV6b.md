# P-ÜV6b — Swift ad kanalı + C++ RTTI kanıt satırı (ilerleme)

Gönderim metni: `docs/arge/2026-11-23_dalga1/gonderim/PUV6b.md`. Ajan: Opus 5.5. Başlangıç 2026-11-24 13:13 (taban main
`cfe93ce`, `git merge --ff-only main` ile). Sert son 15:05.

Koşu kökü: `~/karadul_olcum/runs/dalga1-2026-11-23/PUV6b/` (özetler `ozet/`, ölçüm betikleri `betik/`).

## Durum

| Kalem | Durum | Commit |
|---|---|---|
| 1 ön kayıt | bitti | `46a722c` |
| 2 kod + testler + mutasyon → dondurma | bitti: 25 test, puv6b 18 / 18 mutant öldü | `28427fb`, `d71b939`, `2ff758c`, dondurma `d94ee20` |
| 3 Ghidra'sız yeniden oynatma (H3, H4, kanal sayıları) | bitti: H3 TUTTU (2 627 / 2 627); H4 TUTMADI (sayı 7 053 aralık dışı; ad 0 tuttu) | `010971e` (Swift satırı), `3872242` |
| 4 ürün koşuları (H1, H2, H6) | bitti: 19 koşu, 19 / 19 çıkış 0; H1, H2, H6 TUTTU | `6055442`, `99ff7e3`, bu commit |
| 5 eski mutasyon tanımları + tam takım (yamasız) | bitti: 172 öldü / 0 hayatta / 3 hata (bayrak; config.py, bu paketin değil); tam takım 11 193 / 23 / 0 | `6055442` |

## Tasarım (koddan)

- **Kaynak adları** (`naming_labels`): `SOURCE_SWIFT_TYPE = "swift_type_accessor"` (`METADATA_SOURCES`'ta; HEDEF ölçüm
  aracının `KANAL_SWIFT` adıyla aynı), `SOURCE_RTTI = "rtti"` (yeni `METADATA_EVIDENCE_SOURCES`: ad yazmayan üst veri
  kaynağı). `UNMEASURED_SOURCES = K4 − METADATA_SOURCES − METADATA_EVIDENCE_SOURCES` → RTTI çıktı (ad yazmadığı için
  güveni de yok; köken kaydında `unmeasured_sources` olarak görünmez).
- **Swift kanalı** (`_add_swift_types`): üretici durumu PUV6a'nın `_metadata_gate`'inden (yapıt yok → `desteklenmiyor`,
  `kapali`, `tutarsiz` aynen, kayıt yok → `veri_yok`). Tip kaydında `ad_yazilabilir is True` değilse kanıt satırı
  (`ad_yazilamaz`; `kisa_ad`, `alt_kume`, `ad_neden` kanıtta). Yazılabilir tipin erişim fonksiyonu adresi `key_for`
  (yalnız Ghidra'nın adsız fonksiyonu; A-28 istisnası yok) → `_add_metadata_candidate`: özgün ad `t["ad"]`
  (= `type metadata accessor for <nitelikli_ad>`, okuyucunun yazdığı, HEDEF kuralıyla birebir), tanımlayıcı
  `c_identifier` (Go / ObjC ile aynı), güven tablodan; tablo satırı yoksa (`kanalın kesinliği ölçülmedi`) ya da alt
  sınır `AD_ESIGI`'nin altındaysa kayıt `esik_alti` kanıt satırı (kod tablodan okur; elle dal yok). Bütün `swift_slots`
  kayıtları (vtable / geçersiz kılma / tanık) kanıt satırı `swift_yuva` (`yuva`, `tip`, `sira`, `yontem_turu`,
  `ust_tip`, `ust_sira`, `protokol`); adressiz yuva yalnız sayılır.
- **RTTI** (`_add_rtti`): ad üretmez. `rtti_classes_path` (`static/rtti_classes.json`) `islevler[]` → her işlev bir kanıt
  satırı `rtti_yuva`: `karar`, `yerler` (`vtable` onaltılık + `sira`), `sinif` (yalnız `belirsiz` değilse) ya da
  `siniflar` (belirsizde), Ghidra adı varsa `ghidra_adi`. Sayaçlar `kayit`, `kanit_satiri`, karar başına, `aday` = 0.
  Üretici durumu demet `(durum, neden)`: `_producer_status` demeti de okur. Yapıt yoksa `desteklenmiyor` (P13b testi
  aynen geçiyor). Bayrak adı `enable_rtti_naming` kaldı; anlamı "RTTI kanıtını köken kaydına yaz" (yorum yamada).
- **Birleştirici** (`k4_inputs`): `swift_types`, `swift_slots`, `swift_status`, `rtti_classes_path` eklendi (başka
  değişiklik yok). Kanıt satırları PUV6a'nın `ust_veri_kanit` listesine gider.
- **Faz 1** (`stages.py`): `swift_metadata_recovery`, `rtti_recovery` → `objc_metadata_recovery`'den sonra,
  `type_recovery_consumer`'dan önce; `steps/__init__.py` kaydı.
- **ObjC güven satırı:** `(33611, 33885, 0.9909)` (P-UV6a H8 ürün düzeyi aday ölçümü); alt sınır `baglama.wilson`
  (0,990903 → aşağı 4 basamak 0,9909); test yeniden hesaplar. Eşik `AD_ESIGI` içe aktarılır.
- **Durum sabitleri:** `DURUM_TUTARSIZ`, `DURUM_KAPALI` `goruntu.py`'de; dört modül içe aktarır.
- **output_formatter:** değişmedi (`_merger_metadata_records` kaynağı `ust_veri_kanali` alanından adıyla okuyor; test
  `test_output_formatter_recognizes_swift_source`).

## Yama

`docs/arge/2026-11-23_dalga1/yamalar/PUV6b__config.py.patch`: `enable_swift_metadata_naming` INERT satırı silinir; dört
alanın yorumu (`enable_swift_metadata_naming`, `enable_swift_metadata_recovery`, `enable_rtti_recovery`,
`enable_rtti_naming`) güncellenir. Öntanımlar değişmez. `git apply --check` temiz; ağaca uygulanmadı (A-34).
Not: yamasız dalda `test_p15a_etkisiz` yeşil kaldı (alan adı `K4_CHANNEL_FLAGS` dizgisinde; `_reads` öznitelik
erişimi arar — PUV6a'daki gibi). Beklenen "tek kırmızı" bu pakette yok.

## Testler ve mutasyon

- `tests/test_puv6b_baglama.py`: 25 test (parametrelerle 28 koşu).
- `scripts/measurement/mutation_specs_puv6b.json`: **18 / 18 öldü** (ilk koşuda iki bayrak mutantı hayatta kaldı:
  bütün bayraklar kapalıyken `add_k4_channels` erken döner, Swift / RTTI satırına hiç inilmiyordu → "başka kanal açık,
  Swift / RTTI kapalı" testi eklendi; ikisi de öldü). Günlük `PUV6b/ozet/mutasyon_puv6b.log`.
- Bayatlayan eski tanımlar (yalnız find / replace düzeltildi): `p13b_k2_birlestirici_k4_yok` (bilinen),
  `p13b_k4_rtti_yalan_veri_yok` (denetim `_metadata_gate`'e taşındı), `p12a_olculmemis_sayi` / `p12a_nokta_tahmini`
  (find iki yerde: PUV6a'nın `metadata_confidence`'ı aynı satırı taşıyor), `adim3_hat stages_ks1_main_den_once`
  (PUV5'in çağrı satırı). Denetim betiği `PUV6b/betik/bayat_denetle.py`: dokunulan 10 dosyaya bakan 22 tanım
  dosyasında find tekilliği 1.
- İlgili 26 test dosyası (dondurmadan önce): 727 geçti / 12 atlandı; tek kırmızı `test_olcum_araci_d0::
  test_siniflayici_denetle_durumlar` (commit'siz çalışma dosyası farkı; PUV6a'da da görüldü, commit'ten sonra geçer).

## Dondurma (H3 / H4'ten önce)

Dondurma commit'i: **bu commit** (üst `2ff758c`). Bu commit'ten sonra SINAMA ölçümüne (H3, H4) dek aşağıdaki dosyaların
kural yolları değişmez; H3 ve H4 birer kez ölçülür. H3'ten sonra `naming_labels.py`'ye yalnız Swift tablo satırı
(ölçülen sayı) girer.

| Dosya | sha256 (ilk 16) | Dondurulan kural |
|---|---|---|
| `karadul/pipeline/steps/_feedback_naming_candidates.py` | `4c291ed530924bbb` | `_swift_rejections`, `_swift_addr`, `_add_swift_types`, `_add_rtti`, `_metadata_gate` |
| `karadul/pipeline/steps/_feedback_naming_merger.py` | `704633ea3572e608` | `k4_inputs`, köken kaydı |
| `karadul/core/naming_labels.py` | `6c8ca2c1591927bf` | kaynak adları, tablo, `metadata_writes_names` |
| `karadul/analyzers/ustveri/swift.py` | `ca8b379f32d407a7` | okuyucu (P-ÜV3 dondurması + yalnız durum sabiti içe aktarımı) |
| `karadul/analyzers/ustveri/cpp_rtti_tara.py` | `261b0c46b06c96f6` | tarayıcı (P-ÜV4 + yalnız durum sabiti) |
| `karadul/pipeline/steps/swift_metadata_recovery.py` | `005405cf3a9430bb` | üretici adım (değişmedi) |
| `karadul/pipeline/steps/rtti_recovery.py` | `7ba45f8c85ffad7b` | üretici adım (değişmedi) |
| `PUV6b/betik/olc_h3_h4.py` (koşu kökü, commit'lenmez) | `058247799da82190` | H3 / H4 ölçüm betiği |

Betiğin kuru denemesi keşif ikililerinde (terminal-notifier Swift `veri_yok`; docker-cli RTTI `veri_yok`) kod yollarını
geçti; sınama ikilileri açılmadı.

## Kalem 3 — SINAMA ölçümleri (dondurma `d94ee20`'dan sonra, birer kez; ağaç `~/karadul_olcum/urun-d94ee206`)

Betik `PUV6b/betik/olc_h3_h4.py` (sha256 ilk 16 `058247799da82190`, dondurma tablosundakiyle aynı; koşudan hemen önce
denetlendi). Çıktılar `PUV6b/ozet/h3_iTerm2_swift.json`, `PUV6b/ozet/h4_llama-server_rtti.json` (yalnız sayı).
Yük altında (load 26–28).

### H3 — Swift, iTerm2 arm64 (soyulmuş, sha256 ilk 12 `4c3e96a2593d`; 13:34:56–13:34:57) → TUTTU

| Üretici | Tip | Yuva | Elenen (`ad_yazilamaz`) | Aday | Doğru | Yanlış | GT'siz | Yazım | Kesinlik (Wilson %95) |
|---|---|---|---|---|---|---|---|---|---|
| `calisti` | 3 659 | 13 807 | 1 032 | **2 627** | **2 627** | **0** | 0 | `demangle` 2 627 | %100 (alt 0,99854) |

- Yanlış oranı %0 ≤ %1, alt sınır 0,99854 ≥ `AD_ESIGI` (0,90909) → **TUTTU**. Aday sayısı (ilk ölçüm) 2 627 =
  okuyucunun ad verdiği tip sayısı (P-UV3). Elenen 1 032 tip kanıt satırı olur (ad uydurulmaz).
- Tabloya `(2627, 2627, 0.9985)` girdi (`010971e`; `baglama.wilson` alt sınırı 0,998540 → aşağı 4 basamak). A-14:
  Swift'te GT'li program 1 (iTerm2) → bayrak öntanımda kapalı kalır.

### H4 — RTTI, llama-server arm64 (soyulmuş, sha256 ilk 12 `6ae2d57c0dae`; 13:35:03) → TUTMADI (sayı) / ad 0 TUTTU

| Üretici | typeinfo | vtable | Ayrık işlev | Bağlı (`tek_sinif` 6 931 + `en_taban_sinif` 80) | `belirsiz` | Kanıt satırı | Belirsizde sınıf adı | RTTI kaynaklı aday |
|---|---|---|---|---|---|---|---|---|
| `calisti` | 1 994 | 1 317 | 7 053 | 7 011 | 42 | **7 053** | 0 | **0** |

- Ön kayıt "kanıt satırı 6 990 ± 42" → aralık [6 948, 7 032]; ölçülen **7 053** aralık dışında (21 fazla): **TUTMADI**
  (eşik değiştirilmedi). Neden (ölçümden sonra okundu): 6 990 sayısı P-UV4.md satır 158'de "ürün bağı (belirsiz
  hariç)" satırının GT'ye göre DOĞRU sayısıdır (6 990 / 7 011); kanıt satırı ise her ayrık işlev için bir satırdır
  (7 011 bağlı + 42 belirsiz = 7 053 = P-UV4 satır 145'teki okuyucu sayısı). Kanal hiçbir işlevi düşürmüyor; ön kayıttaki
  sayı yanlış nicelikten alınmıştı. Bağlı satır sayısı 7 011 aralığın içinde.
- **RTTI kaynaklı ad 0** (tuttu); belirsiz 42 satırın hiçbirinde sınıf adı yok (`siniflar` listesi yazıldı).

### Ghidra'sız yeniden oynatma — var olan çalışma alanları (ağaç `urun-010971e0`; `PUV6b/betik/oynat_puv6b.py`)

| Çalışma alanı | Swift | RTTI | RTTI kaynaklı aday |
|---|---|---|---|
| Ollama (`ANA/ollama_ustveri/ws`, `Ollama_arm64`, 13 559 Ghidra fonksiyonu) | `veri_yok` (Swift bölümü yok) | `calisti`: 68 işlev → 68 kanıt satırı (`tek_sinif` 65, `en_taban_sinif` 3) | 0 |
| terminal-notifier (`PUV6a/urun/acik2`) | `veri_yok` | `veri_yok` (Itanium typeinfo yok) | 0 |

Çıktılar `PUV6b/ozet/oynat_{ollama,terminal-notifier}.json`.

Bekleme: ürün koşuları kuyrukta (13:36'da başladı; ANA Ollama kabul koşusu bir yuvayı tutuyor, öbüründe OL4 / HZ2 / BA2
sırada). TAHMİN bitiş 14:30–15:00; 15:05'e yetişmeyen koşu "kalan" yazılır.

## Kalem 5 — eski mutasyon tanımları ve tam takım

Dokunulan dosyalara bakan tanımlar (kod `3872242`; günlükler `PUV6b/ozet/mutasyon_<ad>.log`, özet
`PUV6b/ozet/mutasyon_eski.txt`); her koşudan sonra `git diff` temiz:

| Tanım | Sonuç |
|---|---|
| puv6a | 20 / 20 öldü |
| puv3 | 18 / 18 |
| puv4 | 16 / 16 |
| p13b (iki find düzeltildi) | 23 / 23 |
| puv0 | 17 / 17 |
| puv1 | 19 / 19 |
| puv2 | 16 / 16 |
| pk1 | 11 / 11 |
| puv5 | 15 / 15 |
| p12a_olculmemis_sayi, p12a_nokta_tahmini (find düzeltildi) | 1 / 1, 1 / 1 |
| adim3_hat stages_ks1_main_den_once (find düzeltildi) | 1 / 1 |
| bayrak | 11 öldü, **3 hata**: `m01_bayrak_ontanimi_acik`, `m04_alan_turu_degisir`, `m10_butce_ontanimi_plan_degeri` — üçü de `karadul/config.py`'deki INERT satırlarını arıyor (`oz_ad_verbatim … ÖK-1 bağlayacak`, `ghidra_adim … ÖL-2`, `ingest_butcesi_sn … ÖL-2`); o satırlar ÖK-1 / ÖL-2 yamalarıyla main'de değişti. Bu paketin dosyası değil (config.py'ye yazılmaz): MUTBAKIM'a not |

**Tam takım (yamasız; 13:46–13:58, 717 sn, yük altında, load 9–21; kod `3872242`): 11 193 geçti / 23 atlandı / 0 kaldı**
(152 seçim dışı). Günlük `PUV6b/ozet/tam_takim.log`. Beklenen `test_p15a_etkisiz` kırmızısı çıkmadı: alan adı
`K4_CHANNEL_FLAGS` dizgisinde okunuyor, `_reads` öznitelik erişimi arıyor (PUV6a'da da böyleydi); yama uygulanınca
INERT kaydı kalkar, `test_every_unread_field_is_registered` dizgi değişmezini bulduğu için yine yeşil kalır (yamalı
kopyada koşulmadı: worktree dışı kopya kurulmadı, gerekçe bu satır). Eksik çalışma verisi bağları (`vendor`, `sigs`,
`scripts/node_modules`, `sigs_macos_system.json`, `signatures.lmdb`, `signatures_homebrew*.json`) tam takımdan önce
kuruldu, sonra kaldırıldı.

## Kalem 4 — ürün koşuları (ağaç `~/karadul_olcum/urun-010971e0`: dondurma + Swift tablo satırı)

Sıra sapması (gerekçeli): gönderimdeki sıra "kapalı 5 → açık 6 → terminal-notifier, Rectangle". Kuyruğun bir yuvası
ANA Ollama koşusunda, öbürü HZ2 / OL4 / BA2 ile paylaşılıyordu; sert sona yetişmeme riskine karşı kabul ölçütünün
(A-17) sayıları (H6) önce koşuldu. İlk zincir (`urun-d94ee206`, Swift satırı yokken) kuyrukta beklerken durduruldu
(hiç koşmadı): o ağaçta Swift kanalı tablo satırı olmadığı için ad yazmazdı. Yaml `PUV6b/bayraklar_acik.yaml`: sekiz
üst veri bayrağı (Go / ObjC / Swift / RTTI üretici + ad) `true`, başka ayar yok. Yamasız dalda
`enable_swift_metadata_naming` için "etkisiz" uyarısı basılır, değer okunur.

### H6 — hedef seti, bayraklar açık → TUTTU

| İkili | Koşu | Üst veri adı (`naming_map` ∧ `out/src`) | GT'ye göre | `ozgun_ad` dolu / güven tablodan / `kesin` | Kanal sayaçları | Kanıt satırı |
|---|---|---|---|---|---|---|
| terminal-notifier (soyulmuş) | 13:45:38–13:46:34 (56 sn) | ObjC **32 / 32** (A-28 31 + adsız 1); Swift `veri_yok`; RTTI `veri_yok` | 32 doğru / 0 yanlış / 0 GT'siz | 32 / 32 / 0 | `objc_method` kayıt 32, `secici_yerine` 31, `tuttu` 1, aday 32 | 0 |
| Rectangle arm64 (soyulmuş, GT yok, sha256 ilk 12 `a38996c976e1`) | 13:46:34–13:52:40 (366 sn) | Swift **180** (kodda 180); ObjC 127 (kodda 127) | ölçülmedi (GT yok) | Swift 180 / 180 / 0; ObjC 127 / 127 / 0 | `swift_type_accessor` kayıt 186, `tuttu` 180, aday 180, `ad_yazilamaz` 6, `yuva_kanit` 226, `yuva_adressiz` 926; `objc_method` kayıt 450, `secici_yerine` 127, `swift_kopru` 323 | Swift yuva 226 + ad verilemeyen tip 6; ObjC `swift_kopru` 323 |

- terminal-notifier: ObjC adı 32 / 32 kaldı (geriye gitme yok); ad bekleyen 40'ta doğru 1 / 40 (PUV6a ile aynı; c_namer 0
  + üst veri 1). Güven artık ürün düzeyi ObjC satırından (0,9909).
- Rectangle: okuyucunun ad verdiği 180 tipin 180'i adlandı (ilk ölçüm). 926 Swift yuvasının adresi yok (uygulama adresi
  çözülmemiş ya da dış): kanıt satırı olarak yazılmadı, yalnız sayıldı — sonraki paket için not.
- Adım süreleri (yük altında): terminal-notifier Swift 0,033 / RTTI 0,033 sn; Rectangle Swift 0,299 / RTTI 0,859 sn.
- Çıktılar `PUV6b/ozet/{urun_terminal-notifier,h6_terminal-notifier,h6_Rectangle,h6_kanit_sayilari}.json`.

### H5 → TUTTU (bu koşularda)

Üst veri kaynaklı hiçbir ad `kesin` taşımıyor (terminal-notifier 0, Rectangle 0); Swift adlarının 180 / 180'i
`üst veriden`, `ozgun_ad` dolu, güven tablodan (0,9985). Birim testi + mutant `puv6b_etiket_kesin`.

### H1 — bayraklar kapalı, S8'in 5 ikilisi ↔ `ANA/s8_taban_534e252b` (`urun_kos.py`, aynı komut ve sıra; 13:52–14:04, yük altında) → TUTTU

| İkili | `naming_map` (out / src / src_iter1) | `decompiled/*.c` fark / dosya | `out/src` fark / dosya | `swift_metadata_recovery` / `rtti_recovery` süresi (sn) |
|---|---|---|---|---|
| debian/coreutils/cat | bayt aynı / aynı / aynı | 0 / 296 | 1 / 138 | 0,0 / 0,0 |
| debian/tree/tree | aynı / aynı / aynı | 0 / 250 | 1 / 145 | 0,0 / 0,0 |
| debian/sqlite3/sqlite3 | aynı / aynı / aynı | 0 / 1 144 | 1 / 458 | 0,0 / 0,0 |
| debian/zstd/zstd | aynı / aynı / aynı | 0 / 1 444 | 1 / 1 119 | 0,0 / 0,0 |
| mac/tmux | aynı / aynı / aynı | 0 / 2 821 | 1 / 2 633 | 0,0 / 0,0 |

- `out/src`'deki tek farklı dosya beş ikilide de `compile_commands.json`: yalnız mutlak çalışma alanı yolu (kök ve zaman
  damgası); yol normalleştirilince 5 / 5 eşit (`PUV6b/ozet/h1_compile_commands.txt`). Taban kökünden gelen yol farkı,
  ürün kodundan değil.
- İki yeni adımın süresi (koşucunun `<adım>_duration_s` kaydı, 4 basamak) 5 / 5 ikilide 0,0 sn ≤ 0,1 sn; iki kanal
  `kapali`. Ayrıntı `PUV6b/ozet/h1_esitlik.json`.

### H2 — bayraklar açık ↔ kapalı, aynı ağaç (`urun-010971e0`), 5 ikili + debian `pzstd` (14:04–14:25, yük altında) → TUTTU

Açık kol `ustveri_urun.py kos --config bayraklar_acik.yaml` (kök `PUV6b/s8_acik`), kapalı kol `urun_kos.py` (kök
`PUV6b/s8_kapali`; pzstd kapalı kolu en sonda). Karşılaştırma `PUV6b/betik/h1_h2.py` → `PUV6b/ozet/h2_esitlik.json`.

| İkili | `naming_map` (out / src / src_iter1) açık = kapalı | `.c` fark | `out/src` fark | Swift | RTTI (kanıt satırı) | RTTI kaynaklı ad | adım süresi Swift / RTTI (sn, açık) |
|---|---|---|---|---|---|---|---|
| debian/coreutils/cat | bayt aynı / aynı / aynı | 0 / 296 | 1 / 138 | `veri_yok` (ELF) | `veri_yok` | 0 | 0,026 / 0,025 |
| debian/tree/tree | aynı / aynı / aynı | 0 / 250 | 1 / 145 | `veri_yok` | `veri_yok` | 0 | 0,028 / 0,020 |
| debian/sqlite3/sqlite3 | aynı / aynı / aynı | 0 / 1 144 | 1 / 458 | `veri_yok` | `veri_yok` | 0 | 0,065 / 0,066 |
| debian/zstd/zstd | aynı / aynı / aynı | 0 / 1 444 | 1 / 1 119 | `veri_yok` | `veri_yok` | 0 | 0,199 / 0,155 |
| mac/tmux | aynı / aynı / aynı | 0 / 2 821 | 1 / 2 633 | `veri_yok` (Swift bölümü yok) | `veri_yok` | 0 | 0,163 / 0,162 |
| debian/zstd/pzstd | aynı / aynı / aynı | 0 / 1 156 | 1 / 901 | `veri_yok` | `calisti`: **13** (`tek_sinif` 13) | **0** | 0,049 / 0,136 |

- Değişen ad 0 (6 / 6); `out/src`'deki tek fark yine `compile_commands.json` (mutlak yol). pzstd'de RTTI kanıt satırı 13
  ≥ 1, köken kaydının `ust_veri_kanit` listesinde; RTTI kaynaklı karar / ad 0. **H2 TUTTU.**
- Açık koldaki adım süreleri bayraklar açıkken ölçüldü (yük altında 0,02–0,20 sn); H1'in ≤ 0,1 sn ölçütü kapalı kol
  içindir (0,0 sn).

## Özet: hükümler (ön kayıt `46a722c`, dondurma `d94ee20`)

| | Hüküm | Sayı |
|---|---|---|
| H1 | TUTTU | bayraklar kapalı: 5 / 5 ikilide `naming_map` (3 dosya) ve `decompiled/*.c` tabanla bayt aynı; `out/src`'de yalnız `compile_commands.json` yolu; iki adım 0,0 sn |
| H2 | TUTTU | açık ↔ kapalı değişen ad 0 (6 / 6); pzstd RTTI kanıt satırı 13, RTTI ad 0 |
| H3 | TUTTU | iTerm2 Swift aday 2 627, doğru 2 627, yanlış 0 (%0), Wilson alt 0,99854 ≥ 0,90909 |
| H4 | TUTMADI (sayı) | llama-server kanıt satırı 7 053 ∉ 6 990 ± 42 (ön kayıttaki 6 990 P-UV4'ün doğru sayısıydı; satır = 7 011 bağlı + 42 belirsiz); RTTI kaynaklı ad 0 tuttu; belirsizde sınıf adı 0 |
| H5 | TUTTU | üst veri adlarında `kesin` 0 (terminal-notifier, Rectangle); Swift 180 / 180 `üst veriden`, `ozgun_ad` dolu, güven tablodan |
| H6 | TUTTU | terminal-notifier ObjC 32 / 32 (doğru 32); Rectangle Swift adı 180 (ilk ölçüm; doğruluk ölçülmedi) |

**Güven tablosunun yeni satırları** (`naming_labels.MEASURED_METADATA_PRECISION`): ObjC `(33611, 33885, 0.9909)` (eskiden
`(33611, 33611, 0.9998)`), Swift `(2627, 2627, 0.9985)`; Go değişmedi. Program sayısı (A-14): Go 2, ObjC 2, Swift 1 →
bayraklar öntanımda kapalı.

## PUV6c ve açılış ölçümü için notlar

- **Swift yuvalarının çoğu adressiz:** Rectangle'da 1 152 yuvanın 926'sının `adres` alanı boş (uygulama adresi
  çözülmemiş / dış); kanal bunları yalnız sayıyor (`yuva_adressiz`), kanıt satırına yazmıyor. Tip + sıra bilgisiyle
  adressiz kanıt satırı yazmak ayrı karar (okuyucu dokunulmaz listedeydi).
- **Kanıt satırı yalnız birleştirici bir karar yazdığında görünür:** `run_name_merger` aday ve c_namer kararı yoksa
  köken kaydını yazmadan döner (`if not candidates_by_symbol and not decided_map: return`); RTTI'nin aday üretmediği bir
  ikilide c_namer da hiç ad vermezse RTTI kanıtı kaybolur. Ölçülen 9 koşunun hepsinde c_namer kararı vardı; birleştirici
  akışı bu paketin kapsamında değildi (yalnız girdi eklendi).
- **Ollama:** Swift `veri_yok`; RTTI 68 kanıt satırı (`tek_sinif` 65, `en_taban_sinif` 3), ad 0. Açılış ölçümünde
  (A-14) Swift için GT'li ikinci ve üçüncü program gerekir (bugün yalnız iTerm2).
- **ObjC güveni düştü:** köken kaydındaki ObjC güveni 0,9998 → 0,9909 (ürün düzeyi); ad eşiğinin üstünde, davranış
  değişmez, yalnız yazılan güven değeri.
- **bayrak mutasyon tanımı:** `m01`, `m04`, `m10` `config.py`'nin artık var olmayan INERT satırlarını arıyor (ÖK-1 / ÖL-2
  yamaları) → MUTBAKIM.
- PUV6c'nin işleri (Go tutarlılık damgası, `main` künyesi, `go_pclntab` notları, `output_formatter` `entry` yaması) bu
  pakette yapılmadı; `_feedback_naming_candidates.py`'de PUV6a / PK1 işlevlerine dokunulmadı (yalnız PUV6a'nın
  `_metadata_gate` / `_producer_status` yardımcıları genişletildi: demet durum, ölçülmemiş / evidence-only nedenleri).

## Koşu kökü ve ağaçlar

- Koşu kökü `~/karadul_olcum/runs/dalga1-2026-11-23/PUV6b/` (2,2 GB; `ozet/` 196 KB + betik kopyaları). Çalışma alanları
  (`acik/`, `s8_kapali/`, `s8_acik/`) ara üründür.
- Ürün ağaçları (silinmedi; ana oturum siler): `~/karadul_olcum/urun-d94ee206` (dondurma; H3 / H4), `~/karadul_olcum/urun-010971e0`
  (dondurma + Swift satırı; ürün koşuları ve yeniden oynatma).
- Arka plan süreci kalmadı; worktree'deki geçici veri bağları kaldırıldı.

## PAKET BİTTİ
