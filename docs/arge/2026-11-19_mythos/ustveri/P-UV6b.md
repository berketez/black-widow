# P-ÜV6b — Swift ad kanalı + C++ RTTI kanıt satırı (ilerleme)

Gönderim metni: `docs/arge/2026-11-23_dalga1/gonderim/PUV6b.md`. Ajan: Opus 5.5. Başlangıç 2026-11-24 13:13 (taban main
`cfe93ce`, `git merge --ff-only main` ile). Sert son 15:05.

Koşu kökü: `~/karadul_olcum/runs/dalga1-2026-11-23/PUV6b/` (özetler `ozet/`, ölçüm betikleri `betik/`).

## Durum

| Kalem | Durum | Commit |
|---|---|---|
| 1 ön kayıt | bitti | `46a722c` |
| 2 kod + testler + mutasyon → dondurma | bitti: 25 test, puv6b 18 / 18 mutant öldü | `28427fb`, `d71b939`, `2ff758c`, dondurma (bu commit) |
| 3 Ghidra'sız yeniden oynatma (H3, H4, kanal sayıları) | sırada | — |
| 4 ürün koşuları (H1, H2, H6) | sırada | — |
| 5 eski mutasyon tanımları + tam takım (yamasız) | sırada | — |

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
