# P-ÜV6a — Go ve ObjC üst veri adlarını ürün çıktısına bağlama (ilerleme)

Gönderim metni: `docs/arge/2026-11-23_dalga1/gonderim/PUV6a.md`. Ajan: Opus 5.5. Başlangıç 2026-11-23 08:11 (taban main `f2b0db5`). Sert son 11:45.

Koşu kökü: `~/karadul_olcum/runs/dalga1-2026-11-23/PUV6a/`.

## Durum

| Kalem | Durum | Commit |
|---|---|---|
| 1 ön kayıt + taban | bitti (taban 0 / 40 hazır kökten okundu) | `3374382` |
| 2 kanal kodu | bitti | `0f46e6d` |
| 3 etiket, `ozgun_ad`, tablo, kanıt satırı; etiketi okuyan yerler | bitti | `de3b463`, `8bede53` |
| 4 Faz 1 listesi + kayıt; yamalar | bitti | `52e28c3` |
| 5 birim testleri | 24 / 24 | `eec6bd9` |
| 6 mutasyon | 20 / 20 öldü | `f2f97a6` |
| 7 Ghidra'sız ölçüm (H4, H5, H6) | sürüyor | — |
| 8 Ghidra'lı ölçüm (H3, H1, H2) | bekliyor | — |
| 9 dondurma + H8 | bekliyor | — |
| 10 tam takım | bekliyor | — |

## Tasarım (koddan)

- **Kanal yeri:** `_feedback_naming_candidates.K4_CHANNEL_FLAGS`'a `go_pclntab` (`enable_go_pclntab_naming`) ve `objc_method` (`enable_objc_metadata_naming`). İkisi `UNMEASURED_SOURCES`'ta değil (güven tablodan). Üreticiler (`go_metadata_recovery`, `objc_metadata_recovery`) Faz 1'de `binaryninja_analysis`'ten sonra, `type_recovery_consumer`'dan önce; yapıtları (`go_functions`, `go_status`, `objc_methods`, `objc_status`) Faz 2 tohumuyla `k4_inputs`'a gelir.
- **Üretici durumu kanala taşınır:** yapıt yok → `desteklenmiyor` ("üretici adım koşmadı"); üretici `kapali` → `kapali`; `veri_yok` / `desteklenmiyor` / `tutarsiz` / `hata` aynen; kayıt yok → `veri_yok`.
- **Go:** `pcsp_kapsama` ∈ {`kisa`, `tasan`} → kanıt satırı (`pcsp_elendi`; hüküm 1). Kalan kayıt `key_for` (yalnız Ghidra'nın adsız fonksiyonu; `tuttu` / `ghidra_adli` / `ghidra_fonksiyonu_yok`).
- **ObjC:** `ad_yazilabilir` ≠ `True` → `ad_yazilamaz`; `swift` → `swift_kopru`; `imp_paylasimli` → `imp_paylasimli`; her biri ayrı sayaç + `kanit_satiri` toplamı (hüküm 3). IMP'siz kayıt (protokol bildirimi) `imp_yok` sayılır.
- **A-28 (`key_for_selector`, yalnız `objc_method`):** Ghidra adı jenerikse `key_for` ile aynı. Ghidra adı seçiciyle birebir aynıysa anahtar o adın **C kodundaki yazımı**: terminal-notifier'da ölçüldü — `ghidra_functions.json`'da ad `applicationWillFinishLaunching:` (32 IMP'in 31'inde ad = seçici, 1 jenerik), decompile çıktısında `void AppDelegate::applicationWillFinishLaunching_(…)`; Ghidra C çıktısında `:` → `_`. Bu yüzden anahtar `code_name(ad)` (tanımlayıcı olmayan karakter → `_`). Anahtarı `ghidra_functions.json`'daki ham ad yapsaydık birleştiricinin Aho değiştiricisi `…Launching:` dizgisini kodda bulamazdı (sözcük sınırı). Ek kural (gönderimde yok, kodda gerekçeli): aynı C yazımını birden çok Ghidra fonksiyonu taşıyorsa (`init` iki sınıfta; ad listesi sınıf ad alanını yazmıyor) kod adı hangi fonksiyon olduğunu ayırmaz → aday yok (`secici_tekil_degil`). Ghidra adı seçiciden farklı ve jenerik değilse dokunulmaz (`ghidra_adli`).
- **Ad:** `c_identifier(özgün ad)` (Go `main.main` → `main_main`; ObjC `-[AppDelegate printVersion]` → `AppDelegate_printVersion`); özgün ad künyede (`ozgun_ad`). Aynı anahtara iki üst veri kaydı → ikisi de kanıt satırı (`cift_kayit`).
- **Eski Go kanalı:** `go_pclntab` önce koşar; `go_demangler` aynı anahtara aday vermez (`ust_veri_onde`). `GoBinaryAnalyzer` bulgusu (plan kalem 7): `strings` + düzenli ifade yolu adres vermiyor; rapora "fonksiyon adı" diye yazılmamalı — bu pakette kod değişmedi (`go_binary.py` dokunulmaz listesinde); ayrı onarım paketi önerilir: o yolu `go_metadata_recovery` çıktısına bağlamak (silme değil).
- **Köken kaydı (birleştirici, `naming_provenance.json` → `name_merger`):** üst veri adı kazandıysa karar `label = üst veriden`, `ozgun_ad`, `ust_veri_kanali`, `ust_veri_dogrulama = olculmedi`, `confidence` = tablo değeri, `evidence`, A-28'de `secici_yerine` + `ghidra_adi`. Başka kaynağın adı kazandıysa `ust_veri_adayi` (kanıt). Ad yazılmayan kayıtlar bölümün `ust_veri_kanit` listesinde (kaynak, adres, özgün ad, nedenler). c_namer'ın adlandırdığı anahtardaki üst veri kaydı `c_namer_adlandirdi` nedeniyle kanıt satırına iner (P13a / AD-04: o anahtarın kararı c_namer'ın). Üst veri kaydı yoksa bölüm eskisiyle bayt bayt aynı.
- **Ad haritası:** ölçüldü — birleştiricinin koda yazdığı adlar `out/naming_map.json`'a bugüne dek hiç girmiyordu (119 koşusunda zstd / pzstd: 6 uygulanmış birleştirici adı, `mappings` 0, `candidates` 0; betik `PUV6a/merger_gorunurluk.py`). `output_formatter._merger_metadata_records` yalnız `label = üst veriden` kararlarını haritaya ekler (kaynak = kanal, `ozgun_ad`, güven, kanal, kanıt). Öbür birleştirici adlarının haritada görünmemesi ayrı bir eski kusur: bu pakette onarılmadı (kapsam dışı; ana oturuma not).
- **Etiketi gösteren yerler:** `naming_labels.NAME_LABELS` dörtlü; rapor `name_merger_by_label`'ı ayrı satırda sayar (doğrulanmadı da kesin de sayılmaz); LM `LABEL_TAGS` → `metadata` (`proven` değil: korunmaz); `guard` liste sözcüğü; arayüz rozet sözlüğü (`m`) ve sayaç (yalnız varsa; P17 testinin metni değişmez). `ui/server.py` `NAME_LABELS`'tan okuduğu için değişmedi. LM `SUMMARY_BLIND_TAGS` (`context.py`, listede yok) değişmedi: üst veri adı ölçüm kipinde `verified` gibi görünür kalır — ana oturum kararı.
- **Güven tablosu:** `MEASURED_METADATA_PRECISION` Go (90 077, 90 077, 0,9999), ObjC (33 611, 33 611, 0,9998); `baglama.wilson` alt sınırı 4 basamağa aşağı (0,99995735 → 0,9999; 0,99988572 → 0,9998; yukarı yuvarlama 1,0 yazardı). `AD_ESIGI` içe aktarılır. A-14 satırı: Go 2 program (docker-cli, docker-compose), ObjC 2 program (terminal-notifier, iTerm2) → öntanımda açılmaz.

## Yamalar (`docs/arge/2026-11-23_dalga1/yamalar/`)

| Yama | İçerik | Neden |
|---|---|---|
| `PUV6a__config.py.patch` | iki INERT satırı silinir; alan yorumu `okuyan: pipeline/steps/_feedback_naming_candidates.py (P-ÜV6a)` | A-19; yamasız `test_p15a` yeşil (alan adları `K4_CHANNEL_FLAGS` dizgisinde), yamalı da yeşil |
| `PUV6a__test_output_formatter_guven.py.patch` | `NAME_LABELS` dörtlüsü | kilitli sözlük testi (gönderim hüküm 4: iki sözlük birlikte güncellenir) |
| `PUV6a__test_lm_tools.py.patch` | `LABEL_TAGS` + `"üst veriden": "metadata"` | kilitli LM etiket testi |

`git apply --check` üçünde de temiz. Config yaması geçici uygulanmışken `test_p15a_etkisiz` + `test_bayrak_on_paketi` + `test_puv6a_baglama` + `test_olcum_araci_d0`: 210 geçti / 4 atlandı; geri alındı.

## Testler ve mutasyon

- `tests/test_puv6a_baglama.py`: 24 test (gönderim kalem 5'in bütün maddeleri + üretici durumu, c_namer kararı, output_formatter, rapor).
- `scripts/measurement/mutation_specs_puv6a.json`: **20 / 20 öldü** (hüküm 1, 2 ×3, 3 ×3, 4, 5, 7 ×2 + plan listesi). `git status` sonrası temiz.
- İlgili test dosyaları (değişen modülleri içe aktaran 48 dosya + P13b, P17, P-ÜV1/2, bayrak, p15a): 1 207 geçti; kalan 3'ün 2'si yukarıdaki kilitli sözlük testleri (yama), 1'i (`test_olcum_araci_d0::test_siniflayici_denetle_durumlar`) `naming_labels.py` commit'lenmemişken HEAD ile çalışma dosyası farkından; commit'ten sonra geçti.
