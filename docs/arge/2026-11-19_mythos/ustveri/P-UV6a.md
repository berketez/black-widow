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
| 7 Ghidra'sız ölçüm (H4, H5, H6) | bitti: H4, H5, H6 TUTTU | `5da70a7` (araç), bu commit |
| 8 Ghidra'lı ölçüm (H3, H1, H2) | kuyrukta (08:43 başladı) | — |
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

## Kalem 7 — Ghidra'sız ölçüm (08:41–08:42; yük altında, `load averages` 11–17)

Araç `scripts/measurement/ustveri_urun.py` (`oynat`, `aday-gt`); çıktılar `~/karadul_olcum/runs/dalga1-2026-11-23/PUV6a/{oynat_ollama,aday_gt_docker-cli,aday_gt_terminal-notifier}.json` (yalnız sayı; ad listesi yok).

### H4 / H5 — Ollama arm64, gösteri çalışma alanı üstünde yeniden oynatma → TUTTU / TUTTU

Girdi: `~/karadul_olcum/runs/gosteri-2026-11-19/ollama/ws/workspaces/Ollama/20261119_081103` (`ghidra_functions.json` 13 559 fonksiyon, görüntü tabanı 0x100000000, delta 0) ve aynı çalışma alanının `raw/Ollama_arm64` dilimi; salt okundu. Ürün kodunun kendisi (`add_k4_channels`, iki bayrak açık) + birleştiricinin ad geçerliliği süzgeci (`validate_merged_names`).

| Kanal | Üretici | Kayıt | `tuttu` | A-28 `secici_yerine` | `ghidra_adli` | `ghidra_fonksiyonu_yok` | `secici_tekil_degil` | `pcsp_elendi` | Aday | Süzgeçten geçen |
|---|---|---|---|---|---|---|---|---|---|---|
| `go_pclntab` | `calisti` (10 601 giriş) | 10 600 | **10 475** | — | 97 | 28 | — | **0** | 10 475 | 10 475 |
| `objc_method` | `calisti` | 151 | 2 | **143** | 0 | 0 | 6 | — | **145** | 145 |

- **H4 TUTTU:** `tuttu` 10 475 ≥ 9 540. `pcsp_elendi` = 0 (ilk ölçüm; P-UV1'de Ollama arm64'te K4 ihlali 0 ile tutarlı). HEDEF G2 10 457'den 18 fazla: G2 thunk'ları (112) ayrı saymıştı; ürünün `_is_unnamed` kuralı `thunk_` adını adsız sayar.
- **H5 TUTTU:** 151 yöntemin 145'ine tam ad adayı (143 A-28 + 2 adsız fonksiyon), hepsi ad geçerliliğinden geçti (≥ 140). 6 yöntem `secici_tekil_degil` (aynı seçici adını iki Ghidra fonksiyonu taşıyor; kod adı fonksiyonu ayırmıyor) → ad yok. Kanıt satırı (swift / paylaşımlı / yazılamaz) 0.
- Okuma 0,37 sn (iki okuyucu; yük altında).
- Not: ürün koşusunda c_namer bazı `FUN_` anahtarlarına önce ad verebilir; o anahtarlarda üst veri adı kanıt satırına iner (`c_namer_adlandirdi`). Bu sayı Ollama'nın uçtan uca koşusunda ölçülür (ana oturum).

### H6 — docker-cli (keşif), Ghidra'sız aday listesi ↔ GT → TUTTU

| Kanal | Kayıt | Elenen | Aday | Doğru | Yanlış | GT'siz | Yazım | Wilson alt |
|---|---|---|---|---|---|---|---|---|
| `go_pclntab` | 35 049 | adsız 1 | 35 048 | **35 048** | **0** | 0 | birebir 34 710 / `.abi0` 328 / orta nokta 10 | 0,99989 |

- %100 ≥ %99,9 → TUTTU. İlk sürümde aday listesi adsız girişi (ad boş) sayıyordu (35 049, yanlış 1); ürün kanalı o girişi atlıyor, ölçüm aracı ürünle aynı kurala çekildi (sayı ölçüm aracının hatasıydı, kanalın değil).
- Ek (keşif): terminal-notifier ObjC 32 / 32 doğru (birebir 31, kategori 1), elenen 0; Go `veri_yok`.

## Kalem 8 — Ghidra'lı ölçüm

Ürün ağaçları (silinmez; ana oturum siler): `~/karadul_olcum/urun-5da70a7` (ilk koşu), `~/karadul_olcum/urun-5d23182` (A-28 onarımı sonrası). Bayrak yaml'ı `~/karadul_olcum/runs/dalga1-2026-11-23/PUV6a/bayraklar_acik.yaml` (dört bayrak `true`, başka ayar yok; yamasız dalda iki ad bayrağı için "etkisiz" uyarısı basılır ama değer okunur). Koşu `ustveri_urun.py kos` (`urun_kos.calistir` + `--config`), ölçüm `ustveri_urun.py urun`.

### H3 ilk koşu (5da70a7; 08:43:20–08:44:19, 59 sn, yük altında 11–17) — ÜST VERİ ADI 6 / 32: kusur bulundu

- `out/naming_map.json`'da `label = üst veriden` 6 ad (5 A-28 + 1 adsız fonksiyon), 6'sı da kodda, 6'sı da GT'ye göre doğru, 6'sında `ozgun_ad` dolu ve güven tablodan. Ad bekleyen 40'ta doğru 0 → 1.
- Kanal sayaçları: `secici_tekil_degil` 26 / yineleme. Teşhis (`PUV6a/tn_cift_ad.py`): 27 yöntemin seçici adını taşıyan ikinci Ghidra fonksiyonunun 27'si `__objc_stubs` bölümünde (≤ 32 bayt; Ghidra `_objc_msgSend$sel` saplamasını seçiciyle adlandırıyor), 3'ü thunk. Decompile çıktısında saplama `objc_stub::printVersion`, yöntem `AppDelegate::printVersion` (sınıf ad alanı). Yalın seçici anahtarı saplamayı ve çağrılarını da değiştirirdi → tekillik bekçisi doğru davranmıştı ama A-28'i 31'den 5'e indiriyordu.
- Ayrıca sayaçlar Faz 2'nin iki turunda birikiyordu (`kayit` 64 = 2 × 32).
- **Onarım (`5d23182`):** A-28 anahtarı `Sınıf::code_name(seçici)` (yöntemin koddaki tanım adı; saplama `objc_stub::` ad alanında kalır); sayaçlar yineleme başına; aynı sınıf + seçici (örnek + sınıf yöntemi) → `cift_kayit` kanıt satırı. Ollama gösteri çalışma alanında yeniden oynatma: ObjC aday 151 / 151 (A-28 149 + adsız 2), 149 nitelikli anahtarın 149'u Ghidra'nın decompile çıktısında geçiyor (`PUV6a/ollama_kodda.py`). Go sayıları değişmedi (10 475).
- Not: S8 koşuları (`s8_kapali`, `s8_acik`) `urun-5da70a7` ile başlatıldı. Onarım yalnız ObjC kanalı açıkken çalışan kodu ve üst veri köken kaydına `adres` alanını değiştirdi; bayraklar kapalıyken ve ObjC'siz ikilide (S8'in 5'i düz C) ad haritasına etkisi yok — H1 / H2 için 5da70a7 sonucu geçerli sayıldı (gerekçe bu satır).

## Kalem 9 — kuralların dondurulması (H8'den önce)

Dondurma commit'i: **bu commit** (üst: `0b70f48`; kural kodu `5d23182`'de). Bu commit'ten sonra SINAMA ölçümüne (H8) dek aşağıdaki dosyaların kural yolları değişmez; H8 bir kez ölçülür.

| Dosya | sha256 (ilk 16) | Dondurulan kural |
|---|---|---|
| `karadul/pipeline/steps/_feedback_naming_candidates.py` | `f0450446734c1d78` | hüküm 1 (`PCSP_REJECTED`), hüküm 3 (`_objc_rejections`), A-28 anahtarı |
| `scripts/measurement/ustveri_urun.py` | `270c64cfc4b0ca39` | `aday_listesi` (ürün süzgeçleriyle aynı; adsız Go girişi atlanır) |
| `karadul/analyzers/ustveri/go_pclntab.py` | `8b1d38ff4dc145d6` | okuyucu (P-ÜV1 dondurmasıyla aynı) |
| `karadul/analyzers/ustveri/objc.py` | `faece6a003852680` | okuyucu (P-ÜV2'de dondurulan) |

H8 Ghidra'sızdır (aday listesi ↔ GT); terminal-notifier'ın ikinci ürün koşusu (A-28 anahtarı) H8'in süzgeç kurallarını değiştirmez.

## H8 — SINAMA, bir kez (09:05:43–09:05:54; dondurma `5e33849`'dan sonra; Ghidra'sız aday listesi ↔ GT)

Çıktılar `~/karadul_olcum/runs/dalga1-2026-11-23/PUV6a/h8_{iTerm2,docker-compose}.json` (yalnız sayı).

| İkili (soyulmuş, sha256 ilk 12) | Kanal | Kayıt | Elenen (süzgeç) | Aday | Doğru | Yanlış | GT'siz | Yazım | Kesinlik (Wilson %95) |
|---|---|---|---|---|---|---|---|---|---|
| iTerm2 arm64 (`4c3e96a2593d`) | `objc_method` | 41 305 | `swift_kopru` 7 420 | 33 885 | **33 611** | **274** (%0,81) | 0 | birebir 31 431 / kategori 2 180 | %99,19 (%99,09–%99,28) |
| docker-compose (`9f39c9662989`) | `go_pclntab` | 90 078 | adsız 1 | 90 077 | **90 077** | **0** | 0 | birebir 89 699 / `.abi0` 360 / orta nokta 18 | %100 (alt 0,999957) |

- **H8 TUTTU:** iTerm2 yanlış %0,81 ≤ %1 ve doğru 33 611 ≥ 33 000; docker-compose yanlış 0 ≤ %0,1.
- **Risk (ana oturum kararı gerekir):** `MEASURED_METADATA_PRECISION[objc_method]` hüküm 5 gereği P-UV2'nin 33 611 / 33 611'i (alt 0,9998). O sayı yalnız GT adı ObjC olan adresleri sayıyordu; ürünün hüküm 3 süzgeçlerinden geçen aday kümesinde kesinlik 33 611 / 33 885 = %99,19 (Wilson alt 0,9909). Kanal yine ad eşiğinin (0,909) çok üstünde, ama köken kaydındaki güven (0,9998) ürün düzeyi ölçümden yüksek. Yanlış 274'ün kümesi P-UV2'nin "Swift işaretsiz 274 kayıt"ıyla aynı sayı (GT adı ObjC değil); türleri sınama kuralı gereği ikinci kez bakılmadı. Öneri: tablo satırı (33 611, 33 885, 0,9909) — değiştirmedim (hüküm 5 bağlayıcı).

### H3 ikinci koşu (`urun-5d23182`; kuyrukta 08:50:01 → 09:11:26 başladı → 09:12:33 bitti, 67 sn, yük 22–26) — ölçüm `PUV6a/urun_terminal-notifier_acik2.json`

| Satır | Önce (b6aceb9, HEDEF taban) | Sonra (5d23182, dört bayrak açık) |
|---|---|---|
| `out/naming_map.json`'da üst veri kaynaklı ad (`label = üst veriden`) | 0 | **32 / 32** (A-28 31 + adsız fonksiyon 1) |
| bunlardan `out/src` kodunda tanımlayıcı olarak geçen | 0 | **32** |
| GT'ye göre doğru / yanlış / GT'siz (`ozgun_ad` üstünden, kalem 2 kuralları) | — | **32 / 0 / 0** |
| `ozgun_ad` dolu / güven tablodan (0,9998) / etiket `kesin` | — | 32 / 32 / **0** |
| ad bekleyen 40 fonksiyonda doğru ad (HEDEF tanımı; c_namer ∪ üst veri) | 0 / 40 | **1 / 40** |
| c_namer genel haritası (HEDEF tanımı) | 0 | 0 |
| kanal sayaçları (`objc_method`) | — | kayıt 32, `secici_yerine` 31, `tuttu` 1, aday 32; kanıt satırı 0; `go_pclntab` `veri_yok` |
| adım süresi (yük altında) | — | Go 0,029 sn, ObjC 0,029 sn |

- **H3 KISMEN:** "≥ 30 / 32 ürün çıktısında (`naming_map` ve `out/src`)" **TUTTU** (32 / 32); "yanlış 0" **TUTTU**; "ad bekleyen 40'ta doğru 0 → ≥ 30" **TUTMADI** (0 → 1). Neden (ön kayıtta ölçümden önce yazılmıştı): 32 IMP'in 31'i Ghidra'da seçiciyle adlı, HEDEF'in nüfus tanımı yalnız jenerik adlı fonksiyonları sayar; nüfusun kalan 39 fonksiyonu ObjC yöntemi değil (GT ad türü "diğer" 50: blok, C işlevi) — bu kanalların kapsamında değiller.
- **H7 TUTTU** (bu koşuda): üst veri kaynaklı 32 adın 32'si `label = üst veriden`, `ozgun_ad` dolu, güven tablodan; `kesin` 0. Köken kaydında 32 karar, 32'si uygulanmış, düşen 0.

### H1 — bayraklar kapalı, S8'in 5 ikilisi (`urun-5da70a7`, `urun_kos.py`; 08:43–09:06, yük 11–35)

Kök `~/karadul_olcum/runs/dalga1-2026-11-23/PUV6a/s8_kapali`; karşılaştırma `scripts/arge/hiz/s8_esitlik.py --once s8_taban_b6aceb9 --sonra s8_kapali --aa s8_taban_b6aceb9_AA` → `PUV6a/h1_esitlik.{md,json}`.

| İkili | `naming_map` farklı / dosya (out, src, src_iter1) | `.c` farklı / dosya | JSON farklı / dosya |
|---|---|---|---|
| debian/coreutils/cat | 0 / 3 | 0 / 296 | 0 / 23 |
| debian/tree/tree | 0 / 3 | 0 / 250 | 5 / 23 (yalnız `ghidra_bsim.json`) |
| debian/sqlite3/sqlite3 | 0 / 3 | 0 / 1 144 | 5 / 23 (yalnız `ghidra_bsim.json`) |
| debian/zstd/zstd | **2 / 3** (`out` aynı; `src`, `src_iter1` farklı) | **1 / 1 444** (`FUN_001063c0.c`) | 7 / 23 |
| mac/tmux | 0 / 3 | 0 / 2 821 | 5 / 23 (yalnız `ghidra_bsim.json`) |

- **H1 TUTMADI (katı okuma: 4 / 5).** zstd'deki fark: Ghidra'nın `FUN_001063c0` decompile çıktısı (5 468. satırda iki atamanın sırası; 10 satır `diff`) ve buna bağlı olarak c_namer'ın o fonksiyondaki yerel adları (`per_function`). Ghidra çıktısı bu paketin koduna ulaşmadan üretilir (static aşaması; değişiklik reconstruct aşamasında), yani fark ürün kodundan değil: **aynı fark P16e'nin `s8_sonra_1` koşusunda da (başka ağaç, bu değişiklik yok) birebir görüldü** (`FUN_001063c0.c` 10 satır, `naming_map` 2 / 3; P16e `H1_ham.md`), `s8_sonra_2` / `_3`'te görülmedi → yük altında Ghidra belirlenimsizliği. `out/naming_map.json` beş ikilide de bayt bayt aynı. Aynı ağaçla zstd tekrar koşusu kuyrukta (`s8_kapali_tekrar`).
- `ghidra_bsim.json` farkı BSim veritabanının taban koşusundan beri büyümesinden (`known_executables`, `matches`); A/A ile ayrılan, ad haritasına girmez.

### H9 — süre (bayraklar kapalı) → TUTTU

Koşucunun kaydı (`<adım>_duration_s`, 4 basamak), S8'in 5 ikilisinin 5'inde: `go_metadata_recovery_duration_s` 0,0 (4 ikili) / 0,0001 (1 ikili), `objc_metadata_recovery_duration_s` 0,0 (5 / 5); iki adım ve kanallar `kapali`. Eşik ≤ 0,1 sn / ikili. (Yük altında; boş makine ölçümü değil. Bayraklar açıkken terminal-notifier'da iki adım 0,029 + 0,029 sn.)
