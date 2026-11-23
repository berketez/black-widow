# PK-1 — var olan başvuru yollarına yöntem kapısı (ilerleme)

Gönderim metni: `docs/arge/2026-11-23_dalga1/gonderim/PK1.md`. Ajan: Opus 5.5. Başlangıç 2026-11-23 19:36 (taban main `0b4d948`). Sert son 21:25.

Koşu kökü: `~/karadul_olcum/runs/dalga1-2026-11-23/PK1/` (ölçüm özetleri `ozet/`; yalnız sayı, ad listesi yok).

## Durum

| Kalem | Durum | Commit |
|---|---|---|
| 0 ilerleme dosyası | bitti | `a29d23c` |
| 1 ön kayıt (H1–H5) | bitti (ölçümden önce) | `174831a` |
| 2 `yontem_kapisi.py` (+ `kimlik/__init__.py`) | bitti | `b65064d` |
| 3 `_feedback_naming_bindiff.py` / `_refdiff.py` kapısı + kanıt satırı | bitti | `1d94cd5` |
| 4 `_add_bindiff` / `_add_refdiff` güveni; iki test yaması | bitti | `35d8600` |
| 5 testler + mutasyon | 24 test (commit iletisindeki "25" yanlış; doğrusu 24); 11 / 11 mutant öldü | `cd7d2e8` |
| 6 ölçüm (`urun_bindiff.py --kapi`; PK-11 çifti; H4 yeniden oynatma) | bitti | `c503075` (betik), bu belge |
| 7 uçtan uca duman | Ghidra'lı koşu yapılmadı (veri yok + kuyruk dolu); Ghidra'sız tesisat dumanı yapıldı | bu belge |
| 8 tam takım | 10 878 geçti / 88 atlandı / 9 kaldı; 9'un hepsi ayrıldı (aşağıda) | bu belge |

## Tasarım (koddan)

- **Tablo** (`karadul/reconstruction/kimlik/yontem_kapisi.py`): `OLCULMUS_SAYIM` = ön kaydın "TÜM GRUPLAR" sayıları (yöntem → doğru, ad verilen). Wilson alt sınırı elle yazılmaz: `baglama.wilson` ile hesaplanır; `OLCULMUS_YONTEM`'deki değer 4 basamağa AŞAĞI yuvarlanmış hâli (P-ÜV6a düzeni, `naming_labels.floor_confidence`). `ad_verebilir` yuvarlamasız alt sınırı `naming_labels.AD_ESIGI` (10 / 11) ile karşılaştırır (hüküm 1); tablo dışı yöntem (`decompiled_hash` dahil) `False`. Sonuç: ad veren yalnız `string_refs` (0,9197) ve `string_fingerprint` (0,9431).
- **Kapı** (`_feedback_naming_bindiff.split_by_method_gate`, `_feedback_naming_refdiff.gate_reference_matches`): `_config_source`, `_refdb_source`, `_match_against_db`'de eşleşme yöntemine göre ayrılır. Kapıdan geçen bugünkü gibi `bindiff_confidence_map` / `bindiff_names` / `refdiff_naming`'e; kalan `stats["bindiff_evidence"]` / `stats["refdiff_evidence"]` listesine; sayaçlar `stats["bindiff_method_gate"]` / `stats["refdiff_method_gate"]` (`yöntem → {ad, kanit}`). `update_unprotected` yalnız ad verenlerle çağrılır (korunan ön ad yine ezilmez). ReferenceDiffer'da adın yöntemi `naming_map`'i kuran kuralla (hedef başına en yüksek güvenli eşleşme, eşitlikte ilk gelen) bulunur; bulunamazsa ölçülmemiş sayılır.
- **Güven** (`_add_bindiff`, `_add_refdiff`): sabit 0,95 ve eşleyicinin kalibre olmayan puanı kalktı; güven = yöntemin ölçülmüş alt sınırı. Ölçülmemiş / kapı altı yöntem aday olmaz (ikinci denetim). `_add_refdiff`'e yöntem bugün taşınmıyor: `collect_candidates`, `_feedback_naming.py` ve birleştirici bu paketin dosyası değil (hüküm 3). Bu yüzden yöntemi bilinmeyen refdiff adına ReferenceDiffer'ın kapıdan geçen yöntemlerinin **en düşüğü** yazılır (bugün tek yöntem geçtiği için `string_fingerprint`'in kendi değeri: 0,9431). İsteğe bağlı `refdiff_methods` parametresi eklendi; çağıran zinciri onu taşırsa ad başına değer kullanılır (yöntem `stats["refdiff_methods"]`'te hazır).
- **Kanıt satırı** (hüküm 4): köken kaydında `reference_evidence` bölümü, bir satır listesi. Satır P-ÜV6a'nın `ust_veri_kanit` satırıyla aynı temel alanlar (`kaynak`, `adres`, `ozgun_ad`, `nedenler`) + `anahtar` (Ghidra adı), `yontem`, `olculmus_alt` (ölçülmemişse `null`), `eslesme_guveni` (eşleyicinin puanı; kalibre değil), `basvuru`. `ozgun_ad` = başvurudaki ad (önerilen, koda yazılmadı). `nedenler`: `yontem_kapisi` (ölçülmüş, eşik altı) ya da `olculmemis_yontem`. Fark: P-ÜV6a satırı `name_merger` bölümünün içinde; bu satırlar ayrı bölümde, çünkü birleştiriciye (dokunulmaz) değil başvuru adımına ait ve birleştiriciden önce yazılıyor. Yazıcı `_feedback_naming_bindiff.write_reference_evidence`: Faz 2'nin ilk yinelemesinde `reconstructed/src/naming_provenance.json` (c_namer'ın kaydı; birleştirici `name_merger` bölümünü aynı dosyaya öbür bölümleri koruyarak yazar), yoksa `reconstructed/reference_evidence.json`. Satır yoksa dosyaya dokunulmaz.
- **Dokunulmayanlar:** `karadul/analyzers/bindiff.py`, `karadul/reconstruction/reference_differ.py`, `config.py`, `naming_labels.py`, `stages.py`, `_feedback_naming_merger.py`; `_feedback_naming_candidates.py`'de yalnız `_add_bindiff` ve `_add_refdiff` değişti (PUV6a'nın kanallarına, `K4_CHANNEL_FLAGS`'a, `GhidraFunctionIndex`'e dokunulmadı).

## Yamalar (`docs/arge/2026-11-23_dalga1/yamalar/`)

| Yama | İçerik | Neden | `git apply --check` |
|---|---|---|---|
| `PK1__test_mutbakim_p13a.py.patch` | BinDiff eşleşmesinin yöntemi `"string"` → `"string_refs"` | test kurgusal bir yöntem adı kullanıyordu; kapı ölçülmemiş yöntemi aday yapmadığı için AD-04 senaryosu kurulamıyordu | temiz |
| `PK1__test_p13a_birlestirici.py.patch` | aynı | aynı | temiz |

Yamalı kopyalar (`PK1/yamali_test/`, worktree dışı): 11 / 11 geçti. Worktree'deki test dosyalarına dokunulmadı.

## Testler ve mutasyon

- `tests/test_pk1_basvuru_yontem_kapisi.py`: 24 test (8'i yöntem başına parametreli). (a) tablo ön kayıtla ve ölçüm betiğinin Wilson'uyla (`scripts/measurement/macho_f1.wilson_interval`, ürün kodundan bağımsız) aynı, ön kayıt metninde sayılar geçiyor; tablo dışı yöntem ad veremez; karşılaştırma yuvarlamasız. (b) `_config_source`, `_refdb_source`, `_match_against_db`: kapı, kanıt satırı, sayaç; `naming_map` kuralıyla yöntem. (c) `_add_refdiff` güveni 0,95 değil; `_add_bindiff` ölçülmüş alt sınır, kaynak adı `bindiff_<yöntem>`. (d) korunan ön ad ezilmez; öntanımlı ayarla hiçbir şey yazılmaz; köken kaydı öbür bölümleri korur; satır yoksa dosya yok.
- `scripts/measurement/mutation_specs_pk1.json`: **11 / 11 öldü** (plan m1–m4 + 7 ek: eşleyici puanı, refdiff kapısı, ref_db kapısı, öbür kaynağın satırları, `_add_bindiff` ikinci denetimi, ilk eşleşmeden yöntem, config adları kapısız). İlk koşuda m10 (ilk eşleşmeden yöntem) hayatta kaldı → test güçlendirildi (iki sıra) → öldü. Koşum sonrası `git status` temiz. Günlük `PK1/mutasyon.log`.
- İlgili eski testler (BinDiff / ReferenceDiffer / birleştirici / P13a / P12c / P13b / PUV6a; 16 dosya): 260 geçti / 2 kaldı → ikisi yukarıdaki yamanın testleri (yamayla yeşil). `tests/test_bindiff.py` ve `tests/test_reference_differ.py` yeşil.

## Ölçüm (Ghidra'sız; yük altında; `PYTHONHASHSEED=0`)

Sürücü `PK1/olc_kapi.py` (ürün kodu worktree'den: günlükte `karadul.__file__` worktree), özet `PK1/yon_ozet.py`. `urun_bindiff.py` sayımı eşleşme düzeyinde, nüfus içi, tam eşitlik.

### Kabul ölçütü — tmux (`sinama_tmux`, iki yön havuzu)

| Kip | Önce (tur 1 kaydı, a62f15e) | Önce (bu koşu) | Sonra (`--kapi`) | Beklenen | Kanıt satırına inen (doğru / yanlış) |
|---|---|---|---|---|---|
| `config` (BinaryDiffer) | 328 / 174 | 328 / 175 | **326 / 16** | 326 / 16 | 2 / 159 |
| `refdb` (`call_pattern` adı) | `call_pattern` 91 / 56 | `call_pattern` 87 / 51 | **`call_pattern` 0** (toplam 326 / 16) | 0 | 89 / 210 |
| `refdiffer` (ReferenceDiffer) | 366 / 769 | 359 / 770 | **304 / 12** | 304 / 12 | 55 / 758 |

**Kabul TUTTU.** Yön başına (sonra): `config` debian → mac 159 / 7 (Wilson alt 0,9155), mac → debian 167 / 9 (alt **0,9057**); `refdiffer` 149 / 5 (0,9263), 155 / 7 (0,9135) — bkz. riskler.

### Havuz (H1, H2)

`sinama_cu_mac` yeniden ölçülemedi: `macgnu/gcat`'in çalışma alanı (`onarim-2026-11-18/P-S3/A/macgnu/gcat`) diskte yok. Dört grup (`kesif_htop`, `sinama_tmux`, `sinama_cu_ic`, `surum`) ölçüldü:

| Yol | Önce (4 grup, bu koşu) | Sonra (4 grup) | Ön kayıt (5 grup) | Kanıt satırına inen (doğru / yanlış) |
|---|---|---|---|---|
| `BinaryDiffer` `config` | 946 / 454 | **414 / 24** | 958 / 604 → 414 / 24 | 532 / 430 |
| `BinaryDiffer` `refdb` | 1 162 / 522 | **414 / 24** | — | 748 / 498 |
| `ReferenceDiffer` | 1 995 / 1 196 | **476 / 18** | 2 056 / 1 359 → 476 / 18 | 1 519 / 1 178 |

- `sinama_cu_mac`'ın tur 1 kaydında (`K/urun_bindiff.json`) dizgi yöntemlerinin eşleşmesi 0 (config 8 / 156 hepsi `cfg_fingerprint` + `size_params`; refdiffer 55 / 168 hepsi `cfg_similarity` + `size_constant`). Bu yüzden beş grubun "sonra" havuzu dört grubunkiyle aynı olur: **414 / 24 ve 476 / 18 → TUTTU** (beşinci grup yeniden ölçülmedi; değer tur 1 kaydından).
- **H1 (yeni yanlış 0): TUTTU.** Kapı yalnız süzer; sonraki her ad önceki ad kümesinde ve iki dizgi yönteminin yanlışları önce / sonra aynı (tmux 16 = 16, 12 = 12; havuz 24 = 24, 18 = 18).
- **H2 (kaybedilen doğru 544 / 1 580; giderilen yanlış 580 / 1 341): yön ve büyüklük tuttu, kesin sayı doğrulanamadı.** Dört grupta ölçülen: `config` kayıp doğru 532, giderilen yanlış 430; `ReferenceDiffer` 1 519 ve 1 178. Dört grup + `sinama_cu_mac` tur 1 kaydı (karma, TAHMİN değil ama iki ayrı koşunun toplamı): 540 / 586 ve 1 574 / 1 346. Fark kaynağı: kapı dışı yöntemlerin "önce" sayıları koşudan koşuya oynuyor (tmux `config` 328 / 174 → 328 / 175, `call_pattern` 91 / 56 → 87 / 51, `cfg_similarity` 58 / 725 → 53 / 728; aynı Ghidra JSON'ları, `PYTHONHASHSEED=0`). Dizgi yöntemleri her koşuda bayt aynı.
- **H3: TUTTU (tasarım).** `cfg_fingerprint` tek satır (445 / 584, alt 0,7258); aynı derleyici koşulu tabloda yok.

### H4 — öntanımlı ayarla davranış aynı → TUTTU

`PK1/h4_oynat.py`: 14 ikili (debian sqlite3, openssl, cat, sort, tree, htop, tmux, zstd, redis-cli, ls, cp, date; mac tmux, htop; `urun-onarim-a62f15e` çalışma alanlarının `static/` JSON'ları), `run_bindiff` + `run_reference_differ` öntanımlı `Config()` ile; önce = sabit ürün ağacı `~/karadul_olcum/urun-152176b`, sonra = bu dal. **14 / 14 aynı**: `bindiff_names` = `refdiff_naming` = 0, ön ad sözlüğü sha256 aynı, istatistik anahtarları aynı, hata yok, köken kaydı yazılmadı. sqlite3 ve openssl'de sürüm tespiti var (ReferenceDiffer yolu veritabanı aramasına kadar koştu; `~/.cache/karadul/ref_db` boş). Çıktı `ozet/h4_{once,sonra}.json`, `ozet/h4_karsilastirma.txt`.

### H5 — PK-11 taze çifti (`gomulu_kitaplik`, zstd → libzstd, Q → R) → TUTTU

| Yol | Önce (PK-11.md) | Önce (PK-11 JSON) | Önce (bu koşu) | Sonra | Wilson alt (sonra) | Kanıt satırına inen |
|---|---|---|---|---|---|---|
| `BinaryDiffer` `config` | 34 / 93 | 36 / 91 | 36 / 88 | **6 / 0** (`string_refs`) | 0,6097 | 30 / 88 |
| `BinaryDiffer` `refdb` | 44 / 94 | 46 / 93 | 45 / 90 | **6 / 0** | 0,6097 | 39 / 90 |
| `ReferenceDiffer` | 175 / 116 | 173 / 117 | 175 / 115 | **12 / 0** (`string_fingerprint`) | 0,7575 | 163 / 115 |

- **Yeni yanlış 0: TUTTU.** Kalan adlar yalnız dizgi yöntemlerinden; Wilson alt sınırları küçük n yüzünden eşiğin altında (ilk ölçüm; eşik yok, yalnız rapor). Ters yön (R → Q): 2 / 0, 2 / 0, 7 / 0.
- "Önce" sayıları üç kayıtta farklı (aynı nedenle: kapı dışı yöntemler belirlenimsiz); dizgi yöntemleri üçünde de 6 / 0 ve 12 / 0.
- Çıktı `ozet/urun_bindiff_pk11_{once,sonra}.{json,txt}`, `ozet/pk11_yonler.txt`.

### Adım 7 — uçtan uca duman

- **Ghidra'lı ürün koşusu yapılmadı.** Plan şartı (sembollü htop `K/bsim/htop_dm/1_debian` çalışma alanının `static/` dizininde) sağlanmıyor: dizinde yalnız Ghidra JSON'ları var, ikili yok (**veri yok**; yeni indirme yasak). Ayrıca kuyruk dolu (yuva 1'de `ANA ollama:ba_kapali` 19:36'dan beri, TAHMİN 1,5–2 sa; öbür yuva PUV5 + OL2). Kalan iş olarak duruyor: başvuru verisi hazırlanınca tek koşu.
- **Yerine Ghidra'sız tesisat dumanı** (`PK1/duman.py`; ölçüm değil): gerçek Ghidra JSON'larıyla `run_bindiff` (`reference_binary` ayarlı; başvuru = aynı Debian htop'un tur 1 `static/` JSON'ları, hedef = `urun-onarim-a62f15e` Debian htop) → kapı → köken kaydı kopyası → `_add_bindiff`.

| | Ana ağaç (eski kod) | Bu dal |
|---|---|---|
| eşleşme | 137 | 137 |
| ad (`bindiff_names` = ön ad sözlüğüne giden) | 137 (`cfg_fingerprint` 82, `string_refs` 44, `size_params` 11) | **44** (`string_refs`) |
| kanıt satırı | — | 93 (`cfg_fingerprint` 82, `size_params` 11; neden `yontem_kapisi`) |
| köken kaydı `reference_evidence` | — | 93 satır; c_namer kaydının öbür bölümleri korundu |
| aday güvenleri | 0,78 / 0,80 / 0,85 / 0,90 (eşleyici puanı) | **0,9197** (ölçülmüş alt sınır) |

  Çıktı `PK1/duman/duman_once_ana_agac_ozet.json`, `PK1/duman/duman_ozet.json`.

## Tam takım (kalem 8)

- Komut `PYTHONDONTWRITEBYTECODE=1 python -m pytest -q -p no:cacheprovider` (worktree kökü, kod `c503075` = son kod; 19:51–19:57, 387 sn, yük altında, `load averages` 5–7): **10 878 geçti / 88 atlandı / 9 kaldı** (152 seçim dışı). Günlük `PK1/ozet/tam_takim.log`.
- 2'si bu paketin beklenen kırmızısı, yamayla yeşil: `test_mutbakim_p13a::test_ad04_olculmus_on_ad_bindiff_ile_iki_kaynak_sayilmaz`, `test_p13a_birlestirici::test_ad04_bindiff_adi_on_ad_olarak_ikinci_kez_sayilmaz` (kurgusal `"string"` yöntemi; yamalar yukarıda, yamalı kopyada geçti).
- 7'si ortam: worktree'de git'in izlemediği çalışma verisi yok (`scripts/node_modules` → `@babel/parser` bulunamadı: `test_deobfuscator` ×2, `test_pipeline::test_identify_and_static`, `test_project_reconstructor::…explicit_modules_dir`; `vendor/gnulib-ref` yok: `test_ps3b_full_write`, `test_ps3b_gnulib_varlik`, `test_ps3b_ic_ad`). `vendor` ve `scripts/node_modules` geçici bağla bağlanınca 7'si **7 / 7 geçti** (`PK1/ozet/tam_takim_ortam7.log`); bağlar sonra silindi, `git status` temiz. Atlanan 88 (main'de 18) aynı nedenle (bağsız çalışma verisi); bu paketin değişikliğiyle ilgili değil.
- Bu paketin değişikliğinden kaynaklanan başka kırmızı yok.

## Riskler ve ana oturum için notlar

1. **Yön başına sayım (A-14, A-15):** tablo plan gereği iki yönün havuzu. `string_refs` tmux mac → debian yönünde tek başına Wilson alt **0,9057 < 0,909** (167 / 9); havuz 0,9197. Kural yön başına okunursa `string_refs` bu yönde eşiğin altında. Hüküm 2 tabloyu "TÜM GRUPLAR" satırlarına bağladığı için kod değişmedi; karar ana oturumun.
2. **Kapı dışı yöntemler belirlenimsiz:** aynı girdiyle `size_params`, `call_pattern`, `cfg_similarity` sayıları koşudan koşuya ±5 oynuyor (tablodaki sayılar tek koşu). Kapının kararını değiştirmez (hepsi eşiğin çok altında); ama bu yöntemler ileride yeniden ölçülürse tek koşuya güvenilmemeli.
3. **`_add_refdiff` güveni yöntem başına değil:** yöntem bilgisi birleştiriciye taşınmıyor; bugün tek ad veren ReferenceDiffer yöntemi olduğu için değer aynı. İkinci bir refdiff yöntemi kapıdan geçerse `refdiff_methods`'u `collect_candidates`'e taşıyan küçük yama gerekir (`_feedback_naming.py` → `run_name_merger` → `collect_candidates`; bu paketin dosyası değil).
4. **Kanıt satırının yeri:** yalnız Faz 2 ilk yinelemenin köken kaydında (`reconstructed/src/naming_provenance.json`); sonraki yinelemelerin (`src_iter1`) kaydına kopyalanmıyor. Arayüz / rapor bu bölümü bugün okumuyor (bağlama ayrı iş).
5. **Ölçüm verisi kaybı:** `onarim-2026-11-18/P-S3/A/macgnu/gcat` silinmiş; `sinama_cu_mac` grubu bu yüzden yeniden koşulamıyor (KİMLİK tur 1 betikleri onu bekliyor).

## PK-2 / PK-4 için notlar

- `karadul/reconstruction/kimlik/` paketi açıldı: `__init__.py` (yalnız belge dizgisi; PK-2'nin `olgu.py`, `esleyici.py`, `ad_ailesi.py`, PK-4'ün `kanal.py` dosyalarını anıyor) ve `yontem_kapisi.py`. PK-2 `__init__.py`'ye dokunmadan yeni dosya ekleyebilir.
- PK-4 kendi kanalının kanıt satırları için `yontem_kapisi.kanit_satiri` biçimini ve `write_reference_evidence`'ı (bölüm `reference_evidence`, `kaynak` alanıyla ayrılır; yazıcı yalnız kendi kaynağının satırlarını değiştirir) kullanabilir; ölçülmüş satırlarını `naming_labels.py`'ye yazacaksa `OLCULMUS_SAYIM` ile aynı (doğru, ad verilen) biçimi ve hesaplanan alt sınırı izlemesi önerilir.
- PK-4 `_feedback_naming_bindiff.py`'ye PK-1'den sonra yazacak: kapı `split_by_method_gate`'te; yeni kanal bu fonksiyonu kullanırsa yöntem adı tabloda olmalı (yoksa kanıt satırı olur).

## Özet: hükümler (ön kayıt `174831a`)

| | Hüküm | Sayı |
|---|---|---|
| Kabul | TUTTU | tmux `config` 326 / 16, `refdb` `call_pattern` adı 0, `refdiffer` 304 / 12; havuz 414 / 24, 476 / 18 (4 grup ölçüldü; `sinama_cu_mac` dizgi yöntemi 0, tur 1 kaydı) |
| H1 | TUTTU | yeni yanlış 0 |
| H2 | yön ve büyüklük tuttu; kesin sayı doğrulanamadı | 4 grupta kayıp doğru 532 / 1 519, giderilen yanlış 430 / 1 178 (ön kayıt 5 grupta 544 / 1 580, 580 / 1 341) |
| H3 | TUTTU (tasarım) | `cfg_fingerprint` tek satır, ad vermez |
| H4 | TUTTU | 14 / 14 ikilide öntanımlı davranış aynı (ad 0) |
| H5 | TUTTU | PK-11 çifti Q → R: `config` 36 / 88 → 6 / 0 (alt 0,6097), `refdb` 45 / 90 → 6 / 0, `ReferenceDiffer` 175 / 115 → 12 / 0 (alt 0,7575); yeni yanlış 0 |
| Adım 7 | Ghidra'lı koşu yok (veri yok, plan gereği atlandı); Ghidra'sız tesisat dumanı: 137 ad → 44 ad + 93 kanıt satırı | — |

Koşu kökü `~/karadul_olcum/runs/dalga1-2026-11-23/PK1/` 2,1 MB (ürün çalışma alanı yok; `duman/` başvuru JSON kopyaları içerir, commit'lenmedi).

## PAKET BİTTİ
