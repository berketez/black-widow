# OL10A — ÖL-10 alt paketi A: saf çekirdek (ilerleme)

**Ollama dilimi (gösteri çalışma alanı), kural sürümü 1: sınıf ve basamak sayıları H-A1 ile birebir aynı (`KENDI` 1 406, `BILINMIYOR` 2 619, `BAGIMLILIK` 594, `STANDART` 8 541, `TASLAK` 399; B1 36 + giriş taslağı, B2 1 373, B3 1 236, B4a 547, B4b 836, B5 591, B6 398); seçilebilen küme 4 619 / 13 160 program fonksiyonu (%35,1); xref türetmesi 9 çalışma alanının 3'ünde JSON-eşit (sıra-normal), 9 / 9'da küme düzeyinde eşit; fark yalnız 112 fonksiyonun `strings_used` sırası.**

- Gönderim: `docs/arge/2026-11-23_dalga1/gonderim/OL10A.md`; tasarım: `olcek/OL10_TASARIM.md` §2, §1.3, §7.1 (bağlayıcı).
- Taban: main `7a1c8f4` (2026-11-23 20:29; `git merge --ff-only main`; ilk ileri sarma sırasında main bir kez daha ilerledi, ikinci ileri sarmayla eşitlendi).
- Koşu kökü: `~/karadul_olcum/runs/dalga1-2026-11-23/OL10A/` (özetler `ozet/`; ölçüm betikleri `olcum.sh`, `ozetle.py`, `sira_farki_denetle.py`, `mutant_uret.py`, günlükler `olcum.log`, `mutasyon.log`, `tam_takim.log`).
- Başlangıç: 2026-11-23 20:32; `uptime` yük ortalaması 28,67 / 31,03 / 28,33 (makine yüklü). Disk kullanılan 716,5 GB.
- Sert son: 22:00.

## Kalemler

| # | Kalem | Durum | Commit |
|---|---|---|---|
| 1 | `karadul/core/tembel_secim.py` (sabitler, veri sınıfları, `sec`, `kes`) | bitti | `7c68d6a` |
| 2 | `karadul/core/tembel_girdi.py` (K1 JSON + görüntüden girdi; taban farkı `load_ghidra_index` ile) | bitti | `7c68d6a` |
| 3 | `karadul/core/tembel_xref.py` (`turet`) | bitti | `7c68d6a` |
| 4 | ön kayıt `on_kayit_OL10A.md` (ölçümden önce ayrı commit) | bitti | `9991574` |
| 5 | testler: `tests/test_ol10a_secim.py` 25, `tests/test_ol10a_xref.py` 7 (toplam 32) | bitti | `7c68d6a`, `6869854` |
| 6 | `scripts/measurement/tembel_kuru.py` (`--ws`, `--k0`, `--sentetik`; `--xref-denetle`, `--permutasyon`, `--ad-haritasi`, `--ust-sinir`) | bitti | `7c68d6a` |
| 7 | **dondurma commit'i** (kural sürümü 1 + kod) | bitti | **`7c68d6a`** |
| 8 | ölçüm H-A1 … H-A5, H-A7 | bitti | bu commit |
| 9 | okuyucu envanteri (adım 6) | bitti | bu commit |
| 10 | mutasyon: 21 / 21 öldü (tasarımın 17'si + 4 ek) | bitti | `6869854` |
| 11 | SINAMA H-A6 (dondurmadan sonra bir kez, 20:46) | bitti | bu commit |
| 12 | tam takım: 11 044 geçti / 18 atlandı / 0 kaldı (152 seçilmedi; 688,9 sn, yük altında) | bitti | bu commit |

## Kural metni ↔ Ek B-1 betiği: uygulanan okuma

- Genişleme `STANDART` ve `TASLAK` fonksiyona girmez, onlardan geçmez; E üyesi sınıfına bakılmadan seçilir ama `STANDART` / `TASLAK` E üyesinden genişleme ilerlemez (kural metni). Ek B-1'in betiği E üyelerinden sınıfa bakmadan ilerliyordu. Ollama'da fark yok: E = {`100081fb0` `entry` taslağı (giriş adresi + Ghidra adı), `10038e740` `main.main` (`KENDI`)}; B1'in program fonksiyonu sayısı iki okumada da 36.
- Ek B-1 giriş adresini yalnız program fonksiyonları arasında aradı; kural metni "giriş adresini içeren Ghidra fonksiyonu" diyor, bu yüzden `entry` taslağı E'de ve B1'de (B1 = 37 öğe = 36 + 1; B6 = 398). Tasarımın H-A1 metni de "B1 36 (+ giriş taslağı `entry`)" diyor: fark yok.
- Seçim sha256'sının tanımı Ek B-1'den farklı (ön kayıtta yazılı: adres + basamak + sınıf satırları, giriş taslağı dahil); Ek B-1'in `16fd504d…` değeriyle karşılaştırılamaz. Bu çalışmanın değeri `74ca4488ac9f8d27…`.

## Ölçüm sonuçları (ön kayıt `9991574`; ölçüm 20:44–20:46, yük altında, `uptime` 23,10 / 21,69 / 23,32 → 17,20 / 20,24 / 22,60)

### H-A1 — TUTTU

| | Öngörü | Ölçülen |
|---|---|---|
| sınıf `KENDI` / `BILINMIYOR` / `BAGIMLILIK` / `STANDART` / `TASLAK` | 1 406 / 2 619 / 594 / 8 541 / 399 | 1 406 / 2 619 / 594 / 8 541 / 399 |
| B1 | 36 (+ `entry`) | 37 = 36 program + `entry` taslağı |
| B2 / B3 / B4a / B4b / B5 / B6 | 1 373 / 1 236 / 547 / 836 / 591 / 398 | 1 373 / 1 236 / 547 / 836 / 591 / 398 |

- Gövde baytı: B1 24 448 (= 24 444 + taslağın 4 B'ı), B2 624 256, B3 938 516, B4a 227 380, B4b 132 589, B5 298 060, B6 3 664; seçilmeyen (`STANDART`) 3 168 916; program 5 414 161 (Ek B-1 ile aynı).
- B1'in sınıfı: `KENDI` 33, `BAGIMLILIK` 3, `TASLAK` 1. Go eşlenen 10 460 / 10 601 Go fonksiyonu; ObjC eşlenen 150; ana modül `github.com/ollama/ollama`; taban farkı 0.
- Gösterinin 17 adı: B3 10, B4a 5, B4b 2; en geç konum 3 832 (0 tabanlı; Ek B-1'deki 3 831'e giriş taslağının eklediği 1).
- Özet: `ozet/ollama.json`, `ozet/HA1_ollama.json`, `ozet/HA1_17ad.txt`.

### H-A2 — TUTTU

- 20 permütasyon (tohum 0 … 19; fonksiyon, dizgi, başvuran, düğüm, çağıran / çağrılan listeleri ve Go / ObjC kayıtları karıştırıldı): 9 / 9 çalışma alanında tek sha, karıştırılmamış girdininkiyle aynı. A/A tarafında da 8 / 8.
- S8 tabanı ↔ A/A tekrarı seçim sha256'sı: 8 / 8 aynı (çağıran sırası farkı seçimi etkilemiyor; A/A'da `called_by` ham farkı 13 … 813 fonksiyon).

### H-A3 — TUTMADI (katı JSON eşitliği 3 / 9); küme düzeyinde 9 / 9 eşit

| Çalışma alanı | fonksiyon | JSON-eşit (sıra-normal) fonksiyon | `strings_used` yalnız sıra farkı | `called_by` ham farkı (P16e öncesi) | `total_functions` / `total_strings_with_xrefs` eşit |
|---|---|---|---|---|---|
| Ollama (gösteri) | 13 559 | 13 512 | 47 | 1 759 | evet / evet (1 803) |
| debian cat | 296 | 296 | 0 | 13 | evet / evet (58) |
| debian sort | 625 | 625 | 0 | 34 | evet / evet (167) |
| debian htop | 1 148 | 1 147 | 1 | 191 | evet / evet (728) |
| debian sqlite3 | 1 144 | 1 143 | 1 | 151 | evet / evet (1 021) |
| debian tmux | 2 588 | 2 582 | 6 | 581 | evet / evet (1 744) |
| debian tree | 250 | 249 | 1 | 36 | evet / evet (172) |
| debian zstd | 1 444 | 1 444 | 0 | 224 | evet / evet (2 981) |
| mac tmux | 2 821 | 2 765 | 56 | 813 | evet / evet (2 540) |
| **toplam** | **23 875** | **23 763** | **112** | — | 9 / 9 |

- Karşılaştırma `called_by` için sıra-normal (taban ve gösteri P16e'den önce üretildi; ham fark ayrıca yazıldı). `functions_called` 9 / 9'da sırasıyla birebir; `name`, anahtar kümesi, `strings_used` kümesi ve değerleri 9 / 9'da eşit.
- 112 sıra farkının 112'si aynı başvuru adresinden (tek komuttan) birden çok dizgiye başvurulan fonksiyonlarda (`ozet/HA3_sira_farki.txt`): döküm sırası başvuru adresine göre azalmayan, eşit adres içindeki sıra Ghidra'nın `getReferencesFrom` sırası ve `strings.json`'da yok. Türetme eşit adreste dizgi adresine göre diziyor. Bu bilgi K1 çıktısından türetilemez.
- `total_globals_with_xrefs`: dökümde sayı (ör. Ollama 173 498), türetilende `null` (tasarım gereği "ölçülmedi").
- Hüküm için not (tasarım §1.3 madde 3): "Tutmazsa xref adımı seçili küme için Ghidra'da koşar, türetme yalnız seçilmeyenler için kullanılır ve fark kayda geçer." Karar OL10-D'nin; seçenekler aşağıda "OL10-D için".

### H-A4 — TUTTU (birincil kesim ⌊P/2⌋; dayanağı zayıf)

| İkili | P (program fn) | `FUN_` adlı (eşlenen) | ⌊P/2⌋ kesiminde seçili | ⌊N/2⌋ kesiminde (taslak dahil; ikincil) |
|---|---|---|---|---|
| cat | 107 | 13 | 13 | 13 |
| sort | 244 | 12 | 12 | 12 |
| htop | 609 | 5 | 5 | 5 |
| sqlite3 | 429 | 12 | 9 | 12 |
| debian tmux | 1 920 | 165 | 165 | 165 |
| tree | 119 | 5 | 2 | 5 |
| zstd | 1 086 | 55 | 41 | 52 |
| mac tmux | 2 588 | 235 | 229 | 232 |
| **toplam** | | **502** | **476 (%94,8)** | 496 (%98,8) |

- Öngörü ≥ %60 → tuttu (toplam oran). İkili başına tree %40 (2 / 5) eşiğin altında; öbürleri ≥ %74,5.
- Sınırı: adların çoğu dizgi kanallarından geliyor; kural da dizgi başvurusunu kanıt sayıyor. İkisi aynı kanıta dayandığı için bu sonuç "kural okunacak kodu öne alıyor" sorusunu sınamaz, yalnız "ad kanallarının girdisi seçili kümede kalıyor" der.
- `ust_sinir = 0` iken 8 C ikilisinin 8'inde seçilmeyen 0 (seçili küme bütün fonksiyonlar; `STANDART` yok). Testte de var (`test_c_ikilisinde_sinirsiz_secim_butun_fonksiyonlar`).
- ELF C ikililerinde B1 tek üye (`entry`): `main` `__libc_start_main`'e gösterici olarak geçiyor, çağrılmıyor; çağrılan `__libc_start_main` taslak. mac tmux'ta B1 61 (Mach-O girişi doğrudan `main`).

### H-A5 — terminal-notifier TUTTU; docker-cli raporlandı (K0)

- terminal-notifier: 32 ObjC IMP adresinin 32'si `KENDI`. K0 fonksiyon başlangıcı 92; kalan 60 `BILINMIYOR`.
- docker-cli (Go 35 049 fonksiyon; ana modül `github.com/docker/cli`): `KENDI` 2 795 (%8,0), `BAGIMLILIK` 20 102 (%57,4), `STANDART` 12 110 (%34,6; standart 9 030 + çalışma zamanı 1 557 + derleyici 1 523), `BILINMIYOR` 42 (paketsiz 41 + adsız 1). Görüntünün `fonksiyon_baslangiclari`'ı bu ikilide 0 döndü (K0 adres kümesi yalnız Go tablosundan).

### H-A6 — SINAMA (dondurma `7c68d6a`'dan sonra bir kez, 2026-11-23 20:46; yük 17,20): docker-compose öngörüsü TUTMADI

| İkili | K0 fonksiyon başlangıcı | `KENDI` | `BAGIMLILIK` | `STANDART` | `BILINMIYOR` |
|---|---|---|---|---|---|
| docker-compose (Go; ana modül `github.com/docker/compose/v2`) | 90 257 | 1 477 | 75 616 | 12 923 | 241 (üst veride 62) |
| iTerm2 (ObjC + Swift + C++) | 109 608 | 41 305 (ObjC IMP) | 0 | 0 | 68 303 |
| llama-server (C++) | 17 211 | 0 | 0 | 0 | 17 211 |

- docker-compose `STANDART` payı (üst verili 90 078 fonksiyon üstünden) %14,3; öngörü ≥ %50 → **tutmadı**. Neden: öngörünün dayanağı ("Go adlarının %72,3–%93,6'sı kitaplık") standart kitaplıkla üçüncü taraf kitaplığı birlikte sayıyor; kural üçüncü tarafı `BAGIMLILIK`'a ayırıyor (%83,9). `STANDART` + `BAGIMLILIK` = %98,3. Kural değiştirilmedi.
- iTerm2: Swift (P-ÜV3) ve C++ RTTI (P-ÜV4) okuyucuları kural sürümü 1'de yok (§2.2); o fonksiyonlar `BILINMIYOR`. Statik bağlanmış üçüncü taraf ObjC kitaplıkları da `KENDI` sayılıyor (§2.2'nin bilinen sınırı).
- llama-server: üst veri yok; hepsi `BILINMIYOR`.
- Özet: `ozet/sinama_k0_{docker-compose,iTerm2,llama-server}.json`.

### H-A7 — TUTTU (yük altında)

- `sec` gösteri girdisinde (13 559 fonksiyon, 13 160 program): 0,0154 sn (≤ 5 sn). Aracın bütün koşusu (içe aktarma, JSON okuma, üst veri okuma dahil) 2,3 sn duvar süresi.
- 163 141 fonksiyonluk sentetik girdi (`tembel_kuru.py --sentetik 163141 --tohum 0`): 0,511 sn (≤ 60 sn). Sentetik girdide JSON okuma ve `girdiden_kur` yok; yalnız `sec`.

## Okuyucu envanteri (adım 6)

Komut: `grep -rn "function_xrefs\|total_globals_with_xrefs\|strings_used\|called_by" karadul ui scripts` (+ `functions_called`, `ghidra_xrefs`). `ui/` içinde okuyucu yok.

| Okuyucu | Okuduğu alanlar | Sıraya duyarlı mı | Türetilen dosyada eksik alan |
|---|---|---|---|
| `karadul/reconstruction/c_namer.py` `_load_xrefs` | `function_xrefs[].name/address/strings_used[].value/functions_called[].name` | `strings_used` ekleme sırası korunuyor (fonksiyonun dizgi listesine eklenir) → olabilir | yok |
| `karadul/reconstruction/binary_name_extractor.py` `_load_function_xrefs` + Yöntem 1 | `function_xrefs[].strings_used[].address/value` | `analyze_strings` sonucunun ilki seçiliyor; eşit güvende girdi sırası belirleyici olabilir | yok |
| `karadul/reconstruction/tarif/evidence.py` | `functions_called[].name/address`, `called_by[].address` (küme), `strings_used[].value` (liste) | `strings` listesi sıralı kalıyor → olabilir | yok |
| `karadul/reconstruction/tarif/kesin.py` | `strings_used[].address/value`, `called_by[].address` | hayır (küme; ilk değer, değerler aynı) | yok |
| `karadul/pipeline/steps/_engineering_helpers.py` `function_strings_from_xrefs` | `name`, `strings_used[].value` | liste sırası korunuyor → olabilir | yok |
| `karadul/lm/tools/index.py` | `functions_called[].name/address`, `strings_used[].value` | hayır (sayım ve küme) | yok |
| `karadul/lm/tools/read.py`, `read_more.py` | yalnız kaynak etiketi metni | — | — |
| `karadul/reconstruction/recovery_layers/signature_fusion.py` `_boost_by_xref_count` | üst düzeyde adres anahtarı + `xref_count` arıyor | — | dökümün biçimi bu değil (üst düzey `program/statistics/function_xrefs`); bugün de hiç eşleşmiyor; türetilenin ek `kapsam`/`kaynak` alanları davranışı değiştirmez |
| `karadul/reconstruction/engineering/data_flow.py` `_apply_xrefs_validation` | üst düzey girdilerde `refs_to/refs_from/references` | — | aynı: bugünkü döküm biçimiyle eşleşmiyor; ek alanlar dizgi olduğu için atlanır |
| `karadul/ghidra/headless.py` (köprü günlük satırı) | `statistics.total_*` | — | `total_globals_with_xrefs` yalnız Ghidra'nın koştuğu yolda okunuyor; tembel kipte xref adımı koşmayacak (OL10-D) |
| `scripts/arge/hiz/gecis_sayimi.py` | `statistics.total_globals_with_xrefs` (aritmetik) | — | **`null` ile hata verir** (ölçüm betiği; tembel çalışma alanında koşulursa) |
| `scripts/arge/olcek/gosteri_oku.py` | günlükten `total_globals_with_xrefs` (düzenli ifade, sayı) | — | tembel koşunun günlüğünde satır olmaz → "yok" |
| `scripts/arge/hiz/s8_esitlik.py`, `scripts/measurement/p04a_olc.py`, `scripts/arge/olgu/*`, `scripts/arge/kimlik/veri.py`, `scripts/measurement/macho_reach.py`, `scripts/string_bridge_benchmark.py`, `scripts/varname_f1_eval.py` | `function_xrefs` / `strings_used` / `called_by` (ölçüm betikleri) | betiğe göre | yok |
| `karadul/analyzers/signature_db.py`, `block_annotator.py`, `c_comment_generator.py`, `domain_classifier.py` | `strings_used` / `called_by` yalnız parametre adı, etiket ya da belge metni (dosya okumuyor) | — | — |

Sonuç: türetilen dosyada ürün okuyucularının istediği alanların hepsi var; tek değer farkı `total_globals_with_xrefs = null` (ürün kodunda yalnız köprünün günlük satırı okuyor). Sıraya duyarlı olabilecek dört okuyucu (`c_namer`, `binary_name_extractor`, `tarif/evidence`, `_engineering_helpers`) 112 fonksiyonluk eşit-adres sıra farkından etkilenebilir; etkisi ölçülmedi (OL10-B'nin denetim kolu ölçebilir).

## Test ve mutasyon

- `tests/test_ol10a_secim.py` 25, `tests/test_ol10a_xref.py` 7: 32 geçti. Ghidra yok, sentetik girdi.
- Mutasyon (`scripts/measurement/mutation_specs_ol10a.json`): 21 killed, 0 survived, 0 error (tasarımın 17 mutantı + dizgi adresine göre sıralama, `called_by` sıralanmaz, `entry` adı, giriş adresini içeren fonksiyon); bitince `git diff` temiz. Bir mutantı öldürmek için `strings_used` sıra sınamasının girdisi güçlendirildi (`6869854`).

## OL10-B / OL10-C / OL10-D için notlar

- **OL10-B:** S = B1–B4 Ollama'da 4 029 öğe (4 028 program + `entry` taslağı). x-tam kolunda `tembel_xref.turet` çıktısı 112 fonksiyonda (gösteride 47) `strings_used` sırasıyla dökümden farklı; kısmi analizin etkisini bu sıra farkından ayırmak için bir denetim kolu öneriyorum: tam kol (dökülen xref) ↔ tam kol (türetilen xref). Fark 0 değilse sıra duyarlı okuyucu (yukarıdaki dört) adıyla yazılır.
- **OL10-C:** seçim künyesi `SecimSonucu.kunye()`; sha tanımı `tembel_secim.sira_ozeti` (ön kayıtta yazılı). Ghidra adresi ↔ ikili adresi farkı `tembel_girdi.taban_farki(functions_json, ikili)`; S8'in PIE ELF'lerinde 0x100000, Mach-O'da 0 ölçüldü. İkili yolu verilmezse fark 0 kabul edilir ve PIE ELF'te giriş adresi eşlenmez (E yalnız Ghidra'nın `entry` adı; htop'ta Ghidra adı `entry` değil, giriş yalnız adresten bulundu).
- **OL10-D:** H-A3 katı eşitlikte tutmadı; neden tek ve dar (aynı komut adresinden çok dizgi başvurusunun sırası). Seçenekler: (a) tasarımın yedeği: seçili küme için xref Ghidra'da, seçilmeyenler türetmeyle; (b) K1'in `strings.json`'ına başvurunun komut içi sırası eklenir (`headless.py`, `_extract_strings`) ve türetme o alanla birebir olur; (c) fark kabul edilir ve kayda geçer. (b) kısmi ve tam kipte aynı çıktıyı verir; karar OL10-D'nin (ön kayıtla). `total_globals_with_xrefs` tembel kipte `null`; köprünün günlük satırı (`headless.py` xref adımı) tembel kipte koşmayacağı için ürün okuyucusu kalmıyor.
- **Seçim kuralı için (sürüm 2 adayları; bu pakette değiştirilmedi):** (1) ELF C'de B1 yalnız `entry` (main çağrılmıyor, gösterici olarak geçiyor); `main` kurtarma (`_recover_main_from_entry`) sonrası `main`'i E'ye almak ayrı karar. (2) iTerm2'de 68 303 fonksiyon `BILINMIYOR` (Swift / C++ okuyucuları kurala bağlanınca azalır).

## Tam takım

- Komut: worktree kökünden `PYTHONDONTWRITEBYTECODE=1 python -m pytest -q -p no:cacheprovider`; çalışma verisi bağları (`sigs`, `vendor`, `scripts/node_modules`, `signatures*.json`, `sigs_macos_system.json`, `signatures.lmdb`) geçici symlink olarak kuruldu, koşudan sonra kaldırıldı (commit'lenmedi).
- Sonuç (HEAD `6869854`, 20:44:24 – 20:55:56): **11 044 geçti / 18 atlandı / 0 kaldı**, 152 seçilmedi; 688,85 sn. Yük altında: başlangıçta `uptime` 26,40 / 22,12 / 23,50, sonda 15,44 / 13,45 / 17,37. Koşu sırasında kaynak dosya değişmedi (aynı sırada yalnız salt okur ölçüm koştu ve belge commit'lendi). Akşam tabanındaki (`95d4e3c`) 10 968 / 18 / 0'a göre +76 geçen: 32'si bu paketin testleri; kalan 44'ün dağılımı sayılmadı (o commit'ten sonra main'e BA1 ve PK1'in test dosyaları girdi).
- Günlük: `~/karadul_olcum/runs/dalga1-2026-11-23/OL10A/tam_takim.log`.

## Kalan

- Yok. Koşu kökü `~/karadul_olcum/runs/dalga1-2026-11-23/OL10A/` (Ghidra çalışma alanı yok; yalnız özetler, betikler ve günlükler).

## PAKET BİTTİ
