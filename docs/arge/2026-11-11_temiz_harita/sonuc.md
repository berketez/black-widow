# Temiz çıktının ad haritası ve README'si: dürüstlük onarımı (2026-11-11)

Kaynak bulgular: `docs/arge/2026-11-10_cikti_saglamligi/rapor.md` bulgu 6 ve 20; yeni üründe
yineleme `yeni_urun_karsilastirma.md`. Ürün kodunda yalnız `karadul/core/output_formatter.py`
değişti (ek olarak test, mutasyon tanımı ve bu belge).

## 1. Kök nedenler

Denetim (`docs/arge/2026-11-10_cikti_saglamligi/denetle.py`) dört sınıfı şöyle sayıyor:

| Sınıf | Denetimin ölçüsü | Kök neden (HEAD 1c78ec6) |
|---|---|---|
| `harita_uygulanmayan` | `denetle.py:821-838`: Ghidra fonksiyonunun son tanım adı ham adıyla aynı, ama `out/naming_map.json` `mappings[ghidra_adı]` başka bir ad diyor | `output_formatter.py:540-614`: `binary_names`, `signature_matches`, `byte_pattern_matches`, `computation_recovery` kayıtları koda uygulanıp uygulanmadığına bakılmadan `mappings`'e yazılıyor (yeni üründe 6 675'in hepsi `signature_db`) |
| `out_harita_ozdes_esleme` | `denetle.py:904-906`: `mappings[k].new_name == k` | aynı yer, `:558-565`: imza kaydı `original == matched` olduğunda da yazılıyor (`strlen → strlen`) |
| `gecersiz_c_adi:gecersiz_karakter` | `denetle.py:878-888`: `mappings` adı `[A-Za-z_][A-Za-z0-9_]*` değil | `:558-565`: imza adı süzgeçten geçmiyor; ad geçerliliği süzgeci (`reconstruction/name_validity.py`) yalnız c_namer'da (Mach-O `_fdopen$DARWIN_EXTSN → fdopen$DARWIN_EXTSN`) |
| `readme_yapi_uyusmuyor` | `denetle.py:1133-1136`: README varken `out/src/main.c`, `out/src/modules`, `out/src/types` üçü birden diskte değil | `output_formatter.py:888-907`: "Output Structure" dile göre elle yazılmış sabit ağaç; proje ağacı kopyalanınca (`:283-286`) bu üç yol hiç yazılmıyor |

Not: `readme_yapi_uyusmuyor` README'nin içeriğine bakmaz, sabit üç yolun diskte olup olmadığına
bakar. Onarımdan sonra da 1 kalır (yollar yazılmıyor ve README artık onları anlatmıyor). Doğrudan
ölçü aşağıda ayrı satırda: README'de adı geçen yolların diskte olmayanı.

## 2. Değişiklik

### README (commit 1)
- "Output Structure" çıktı dizininin iki düzeyli listesi: üst düzey girdiler ve üst düzey
  dizinlerin çocukları; dizinin yanında içindeki dosya sayısı; 20 girdiden kalabalık dizin
  "... (N more)" ile kesilir. Açıklama yalnız biçimlendiricinin yazdığı üst düzey dosyalara.
- "Source Files" diskteki `src/` dosya sayısı. Genel dal (`language: cpp`) aynı adlı dosyaları
  üst üste yazıp her yazmayı sayıyordu: pzstd'de README 12 757, disk 1 201.
- "Names Recovered" = haritadaki `total_mappings` (değişmedi).

### Ad haritası (ayrı dal, bkz. §5)
Biçim 1.1 (`version: "1.1"`). Var olan alanlar korunur, anlamı daralan iki alan:
- `mappings`: yalnız temiz çıktının C kodunda görülen yeniden adlandırmalar. Kayıt alanları
  (`new_name`, `source`, `confidence`, `library`, `label`, `channel`, `evidence` …) aynen.
- `total_mappings`: `len(mappings)`.

Yeni alanlar:
- `applied_check`: `c_source` (src/ altındaki C kodunda doğrulandı) ya da `not_checked`
  (doğrulanacak C kodu yok: JS çıktısı ya da biçimlendiricinin iç çağrısı).
- `candidates`: koda uygulanmamış kayıtlar, alanlarıyla birlikte + `reason`:
  `same_as_original` (yeni ad koddaki adla aynı), `not_in_code`, ya da `name_validity`
  nedeni (`invalid_c_identifier`, `invalid_c_keyword`, `invalid_type_name`).
- `total_candidates`.

Hiçbir kayıt silinmez: 1.0'daki `mappings` = 1.1'deki `mappings` ∪ `candidates` (bir anahtar
yalnız birinde).

"Koda uygulanmış" kuralı (yorum ve dizgi/karakter sabitleri atılmış .c/.h metninden):
1. yeni ad bir fonksiyon tanımının adı ve eski ad hiçbir tanımın adı değil (tanım yeni adı
   taşıyor; eski ad bir çağrıda kalmış olabilir), ya da
2. eski ad hiçbir tanımın adı değil, yeni ad kodda geçiyor, eski ad kodda hiç geçmiyor (veri
   adları).

"Eski ad": adresten kurulmuş anahtarda (`FUN_00105dc0`) Ghidra'nın o adresteki fonksiyona verdiği
ad (`static/ghidra_functions.json`; ör. `entry`, `_FINI_0`), öbür anahtarlarda anahtarın kendisi.
Bu çözüm olmadan 119 ikilide 8 kayıt yanlışlıkla "uygulanmış" çıkıyordu: 7'si `FUN_… → start`
(kodda `start` yalnız bir yapı alanı ya da yerel adı, giriş fonksiyonu hâlâ `entry`), 1'i
Debian htop `FUN_001322e4 → full_write` (Ghidra o fonksiyona zaten `full_write` adını vermiş).

README'ye "Name Candidates (not applied)" satırı ve `Names Recovered`'ın ne saydığını anlatan bir
cümle eklendi.

## 3. Gerçek veride önce/sonra

Çalışma alanları `~/karadul_olcum/runs/urun-yeni-93a2956/` altından kopyalandı (kaynak salt
okundu): `~/karadul_olcum/runs/temiz-harita-2026-11-11/{once,sonra}/{debian/tree/tree,
debian/sqlite3/sqlite3,mac/htop}`. Betikler `~/karadul_olcum/runs/temiz-harita-2026-11-11/betikler/`.

Komutlar (`W` = worktree, `D` = `~/karadul_olcum/runs/temiz-harita-2026-11-11`, `B` = `$D/betikler`):
```
# önce: HEAD 1c78ec6'nın karadul paketi (git archive) ile yeniden biçimle
PYTHONPATH=<head_src> python3 $B/yeniden_bicimle.py $D/once/<ikili> <head_src>
# sonra: worktree kodu
PYTHONPATH=$W python3 $B/yeniden_bicimle.py $D/sonra/<ikili> $W
python3 $B/ozet_hash.py $D/{once,sonra}/<ikili>              # out/src, ws/, ölçülen harita özetleri
python3 $B/denetle_kopya.py $W/docs/arge/2026-11-10_cikti_saglamligi/denetle.py $D/{once,sonra} $D/denetim_{once,sonra_son}.json
python3 $B/denetim_ozet.py $D/denetim_{once,sonra_son}.json
python3 $B/readme_yollari.py $D/{once,sonra}/<ikili> ...
python3 $B/harita_tablo.py $D/once $D/sonra <ikili> ...
```
Önce kolu HEAD koduyla yeniden üretildi; `naming_map.json` saklı koşununkiyle bayt bayt aynı
(sha256 önekleri tree `f305ed4f…`, sqlite3 `16a47d3d…`, Mac htop `1f51e037…`).

### Dört kusur (denetimin ölçüsüyle) ve sayılar

| | tree önce | tree sonra | sqlite3 önce | sqlite3 sonra | Mac htop önce | Mac htop sonra |
|---|---|---|---|---|---|---|
| `harita_uygulanmayan` | 34 | 0 | 77 | 0 | 195 | 0 |
| `out_harita_ozdes_esleme` | 49 | 0 | 226 | 0 | 1 | 0 |
| `gecersiz_c_adi:gecersiz_karakter` | 0 | 0 | 0 | 0 | 4 | 0 |
| `readme_yapi_uyusmuyor` (vekil ölçü) | 1 | 1 | 1 | 1 | 1 | 1 |
| README'de adı geçip diskte olmayan yol | 3 / 9 | 0 / 15 | 3 / 9 | 0 / 15 | 3 / 9 | 0 / 15 |
| `haritasiz_degisim` + `degisim_haritadan_farkli` | 0 | 0 | 0 | 0 | 0 | 0 |
| denetimin `harita_uygulanan` (adı değişip haritada aynı ad) | 3 | 3 | 18 | 18 | 0 | 0 |
| `total_mappings` (README "Names Recovered") | 74 | 3 | 300 | 18 | 196 | 0 |
| `total_candidates` | — | 71 | — | 282 | — | 196 |
| aday: `signature_db` same_as_original / not_in_code / geçersiz | — | 49 / 20 / 0 | — | 226 / 54 / 0 | — | 1 / 191 / 4 |
| aday: `c_namer` not_in_code | — | 2 | — | 2 | — | 0 |
| `out_harita_ws_haritadan_farkli` (yeni bayrak, §4) | 0 | 1 | 0 | 1 | 0 | 0 |

Üç ikilide de: 1.1 `mappings` ∪ `candidates` = 1.0 `mappings` (aynı anahtarlar); eşleme kayıtları
1.0'dakiyle aynı; aday kayıtları 1.0'dakiyle `reason` dışında aynı. README'deki "Source Files"
diskteki `src/` dosya sayısına (275, 1 168, 845), "Names Recovered" `total_mappings`'e, "Name
Candidates" `total_candidates`'e eşit.

### Değişmeyenler (biçimlendirici yalnız harita ve README'yi değiştiriyor)

`ozet_hash.py` (sha256; dosya sayısı). Her hücrede saklı kaynak, önce ve sonra kolu aynı:

| | `out/src/` | `ws/` | `reconstructed/src/naming_map.json` |
|---|---|---|---|
| tree | `cf20a573…` (275) | `c6a830a4…` (3 343) | `80ca70e8…` |
| sqlite3 | `9a052389…` (1 168) | `7958e9cd…` (14 979) | `f21a32c6…` |
| Mac htop | `411d91f1…` (845) | `93a1505e…` (9 601) | `6b9b2238…` |

`dependency_graph.json` de aynı; `report.json`/`report.html`/`README.md` zaman damgası taşıdığı
için her koşuda değişir.

### 119 ikili (bellekte, salt okunur)

Saklı yeni ürün koşusunun (`urun-yeni-93a2956`) 119 ikilisinde yeni harita bellekte kuruldu
(`_build_naming_map(out/src, dil)`; çalışma alanı nesnesi dizin oluşturmaz) ve denetimin
`kosu_denetle`'si, yalnız `out/naming_map.json` okuması bu haritaya yönlendirilerek, değişmeden
koşturuldu. Koşu sonrası `find … -newer <işaret>` kaynak ağaçta 0 değişen dosya buldu.
```
PYTHONPATH=$W python3 $B/denetle_119_bellekte.py $W/docs/arge/2026-11-10_cikti_saglamligi/denetle.py $W $D/denetim_119_bellekte_son.json
python3 $B/ozet_119.py $D/denetim_119_bellekte_son.json $W/docs/arge/2026-11-10_cikti_saglamligi/sonuc_yeni_urun.json
```

| Sınıf (ikili / adet) | saklı denetim (1.0) | 1.1, bellekte |
|---|---|---|
| `harita_uygulanmayan` | 119 / 6 675 | 0 / 0 |
| `out_harita_ozdes_esleme` | 119 / 9 823 | 0 / 0 |
| `gecersiz_c_adi:gecersiz_karakter` | 2 / 7 | 0 / 0 |
| `haritasiz_degisim`, `degisim_haritadan_farkli` | 0 | 0 |
| `yetim_anahtar` | 117 / 234 | 0 / 0 |
| `out_harita_ws_haritadan_farkli` | 0 | 117 / 117 (§4) |
| denetimin `harita_uygulanan` toplamı | 2 048 | 2 048 (119 koşunun hepsinde koşu başına aynı) |

1.1 haritaların toplamı: `mappings` 2 048 (hepsi c_namer), `candidates` 13 073
(`signature_db`: same_as_original 9 821, not_in_code 3 007, invalid_c_identifier 7; `c_namer`:
not_in_code 235, same_as_original 1; `debug_string`: same_as_original 2). 2 048 + 13 073 = 15 121
= saklı README'lerdeki "Names Recovered" toplamı (kayıt silinmedi). `readme_yapi_uyusmuyor` bu
koşuda ölçülmedi (README yeniden yazılmadı).

## 4. Tüketiciler

| Okuyan | Ne okuyor | 1.1'de |
|---|---|---|
| `ui/server.py` `_name_record` / `_provenance` / liste etiketi | `mappings[FUN_…]`, `new_name == o anki ad` | değişmez: üç ikilide 1 137 fonksiyonda etiket ve köken kartı 0 farklı (`ui_koken.py`) |
| `ui/server.py:1862-1885` `_label_counts` (yedek yol) | `mappings`'teki `label` | yalnız uygulanmış adların etiketleri sayılır |
| **`ui/server.py:597-613` `_external_call_hints`** (ipucu listesi ve `_naming_diagnosis` "kütüphane sarmalayıcı" kararı) | `mappings[çağrılan_sembol].library` | **BOZULUR**: bu kayıtlar (imza veritabanının tanıdığı ithaller) özdeş ya da uygulanmamış olduğu için `candidates`'e geçiyor. İpuçlu fonksiyon / ipucu: tree 93 / 219 → 0 / 0, sqlite3 314 / 987 → 0 / 0, Mac htop 261 / 537 → 0 / 0 (`ui_ipucu.py`) |
| `scripts/measurement/function_f1.py` `load_naming_map` | `mappings[k].new_name` | `find_run_artifacts` önce `reconstructed/src/naming_map.json`'u seçer; temiz haritaya yalnız o yoksa düşer, o zaman yalnız uygulanmış adlar puanlanır |
| `scripts/measurement/alt_kanal.py` `taban_adlandirma` | `mappings` `FUN_…` | yalnız elle verilen yol; uygulanmamış `FUN_` imza kayıtları artık gelmez |
| `tests/benchmark/benchmark_runner.py` `_flatten_naming_map` | `mappings` | aynı |
| `docs/arge/2026-11-11_fonksiyon_karti/envanter_sayim.py` | `mappings` → arayüzün ipucu işlevi | yeniden koşulursa ipucu sayısı 0 çıkar (arayüzle aynı neden) |
| denetim `out_harita_ws_haritadan_farkli` (`denetle.py:770-775`) | temiz haritanın c_namer kayıtları = çalışma alanı haritası | yeni bayrak: çalışma alanı haritasındaki koda ulaşmayan c_namer adları (çoğu önyük anahtarı `FUN_… → start`, `do_global_dtors_aux`) artık `candidates`'te. Denetimin varsayımı yeni anlamla çelişiyor; kusur değil, ama denetim betiği değişmedikçe sayılır |

En küçük arayüz onarımı (uygulanmadı; `ui/` yetkim dışında):
`~/karadul_olcum/runs/temiz-harita-2026-11-11/betikler/ui_server_onerilen.patch` —
`_clean_mappings` `{**candidates, **mappings}` döndürür. Bu birleşimle üç ikilide ipucu çıktısı
1.0 ile fonksiyon fonksiyon aynı (0 farklı), etiket/köken 0 farklı. Daha kalıcı yol
`docs/arge/2026-11-11_fonksiyon_karti/envanter.md:285`'in önerisi: ipucu imza süzgeci yerine
Ghidra'nın ithal çağrılarından.

## 5. Commit'ler

- `df2a843` (worktree dalı): README.
- Bu belge: worktree dalında, README commit'inin üstünde.
- Harita: `temiz-harita-ui-bekliyor` dalında, bu belgenin commit'inin üstünde. Arayüzün
  kütüphane çağrısı ipucunu boşalttığı için (§4) arayüz yaması olmadan main'e alınmamalı;
  `ui/` bu işin yetkisi dışındaydı.

## 6. Testler ve mutantlar

- `tests/test_temiz_harita.py`: 22 test işlevi (README 8, harita 14); parametreli dahil 28 öge.
- `scripts/measurement/mutation_specs_temiz_harita.json`: 25 mutant, 25'i öldü; ölüm nedeni
  25'inde de `AssertionError` (`betikler/olum_nedeni.py`). Eski
  `mutation_specs_adim3_bicimlendirici.json` 8/8 öldü (çapalar korunuyor).
- Tam takım (harita + README kodu, worktree'ye `scripts/node_modules` bağlıyken):
  `python -m pytest tests -q -p no:cacheprovider` → 7 947 geçti, 35 atlandı, 153 seçilmedi
  (pyproject: `not integration and not benchmark`), 0 düştü.

## 7. Sınırlar

- Kural metin düzeyinde: `#define` ile üretilen adlar, işlev göstericisi döndüren tanımlar
  (`code * (*f(int))(void)`) tanım sayılmaz; tanımlayıcı kuralına düşer.
- `not_checked` kolunda (JS) yalnız özdeş girişler ayrılır; JS modül adlarının koda uygulanıp
  uygulanmadığı denetlenmiyor.
- `report.html`'in "Name Recovery" tablosu (`core/report_generator.py:710-737`) hâlâ imza
  eşleşmelerini "Recovered" diye listeliyor; bu iş kapsamında değil.
