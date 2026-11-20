# P-Ö1 — biçim satırı: sonuç

Ön kayıt: `P-O1_on_kayit.md` (commit `992c9cc`, koddan önce). OLCUM paketi (Dalga 0), 2026-11-20. Ölçüm hazır çıktılar üstünde (Ghidra koşusu yok); çıktılar depo dışında: `~/karadul_olcum/runs/dalga0-2026-11-20/OLCUM/po1/`.

## Ne eklendi

- `scripts/measurement/ad_bicimi.py` (yeni): `ek_soy`, `harf_dizisi`, `harf_tam` `scripts/arge/olcu/olcu.py`'den aynen; `KLON_EKI_RE` `ks1_olc`'den içe aktarılır (kopya yok; sınama `ab.KLON_EKI_RE is ks1_olc.KLON_EKI_RE`). Taşıma, başvuru betiğiyle 11 × 11 ad çiftinde aynı sonucu veriyor (`test_tasima_arastirma_betigiyle_ayni`).
- `scripts/measurement/urun_olc.py`:
  - `degerlendir_elf`: her kayda `bicim` (tam doğru ya da `ad_bicimi.harf_tam(ad, [platform_adi(g) …])`; GT'de karşılığı yoksa `False`).
  - `fonksiyon_ozeti`: `bicim_normallestirmesi` (tam + biçim doğru k / n) ve `bicim_yanlis_orani` (tam + biçim yanlış k / n). İkisi `DUYARLILIK_OLCULERI`'nde; `toplam_ozeti` bunlar için havuz ve program düzeyi makroyu `program_makrosu`'nun kuralıyla üretir (birimde en az `N_MIN` ad; platform birimleri önce ortalanır; `$H/taban_puanla.py` `makro`'suyla aynı kural).
  - Planın adım 3'ü yalnız `bicim_normallestirmesi`'ni sayar; adım 4'ün "tam + biçim makro yanlış" satırı ayrı bir alan (`bicim_yanlis_orani`) olarak eklendi: makroyu `1 − makro(doğru)` diye türetmek yerine aynı işlevle doğrudan hesaplamak için. Karar alanlarına (`olcu`, `kol_kararlari`, kırılımlar, `ogeler`, `oge_yaz` / `oge_oku`) dokunulmadı.
  - `olc_markdown` duyarlılık cümlesi ve `karsilastir_markdown` yan yana tablosunun altı: "biçim normalleştirmesiyle doğru k / n; tam + biçim yanlış k / n, tam + biçim makro yanlış x". Alanı olmayan eski JSON'da "biçim satırı: veri yok (P-Ö1'den önceki çıktı)" yazılır; `karsilastir` eski JSON'la çalışır (sınandı).
  - `bicim` alanı olmayan kayıt (başka araçların kurduğu kayıt listesi) yalnız tam eşitlikle sayılır.

## Kabul tablosu (betik çıktısı; ön kayıttaki beklentiyle)

Komut (iki kol; worktree kökünden): `PYTHONDONTWRITEBYTECODE=1 python scripts/measurement/urun_olc.py olc --kok-debian <kök>/debian --kok-mac <kök>/mac --mac-veri /Users/apple/Black_Widow/workspaces/olcum_mac --kol <ad> --json <j> --md <m>`.

| Kol | Ad | Tam doğru | Biçim (tam değil) | Tam + biçim yanlış | Tam + biçim makro yanlış | Hüküm |
|---|---|---|---|---|---|---|
| a62f15e (beklenen) | 1 800 | 1 681 | 40 | 79 (0,043889) | 0,1914 | |
| a62f15e (ölçülen) | 1 800 | 1 681 | 40 | 79 / 1 800 (0,043889) | 0,191449 → 0,1914 (coreutils 0,0070; openssl 0,0769; redis-tools 0,2000; sqlite3 0,5833; tmux 0,1178; zstd 0,1636) | **tuttu** (3 / 3) |
| f30ac9a (beklenen) | 2 261 | 1 589 | 47 | 625 (0,276426) | 0,4077 | |
| f30ac9a (ölçülen) | 2 261 | 1 589 | 47 | 625 / 2 261 (0,276426) | 0,407694 → 0,4077 (coreutils 0,1644; openssl 0,2571; redis-tools 0,5862; sqlite3 0,7500; tmux 0,4884; zstd 0,2000) | **tuttu** (3 / 3) |

**Altı sayının altısı tuttu** (makro ön kayıttaki kuralla 4 ondalığa yuvarlanarak karşılaştırıldı; program değerleri de PLAN'daki a62f15e dökümüyle aynı). Zemin denetimi (ad, tam doğru) iki kolda da tuttu.

**OLCUM kalem 2 (`ks1_olc` `BITTI` içeriği) sonrası yeniden koşu** (ön kayıt değiştirilmedi; satır sonradan eklendi):

| Kol | Bitmişlik (tamam / kısmi / hatalı / bekliyor / çıktısız) | `BITTI` işareti | Ad | Tam doğru | Biçim | Tam + biçim yanlış | Makro | P-Ö1 çıktısıyla |
|---|---|---|---|---|---|---|---|---|
| a62f15e | 119 / 0 / 0 / 0 / 0 | `0` × 119 | 1 800 | 1 681 | 40 | 79 | 0,1914 | `nufus` ve `arac` dışında metin eşit; `nufus`'un eski alanları eşit |
| f30ac9a | 119 / 0 / 0 / 0 / 0 | `0` × 119 | 2 261 | 1 589 | 47 | 625 | 0,4077 | aynı |

Sayı değişmedi: iki kökte de kısmi (`3`) ya da hatalı birim yok (bütün `BITTI`'ler `0`). Kısmi birim bulunmadığı için "hangi birim kısmiydi" listesi boş.

Ön kayıttaki ayrıntı (a62f15e): biçim 40'ın birimleri zstd 37, coreutils 1, openssl 1, mac/tmux 1 — **tuttu**; kanalı 40 / 40 `string_context/oz_ad` — **tuttu** (kanal dağılımı `urun_olc.degerlendir_elf` ile ayrıca sayıldı). f30ac9a'da biçim 47'nin birimleri: zstd 43, openssl 2, coreutils 1, mac/tmux 1 (ön kayıtta beklenti yoktu; yalnız kayıt).

## Var olan alanlar: bayt düzeyinde eski çıktıyla

Yöntem: yeni iki alan (`bicim_normallestirmesi`, `bicim_yanlis_orani`) her düzeyden silinir; kalan belge eski çıktıyla alan alan ve `json.dumps(indent=1)` metni olarak karşılaştırılır.

| Kol | Eski çıktı | Fark | Hüküm |
|---|---|---|---|
| a62f15e | `docs/arge/2026-11-19_birlesik_olcum/urun_olcumu_onarim.json` | yalnız `arac.betik_sha256` (betik değişti) ve `arac.git_head`; `arac` ve `kol` dışındaki her şey (karar (a)–(c), kanal kırılımı, kanal grubu, tabaka, `etiket_kanal`, `ogeler`) metin olarak aynı | **tuttu** |
| f30ac9a | `docs/arge/2026-11-10_n1_adim3/urun_olcumu_yeni2.json` | `arac` 2 alan + `kanal_grubu` 92 alan (birim 64, toplam 28); öbür her şey (kararlar, kanal kırılımı, `ogeler`) aynı | ön kayıttaki kurala göre ertelendi: `kanal_grubu` farkı sınıflayıcı sürümünden (worktree `alt_kanal.SILENCED_SUBCHANNELS` ≠ f30ac9a ağacınınki; ön kayıt "Karşılaştırma kuralı"). Sınıflayıcıyı ürün ağacından yükleyen seçenek (OLCUM kalem 7) ile yeniden denetlenir; sonucu aşağıdaki "Kalem 7 sonrası" satırında. |
| f30ac9a, **kalem 7 sonrası** (`--siniflayici-agac ~/karadul_olcum/urun-f30ac9a`) | aynı | yeni alanlar (`bicim_*`, `nufus.durumlar`, `nufus.bitti_isareti`, `siniflayici`), `arac` ve `kol` dışında metin olarak **aynı** (`kanal_grubu` dahil); sınıflayıcı denetimi iki kökte `ayni` | **tuttu** |
| a62f15e, kalem 7 sonrası (betiğin sınıflayıcısı; denetim `ayni`) | aynı | aynı ölçüt: metin olarak aynı | **tuttu** |

Worktree sınıflayıcısıyla f30ac9a kökünü ölçmek kalem 7'den sonra durur (`DURDU: ad sınıflayıcısı ölçülen ürününkiyle farklı …`, çıkış 2). `karsilastir` eski JSON'la (taban: eski `urun_olcumu_yeni2.json`, yeni: kalem 7 a62f15e çıktısı) çalıştı; birleşik ölçümün `urun_olcumu_fark_yeni2_onarim.json`'uyla yeni alanlar, `arac` ve `kol` dışında aynı.

**P-Ö1 kabulü bütünüyle:** altı sayı tuttu; var olan alanlar iki kolda eski çıktıyla aynı (f30ac9a ürünün sınıflayıcısıyla); `tests/test_urun_olc.py` yeşil.

## Sınama ve mutasyon

- `tests/test_ad_bicimi.py` (yeni, 9 sınama): deve yazımı ↔ küçük harf (`FSE_buildDTable_internal` ↔ `fse_builddtable_internal`), `_2` / `_12`, `.part.0` / `.isra.0` / `.cold.1` / art arda ekler, Mach-O baştaki `_`, boş ad ve yalnız rakam (eşleşmez), bir harf farkı (eşleşmez), iki GT takma adı, ek ifadesinin `ks1_olc`'den gelmesi, başvuru betiğiyle eşitlik.
- `tests/test_urun_olc.py` (ek, 4 sınama): `bicim` alanı (GT yoksa False; Mach-O), duyarlılık satırı ve makro kuralı (platform ortalaması, `N_MIN`), "kararlar değişmez", uçtan uca + eski JSON'la `karsilastir` ("veri yok").
- `scripts/measurement/mutation_specs_po1.json`: planın m1–m5'i + m6 (GT yoksa biçim), m7 (eski JSON "veri yok" denetimi) → **7 / 7 öldü**. Var olan `mutation_specs_urun_olc.json` 65 / 65 öldü (yeni `ad_sayisi` değişkeni, var olan `n = len(kayitlar)` mutantının `find`'ını tekil bırakmak için).

## Yorum sınırı

Bu satır "yanlış ≤ %10" kararını değiştirmez; karar tam eşitlikle verilir (KARARLAR A-3; ürün tarafındaki asıl onarım ÖK-1). a62f15e'de biçim düzeyiyle makro yanlış 0,3105 → 0,1914; bu düşüşün 37 / 40'ı zstd'den (`string_context/oz_ad` adlarının harf düzeni farkı).

Çıktıların sha256'sı: `po1/onarim.json` `05d95ac7a8596cd7…`, `po1/yeni2_worktree_siniflayici.json` `8a5e31c909600f7b…` (betik `urun_olc.py` `1656ae2db92213ec…`, `ad_bicimi.py` `80cbaa76c3065857…`).
