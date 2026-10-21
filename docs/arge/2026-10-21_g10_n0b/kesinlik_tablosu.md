# N0b adım 2: alt kanal başına kesinlik (G4 etiketleriyle)

- **Ön kayıt:** `alt_kanal_onkayit.md` (commit f23f4ea), §4-§5 aynen.
- **Betikler:** `alt_kanal.py` sha256 `d0e6f54431d77f26…` (denetlendi); `alt_kanal_olc.py` sha256 `2d743b327aa67a2b…`.
- **Öğeler:** L1 `tmux_385_kor` ve L3 `htop_kor`, yemler hariç. `tam` anahtardaki otomatik eşleşmeden; yakın = `tam` + `dogru_tarif`; yanlış = `yanlis` (yanlış fiil dahil).
- **Eşlenme:** 482/482 (%100,0); taban ad denetimiyle.
- **Kural:** yanlış oranının Wilson %95 aralığı [L, U], eşik %10. `dogrulandi` (U ≤ %10) ve `belirsiz` kalır; `zayif` (L > %10) ve `olculemedi` (n = 0) susar. Karar birleşik sayılarla.

## Birleşik tablo ve karar

| Alt kanal | n | yanlış | %95 aralık | yakın | tam | yalnız alan | karar | üründe | etiket |
|---|---|---|---|---|---|---|---|---|---|
| `agresif` | 0 | — | — | — | — | — | `olculemedi` | hayır | — |
| `kod_parcasi` | 46 | %100,0 | %92,3-%100,0 | %0,0 | %0,0 | %0,0 | `zayif` | hayır | — |
| `bicim_parcasi` | 18 | %66,7 | %43,7-%83,7 | %5,6 | %0,0 | %27,8 | `zayif` | hayır | — |
| `oz_ad` | 52 | %7,7 | %3,0-%18,2 | %84,6 | %82,7 | %7,7 | `belirsiz` | evet | doğrulanmadı |
| `tek_sozcuk` | 68 | %95,6 | %87,8-%98,5 | %2,9 | %2,9 | %1,5 | `zayif` | hayır | — |
| `tanimlayici` | 53 | %28,3 | %18,0-%41,6 | %18,9 | %0,0 | %52,8 | `zayif` | hayır | — |
| `kebap_ad` | 74 | %10,8 | %5,6-%19,9 | %8,1 | %0,0 | %81,1 | `belirsiz` | evet | doğrulanmadı |
| `hata_iletisi` | 52 | %84,6 | %72,5-%92,0 | %3,8 | %0,0 | %11,5 | `zayif` | hayır | — |
| `bicim_dizgisi` | 63 | %34,9 | %24,3-%47,2 | %19,0 | %1,6 | %46,0 | `zayif` | hayır | — |
| `duz_metin` | 38 | %65,8 | %49,9-%78,8 | %2,6 | %0,0 | %31,6 | `zayif` | hayır | — |
| `diger` | 12 | %58,3 | %32,0-%80,7 | %16,7 | %0,0 | %25,0 | `zayif` | hayır | — |

**Tek kanal okuması** (bütün `string_context`, n = 476): yanlış %52,1 (%47,6-%56,6), yakın %16,8; karar `zayif`.

**`hepsini_kapatir()`:** hayır.

## Program başına (yalnız rapor)

| Alt kanal | tmux n | tmux yanlış | tmux karar | htop n | htop yanlış | htop karar |
|---|---|---|---|---|---|---|
| `agresif` | 0 | — | `olculemedi` | 0 | — | `olculemedi` |
| `kod_parcasi` | 36 | %100,0 | `zayif` | 10 | %100,0 | `zayif` |
| `bicim_parcasi` | 12 | %50,0 | `zayif` | 6 | %100,0 | `zayif` |
| `oz_ad` | 52 | %7,7 | `belirsiz` | 0 | — | `olculemedi` |
| `tek_sozcuk` | 34 | %91,2 | `zayif` | 34 | %100,0 | `zayif` |
| `tanimlayici` | 53 | %28,3 | `zayif` | 0 | — | `olculemedi` |
| `kebap_ad` | 74 | %10,8 | `belirsiz` | 0 | — | `olculemedi` |
| `hata_iletisi` | 43 | %83,7 | `zayif` | 9 | %88,9 | `zayif` |
| `bicim_dizgisi` | 55 | %34,5 | `zayif` | 8 | %37,5 | `zayif` |
| `duz_metin` | 15 | %66,7 | `zayif` | 23 | %65,2 | `zayif` |
| `diger` | 5 | %80,0 | `zayif` | 7 | %42,9 | `zayif` |
| *tek kanal* | 379 | %44,6 | `zayif` | 97 | %81,4 | `zayif` |

**`string_context` dışı öğeler** (karar yok): `api_param_reverse` n = 5, yanlış 5, yakın 0, `binary_extract` n = 1, yanlış 1, yakın 0.

## Betimsel kırılımlar (birleşik `string_context`, karar dışı)

| Kırılım | n | yanlış | %95 aralık | yakın |
|---|---|---|---|---|
| kaynak = `body_literal` | 49 | %98,0 | %89,3-%99,6 | %0,0 |
| kaynak = `string_ref` | 427 | %46,8 | %42,2-%51,6 | %18,7 |
| k = `1` | 74 | %95,9 | %88,7-%98,6 | %2,7 |
| k = `2` | 136 | %47,1 | %38,9-%55,4 | %14,0 |
| k = `3` | 142 | %27,5 | %20,8-%35,3 | %34,5 |
| k = `4` | 124 | %59,7 | %50,9-%67,9 | %8,1 |

## Duyarlılık (karar dışı)

- **`capraz_atif > 0` öğeler dışarıda.** Dışarıda kalan: htop 24, tmux 152. Ana karardan farklı alt kanal: yok.
  `kod_parcasi` n = 40, yanlış %100,0; `bicim_parcasi` n = 12, yanlış %75,0; `oz_ad` n = 30, yanlış %3,3; `tek_sozcuk` n = 44, yanlış %100,0; `tanimlayici` n = 24, yanlış %25,0; `kebap_ad` n = 40, yanlış %17,5; `hata_iletisi` n = 42, yanlış %85,7; `bicim_dizgisi` n = 36, yanlış %33,3; `duz_metin` n = 27, yanlış %74,1; `diger` n = 8, yanlış %37,5.
- **tmux için L3 `tmux_200_kor` etiketleri.** Eşlenme 200/200. Ana karardan farklı alt kanal: `tanimlayici` (zayif → belirsiz), `kebap_ad` (belirsiz → zayif).
  `kod_parcasi` n = 23, yanlış %100,0; `bicim_parcasi` n = 12, yanlış %75,0; `oz_ad` n = 21, yanlış %0,0; `tek_sozcuk` n = 51, yanlış %100,0; `tanimlayici` n = 19, yanlış %21,1; `kebap_ad` n = 31, yanlış %35,5; `hata_iletisi` n = 45, yanlış %82,2; `bicim_dizgisi` n = 46, yanlış %26,1; `duz_metin` n = 36, yanlış %61,1; `diger` n = 8, yanlış %50,0.

## Özet

- Üründe kalan alt kanallar: `oz_ad` (doğrulanmadı), `kebap_ad` (doğrulanmadı).
- N1'de susturulacak alt kanallar: `agresif` (olculemedi), `kod_parcasi` (zayif), `bicim_parcasi` (zayif), `tek_sozcuk` (zayif), `tanimlayici` (zayif), `hata_iletisi` (zayif), `bicim_dizgisi` (zayif), `duz_metin` (zayif), `diger` (zayif).
- Ayrıntı ve bütün aralıklar: `kesinlik_tablosu.json`.
