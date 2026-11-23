# P-ÜV7 — Go tutarlılık denetimi (I4): ilerleme (2026-11-23)

Gönderim metni: `docs/arge/2026-11-23_dalga1/gonderim/PUV7.md`. Plan: `ustveri/PLAN.md` "P-ÜV7".
Dal: `worktree-agent-ade3c0e98c5bfe6e0`, taban `26219df` (main). Sert son 11:30.
Koşu kökü: `~/karadul_olcum/runs/dalga1-2026-11-23/PUV7/` (özet `ozet/`).

## Durum

| Sıra | Kalem | Durum | Commit |
|---|---|---|---|
| 1 | Ön kayıt (`on_kayit_PUV7.md`) | yazıldı | aee60c3 |
| 2 | Tip verisi okuyucu (`go_tip.py`) + sentetik testler | yazıldı | (kitaplık commit'i) |
| 3 | Denetimler T1, T2, T2p, T5, T6 (güçlü); T3, T4 (zayıf) | yazıldı | (kitaplık commit'i) |
| 4 | Damga + ikili özeti | yazıldı | (kitaplık commit'i) |
| 5 | Bozma deneyi betiği (A–E) | bekliyor | — |
| 6 | Kalem 6 (K10) ölçümü ve kararı | bekliyor | — |
| 7 | Mutasyon (≥ 8) | bekliyor | — |
| 8 | Kabul ölçümü (H1, H2, H4, H6, H7; ek ikililer) | bekliyor | — |
| 9 | Dondurma → H3-sınama (docker-compose) | bekliyor | — |
| 10 | Tam takım | bekliyor | — |

## Kalem 2–4: kitaplık (`go_tip.py`, `tutarlilik.py`)

- `karadul/analyzers/ustveri/go_tip.py` — `GoTipVerisi(goruntu, pcln, surum)`: kurucu istisna
  atmaz, `durum` / `neden` yazar. Sürüm kapısı Go 1.20–1.27 (`EN_KUCUK_SURUM`, `EN_BUYUK_SURUM`);
  dışında `desteklenmiyor` (tahmin yok). `moduledata` 37. sözcük `types`; 1.27'de 39 `etypes`,
  40 / 41 `itaboffset` / `itabsize` (itab aralığı `types…etypes` dışındaysa `desteklenmiyor`);
  1.20–1.26'da 38 `etypes`, itab'lar `__itablink` / `.itablink`, ek tipler `__typelink` /
  `.typelink`. `uncommon` (yapı 80, gösterici / dilim 56, dizi 72, kanal 64, arayüz 80, öbürü 48;
  eşlem / fonksiyon atlanır), `arayuz_yontemleri`, `itablar`, `ulasilan_tipler`,
  `ad_ayrintili` (bozma deneyi için ad baytlarının adresi). Metin ofseti −1 / 0 → `None`.
- `karadul/analyzers/ustveri/tutarlilik.py` — `denetle(goruntu, pcln=None, fonksiyonlar=None,
  buildinfo=None, butunluk=None) -> TutarlilikSonucu`; istisna atmaz. T1, T2, T2p, T3, T4, T5,
  T6 araştırma betiğinin tanımıyla; ek olarak P-ÜV1'in fonksiyon başına K4 sonucu (`kisa` /
  `tasan`) `K4` işareti olur ve damgayı `tutarsiz` yapar (ön kayıttaki tanım). Damga, ikili kararı,
  eşik adlandırılmış sabit: `DAMGA_CIFT_KAYNAK`, `DAMGA_TEK_KAYNAK`, `DAMGA_TUTARSIZ`, `DAMGALAR`,
  `KARAR_TEMIZ`, `KARAR_UYARI`, `KARAR_UST_VERI_SUPHELI`, `IKILI_KARARLARI`,
  `UST_VERI_SUPHELI_ESIGI` (0,01), `GUCLU_DENETIMLER`, `ZAYIF_DENETIMLER`, `K4_UYUMSUZ`.
  P-ÜV1'in yapı kararı (`tutarsizlik_nedeni`) ihlal veriyorsa ikili kararı da `ust_veri_supheli`.
- Testler `tests/test_puv7_tutarlilik.py`: 33 (sentetik kurucu: 8 fonksiyon, 7 tip, 4 arayüz,
  4 itab; 1.27 ve 1.26 yerleşimi ayrı; göstericiler düzeltme sözlüğünde, ham sözcük bozuk).
  Kapsanan: itab / tip okuma ×2 yerleşim, yapı `Uncommon` 80 + `ExtraStar`, budanmış yöntem −1,
  ad baytı adresi, desteklenmeyen sürüm ×5, 1.27 itab aralığı dışı, temiz modül damgaları ×2,
  `unreachableMethod` dışlaması, T1+T2 / yalnız T2 / T2p / T5 / T6 yakalama, kaçış çözümü, T3
  zayıf, K4 `tasan` → tutarsız, karar uyarı / eşik, desteklenmeyen sürümde damga, kesik tip
  bölgesi ×4, Go değil, ad yardımcıları.
- Hızlı yoklama (kabul değil; kabul kalem 8'de betikle): `gh` ve `limactl` bozulmamış hâlde T1,
  T2, T3, T4, T5, T6, `isaret_dagilimi`, ikinci kaynaklı sayısı `$V/dusman/<ad>_taban.json` ile
  alan alan aynı.
- Kanca notu: `check-consistency.sh` `UNCOMMON_OFSETI` ve `FUNC_ID` / `FUNC_ID_ADI` için araştırma
  betikleriyle "tutarsızlık" bildirdi; değerler aynı (araştırmada sayısal anahtar, üründe
  adlandırılmış sabit; `FUNC_ID` tabloları programla karşılaştırıldı: eşit). Ürün `go_pclntab.py`
  `FUNC_ID` tablosunu tanımlamıyor → üründeki tek tanım `tutarlilik.py`'de (P-ÜV6b notu).
