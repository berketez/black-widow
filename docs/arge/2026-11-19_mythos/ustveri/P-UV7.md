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
| 5 | Bozma deneyi betiği (A–E) | yazıldı; H2 TUTTU | (betik commit'i) |
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

## Kalem 5: bozma deneyi betiği (`scripts/measurement/ustveri_bozma.py`)

- Alt komutlar: `taban <ikili> [--dilim]` (bozulmamış ikilide denetim özeti), `deney <ince ikili>
  [--k10]` (A–E), `k10 <ince ikili>` (kalem 6 ölçüsü, `capstone`). İkili çalıştırılmaz; bozuk
  kopyalar yalnız bellekte (`goruntu.baytlardan`); özgün dosyaya yazılmaz, diske kopya yazılmaz.
- Betik depo kökünü `sys.path`'in önüne koyar: `python scripts/…` ile koşulunca editable kurulumun
  gösterdiği ana ağaç değil, worktree'nin `karadul`'u yüklenir (ilk koşuda `ImportError` ile
  görüldü, düzeltildi).
- Örneklem araştırmanınkiyle aynı (aday dışlaması T3 dahil "araştırma güçlü" tanımıyla). Rapor iki
  sütun: `arastirma` (başvuruyla karşılaştırma) ve `urun` (ürün damgası `tutarsiz`; K4 ürünün
  `pcsp_kapsama` sonucu).

### H2 — aynı tohumla A–E başvuruyla aynı → TUTTU

Komut: `python scripts/measurement/ustveri_bozma.py deney $V/hedef/<ad> --cikti
~/karadul_olcum/runs/dalga1-2026-11-23/PUV7/ozet/deney_<ad>.json` (yük altında, ~6–7 sn / ikili).
`arastirma` sütununun bütün alanları (`guclu_denetim_yakaladi`, ikinci kaynaklıda / kaynaksızda,
yalnız T4, K4, hiçbiri, `yakalayan_denetim`, bozulmayanda yeni işaret) + bozulan ve ikinci kaynaklı
bozulan sayıları `$V/dusman/<ad>.deney.json` ile 10 / 10 koşuda aynı. Taban güçlü işaretli
(araştırma tanımı) gh 154 / 154, limactl 2 448 / 2 448.

| İkili | Tür | Bozulan | Araştırma sütunu (= başvuru) | Ürün damgası `tutarsiz` | Ürün: güçlü T | Ürün: K4 `pcsp_kapsama` | Bozulmayanda yeni `tutarsiz` | İkili kararı |
|---|---|---|---|---|---|---|---|---|
| gh | A | 200 | 66 | 66 | 66 | 0 | 0 | uyari |
| gh | B | 200 | 181 | 68 | 68 | 0 | 0 | uyari |
| gh | C | 200 | 73 | 73 | 73 | 0 | 0 | uyari |
| gh | D | 86 | 0 | 0 | 0 | 0 | 0 | uyari |
| gh | E | 200 | 65 (+ K4 160) | 181 | 65 | 159 | 0 | uyari |
| limactl | A | 200 | 84 | 84 | 84 | 0 | 0 | uyari |
| limactl | B | 200 | 192 | 92 | 92 | 0 | 0 | uyari |
| limactl | C | 200 | 82 | 82 | 82 | 0 | 0 | uyari |
| limactl | D | 451 | 0 | 0 | 0 | 0 | 0 | uyari |
| limactl | E | 200 | 67 (+ K4 166) | 177 | 71 | 165 | 0 | uyari |

Okuma:
- B'de araştırma sütunu 181 / 192, ürün 68 / 92: farkı T3 yapıyor (araştırmada güçlü sayılıyordu;
  ürün planı gereği zayıf). Ürünün B yakalaması yalnız ikinci kaynaklı fonksiyonlarda.
- E'de ürün 181 / 177: K4 `pcsp_kapsama` (fonksiyon başına, P-ÜV1) + T. Araştırmanın K4'ü 160 /
  166 (birleştirici dili ayrımı yok); ürününki 159 / 165.
- **İkili kararı hiçbir bozmada `ust_veri_supheli`'ye çıkmadı:** 200 fonksiyonun bozulması
  40 000'lik ikilide en çok %0,45 güçlü işaret veriyor (< %1). Eşik yalnız toplu bozmayı / bozuk
  üst veriyi yakalar; tek tek ad tahrifatını fonksiyon başına damga yakalıyor (H7'ye bakınız).
- limactl E'de güçlü T ürün 71, araştırma 67: araştırmanın güçlü tanımı T3'ü de içerdiği için
  tabanda T3 işaretli fonksiyonlar "yeni" sayılmıyordu; ürün sütunu T3'süz tabana göre sayar.
