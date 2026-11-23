# P-ÜV7 — Go tutarlılık denetimi (I4): ilerleme (2026-11-23)

Gönderim metni: `docs/arge/2026-11-23_dalga1/gonderim/PUV7.md`. Plan: `ustveri/PLAN.md` "P-ÜV7".
Dal: `worktree-agent-ade3c0e98c5bfe6e0`, taban `26219df` (main). Sert son 11:30.
Koşu kökü: `~/karadul_olcum/runs/dalga1-2026-11-23/PUV7/` (özet `ozet/`).

## Durum

| Sıra | Kalem | Durum | Commit |
|---|---|---|---|
| 1 | Ön kayıt (`on_kayit_PUV7.md`) | yazıldı | aee60c3 |
| 2 | Tip verisi okuyucu (`go_tip.py`) + sentetik testler | yazıldı | 52c3f9a |
| 3 | Denetimler T1, T2, T2p, T5, T6 (güçlü); T3, T4 (zayıf) | yazıldı | 52c3f9a |
| 4 | Damga + ikili özeti | yazıldı | 52c3f9a |
| 5 | Bozma deneyi betiği (A–E) | yazıldı; H2 TUTTU | 85f8a03 |
| 6 | Kalem 6 (K10) ölçümü ve kararı | ölçüldü (≥ %99) → eklendi; H5 TUTMADI | 896753a |
| 7 | Mutasyon (≥ 8) | 15 / 15 öldü | (mutasyon commit'i) |
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

## Kalem 6: K10 içerik denetimi — önce ölçüm, sonra karar

### Ölçüm (kod yazmadan önce; `ustveri_bozma.py k10`, `capstone` 5.0.7)

Bakılan: `pcsp` tablosu olan, birleştirici dili bayraklı olmayan, `pcsp`'si en az bir yerde
sıfırdan farklı fonksiyonlar. Uyum: `pcsp` değerinin ilk kez sıfırdan farklı olduğu pc'den önceki
komut aynı büyüklükte yığın ayarı.

| Dilim | Bakılan | Ön kayıtlı kural: uyumlu (oran) | Tanınmayan / uyumsuz | Genişletilmiş kural: uyumlu (Wilson %95) |
|---|---|---|---|---|
| gh (keşif) | 32 581 | 32 437 (%99,558) | 143 / 1 | 32 581 / 32 581 (%99,988–%100) |
| limactl (keşif) | 32 249 | 32 214 (%99,891) | 34 / 1 | 32 249 / 32 249 (%99,988–%100) |
| Ollama arm64 | 9 254 | 9 240 (%99,849) | 14 / 0 | 9 254 / 9 254 (%99,959–%100) |
| colima | 10 885 | 10 871 (%99,871) | 14 / 0 | 10 885 / 10 885 (%99,965–%100) |

(Bakılmayan: çerçevesiz gh 7 458, limactl 7 717, Ollama 1 047, colima 1 888; birleştirici dili
342 / 352 / 297 / 306; `pcsp` yok 3 / 3 / 3 / 3.)

- **Ön kayıtlı kuralla eşik tuttu** (dört dilimde de ≥ %99) → plan gereği K10 eklendi.
- Tanınmayan / uyumsuz girişlerin hepsi aynı türdü: `mov sp, x20` ile biten büyük çerçeve giriş
  bölümü. Ön kayıtlı kural yalnız `sub xR, sp, #N` + `mov sp, xR`'yi tanıyordu; Go arm64 ayrıca
  (a) `mov x27, #N` [+ `movk x27, #M, lsl #16`] + `sub x20, sp, x27` + `mov sp, x20` ve (b) iki
  parçalı `sub x20, sp, #a` + `sub x20, x20, #b, lsl #12` yazıyor (gh'te 3 örneğin sökümüyle
  görüldü; tek "uyumsuz" (b) kalıbının ilk parçasını tam sanan kuraldandı: 0x610 ↔ 0x19610).
  Kural keşif ikililerinde (gh, limactl) bu iki kalıbı tanıyacak biçimde genişletildi; sonra dört
  dilimde de yanlış alarm 0. Kural değişikliği karardan sonra; karar ön kayıtlı kuralla verildi.
- Ürün çözücüsü `capstone`'a bağlı değil: beş komut biçimi + üç büyük çerçeve biçimi A64 bit
  kodlamasından (`tutarlilik.arm64_yigin_komutu`, `arm64_buyuk_cerceve_komutu`). Ölçüm betiği
  `capstone` ile bağımsız ikinci uygulama: dört dilimde sayımlar ve ihlal kümesi birebir aynı
  (`ozet/k10_<ad>.json` → `urun_cozucusu.ayni_kume = true`).

### E yeniden ölçüldü (`deney --k10`; ürün damgası K10 dahil)

| İkili | E bozulan | K10'suz ürün | K10'lu ürün | Wilson %95 | K10 tek başına | Bozulmayanda yeni K10 | Tabanda K10 ihlali |
|---|---|---|---|---|---|---|---|
| gh | 200 | 181 | 181 | %85,6–%93,8 | 119 | 0 | 0 |
| limactl | 200 | 177 | 183 | %86,8–%94,6 | 115 | 0 | 0 |

- **H5 → TUTMADI:** E yakalaması %90,5 / %91,5; ≥ %95 beklentisi tutmadı. K10 K4'ün kaçırdığı
  çiftlerden yalnız 0 / 6'sını ekledi.
- Neden: K4 komşu fonksiyonların **boyu** farklıysa yakalıyor; boyu aynı olan çiftlerin çoğunun
  çerçeve büyüklüğü ve giriş bölümü de aynı (aynı biçimde üretilmiş kardeş fonksiyonlar), bu
  yüzden giriş bölümüne bakan bir içerik denetimi de onları ayıramıyor. Kalan 19 / 17 çift için
  fonksiyon gövdesinin daha derin bir imzası gerekir (ör. `pcdata` / `funcdata` yığın haritaları ↔
  komut akışı); bu pakette yazılmadı (ölçülmedi).
- A–D'de K10 değişiklik yapmadı (tabanda K10 ihlali 0 olduğu için sayılar K10'suz koşuyla aynı:
  gh A 66, B 68, C 73, D 0; limactl A 84, B 92, C 82, D 0). Araştırma sütunu yine başvuruyla aynı.
- Testler +11 (toplam 44): komut çözümü, uyumlu str / stp / sub sp ×3, büyüklük uyuşmazlığı,
  yığın komutu olmayan, büyük çerçeve `movz` + `movk` + `sub` yazmaç (ve `movk` atlanırsa
  yakalanır), iki parçalı `sub` ×2, çerçevesiz ve birleştirici dili bakılmaz, arm64 dışı
  `desteklenmiyor`, kapatılabilir.

## Kalem 7: mutasyon (`scripts/measurement/mutation_specs_puv7.json`)

**15 mutant, 15 öldü, 0 hayatta, 0 hata** (`karadul/` farkı sonra temiz). Plandaki 8 mutantın hepsi
(`unreachableMethod` dışlaması kalkar; köşeli ayraç soyulmaz; yapı `Uncommon` ofseti 56; itab adımı
`32 + 8n`; T3 güçlü sayılır; `tutarsiz` → `tek_kaynak`; metin ofseti −1 adres sayılır; kaçış
çözülmez) + 7 ek (K4 / K10 damgaya girmez; K10 `movk` parçası atlanır; K10 `str` anlığı
işaretsiz; K10 tanınmayan ihlal değil; eşik %5; sürüm alt sınırı kalkar; 1.27 itab aralığı
denetimsiz).

İlk koşuda 2 hayatta + 1 hata çıktı, ikisi test zayıflığıydı:
- Köşeli ayraç: sentetik adlarda köşeli ayraç son noktadan önce (`p.(*Liste[go.shape.int]).Ekle`)
  olduğu için soymasız da son bileşen doğru çıkıyordu → `p.Esle[go.shape.string,go.shape.int]`
  denetimi eklendi (son noktadan sonra köşeli ayraç).
- Sürüm alt sınırı: bağlı test 1.27 yerleşimiyle kuruluyordu; 1.19'da 1.26 sözcük sırasıyla okunan
  `etypes` akıl dışı çıktığı için ikinci denetim yakalıyordu (mutant gerçekten zararsızdı o
  kurulumda). 1.26 yerleşimiyle kurulan teste (`test_desteklenmeyen_surumde_ad_cift_kaynak_olmaz`)
  bağlandı.
- Hata: `find` metni satır sonu yorumu yüzünden eşleşmedi; yorumsuz alt dizgiyle düzeltildi.
- Ayrıca test kurucusu kitaplığın biçim sabitlerini (`GT.UNCOMMON_OFSETI` …) kullanıyordu: sabiti
  değiştiren mutant kurucuyu da değiştirirdi. Kurucu modülden bağımsız sabit sayılarla yeniden yazıldı.

## Ara düzeltme: T2p önek kuralı (kabul ölçümünün ilk koşusunda görüldü)

- İlk taban koşusunda (10 dilim, sınama hariç) güçlü işaretlerin **tamamı T2p** idi: limactl 83,
  docker-brew 27, docker-cli 24, ollama-cli 3 + 3, gh 1, arduino-cli 1 (en büyük oran limactl
  %0,206). Hepsinin ortak yanı (gh, limactl, docker-cli'de tek tek bakıldı: 1 / 1, 83 / 83,
  24 / 24): **başka paketten yükseltilmiş dışa kapalı yöntem**. Go bu yöntemin sembolünü yöntem
  paketinin yoluyla niteler: `google.golang.org/grpc/internal/transport.(*parsedDataFrame).golang.org/x/net/http2.streamEnded`.
  Araştırmanın (ve P-ÜV1'in) `paket_adi` kuralı (`runtime.funcpkgpath`: son `/`'tan sonraki ilk
  nokta) son `/`'u yöntem adının içinde bulduğu için paketi
  `…(*parsedDataFrame).golang.org/x/net/http2` diye çıkarıyordu → yanlış alarm.
- Düzeltme: ürün T2p'si `ad_paketle_baslar(ad, paket)` = ad (kaçışlar çözülerek) `paket + "."` ile
  başlıyor mu. Tahrifat duyarlılığı aynı (paketi değişen ad önekte de değişir). Araştırma tanımlı
  sayaç `T2.paket_uyan_arastirma_tanimi` adıyla raporda kalıyor (H1 karşılaştırması onunla).
- Bozma betiği örneklemi araştırmanınkiyle aynı tutmak için araştırma T2p'sini ayrıca hesaplıyor
  (`t2p_arastirma`); bu yapılmadan koşulan ara denemede örneklem kaymıştı (A 68, D 80 bozulan) —
  o koşu atıldı, düzeltilmiş betikle araştırma sütunu yine 10 / 10 aynı.
- Test +1 (`test_yukseltilmis_disa_kapali_yontem_t2p_vermez`), mutant +1
  (`puv7_t2p_arastirma_kurali`; kaçış mutantı yeni koda taşındı): **16 / 16 öldü**.
- P-ÜV6b / P-ÜV1 notu: aynı yanılgı `go_pclntab.paket_adi`'de; bu fonksiyonların `paket` ve
  `sinif` alanı yanlış (sayısı kabul bölümünde).

### Bozma deneyi son hâli (K10 + düzeltilmiş T2p; `ozet/deney_k10_<ad>.json`)

| İkili | Tür | Bozulan | Araştırma sütunu (= başvuru) | **Ürün `tutarsiz`** | Wilson %95 | Güçlü T | K4 | Bozulmayanda yeni | İkili kararı |
|---|---|---|---|---|---|---|---|---|---|
| gh | A | 200 | 66 | **66** | %26,9–%39,8 | 66 | 0 | 0 | uyari |
| gh | B | 200 | 181 | **68** | %27,8–%40,8 | 68 | 0 | 0 | uyari |
| gh | C | 200 | 73 | **73** | %30,1–%43,4 | 73 | 0 | 0 | uyari |
| gh | D | 86 | 0 | **0** | %0–%4,3 | 0 | 0 | 0 | temiz |
| gh | E | 200 | 65 (K4 160) | **181** | %85,6–%93,8 | 65 | 159 | 0 | uyari |
| limactl | A | 200 | 84 | **84** | %35,4–%48,9 | 84 | 0 | 0 | uyari |
| limactl | B | 200 | 192 | **92** | %39,2–%52,9 | 92 | 0 | 0 | uyari |
| limactl | C | 200 | 82 | **82** | %34,4–%47,9 | 82 | 0 | 0 | uyari |
| limactl | D | 451 | 0 | **0** | %0–%0,8 | 0 | 0 | 0 | temiz |
| limactl | E | 200 | 67 (K4 166) | **185** | %88,0–%95,4 | 71 | 165 | 0 | uyari |

- H2 → TUTTU (araştırma sütunu 10 / 10 koşuda alan alan aynı). H4 → TUTTU (D: 0 / 86, 0 / 451;
  beklenen olumsuz). Bozulmayan fonksiyonlarda yeni `tutarsiz` 0 (10 koşu).
- H5 → TUTMADI: E %90,5 / %92,5 (< %95).
- D'de ikili kararı `temiz`: tutarlı sahtecilik hiçbir iz bırakmıyor.
