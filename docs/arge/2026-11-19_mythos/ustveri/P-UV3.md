# P-ÜV3 — Swift tip üst verisi okuyucu + `swift_metadata_recovery` (ilerleme)

Paket metni: `docs/arge/2026-11-23_dalga1/gonderim/PUV3.md`. Ortak brifler: `docs/arge/2026-11-23_dalga1/ORTAK_D1.md`,
`docs/arge/2026-11-20_dalga0/ORTAK_D0.md`, `docs/arge/2026-11-18_onarim/ONARIM_BRIF.md`.
Plan: `ustveri/PLAN.md` "P-ÜV3". Kararlar: A-10, A-13, A-14, A-27.

- Başlangıç: 2026-11-23 08:12. Taban commit `f2b0db5` (main; `git merge --ff-only main`, ileri sarma tamam).
- `karadul.__file__` worktree yolunu gösteriyor (doğrulandı).
- Koşu dizini: `~/karadul_olcum/runs/dalga1-2026-11-23/PUV3/` (yerel örnek ikilileri, ölçüm JSON'ları, yardımcı betikler).
- Sert son 11:30.
- Makinede Swift ABI başlıkları yok (`/Library/Developer/CommandLineTools` altında `swift/ABI/*.h` aranıp bulunamadı);
  doğrulama kaynağı yerel örneklerin `/usr/bin/nm` (görüntü sembolleri) + `xcrun swift-demangle` çıktısı. Araç zinciri:
  Apple Swift 6.4.2 (swiftlang-6.4.2.1.9), hedef arm64-apple-macosx27.2.0.
- **Ön kayıt:** `on_kayit_PUV3.md`, commit `0f5889b` (koddan ve ölçümden önce).
- **Okuyucu dondurma:** `karadul/analyzers/ustveri/swift.py`'nin son değişikliği `1521528`; dondurma bu dosyanın commit'iyle
  ilan edildi (aşağıdaki "Dondurma" bölümü). iTerm2 sınama GT'si (H2, H3) bundan sonra bir kez açılır.

## Durum

| Kalem | Durum | Commit |
|---|---|---|
| 1 Ön kayıt | yazıldı | `0f5889b` |
| 2 Yerel örnekler + derleme + ölçüm betiği | bitti (5 kaynak + C başlığı; 3 derleme biçimi) | `2f2aae3`, `1521528`, `9d57173` |
| 3 Okuyucu (tip, erişim, nitelikli ad; üç eksik) + testler | bitti | `0a9a36a`, `1521528` |
| 4 vtable / geçersiz kılma / uyum / tanık | bitti (+ geçersiz kılma hedefi, async gövde kanıtı) | `0a9a36a`, `53ef449` |
| 5 Üretici adım + INERT yaması | bitti | `0a9a36a`, `12f453d` |
| 6 Sağlamlık + mutasyon | bitti: 18 / 18 öldü | `cfc572f` |
| 7 Keşif ölçümü (H0, H1, H4, H5) | bitti: H0, H1, H4, H5 tuttu | bu commit |
| 8 Dondurma → H2, H3 bir kez | dondurma ilan edildi; ölçüm sırada | — |
| 9 Tam takım | sırada | — |

## Biçim: plandan farklar ve yerelde doğrulananlar

Plan biçimi (swiftlang/swift `MetadataValues.h`, `Metadata.h`, `GenericContext.h`, 2026-11-19) yerel örneklerle sınandı.
Tutan: bağlam bayrakları, tip +8 / +12, sınıf sabit kısmı 44, artçı sırası, yöntem betimleyicisi 8 bayt, geçersiz kılma
12 bayt (uygulama +8), uyum betimleyicisi alanları, tanık tablosunun ilk sözcüğü. Plandan farklı ya da planda yazılı
olmayanlar (örneğe uyuldu):

1. **Adsız bağlamın karışık adı öntanımda yok.** Plan kalem 2a "bağlamın ayraç adını oku" diyor; yerel örnekte adsız
   bağlamın türe özgü bit 0'ı (`HasMangledName`) `-O`, `-Onone` ve `-O -g` derlemelerinde 0: betimleyici 8 bayt (bayrak +
   üst), ayraç dizgisi yok. Yalnız `-Xfrontend -enable-anonymous-context-mangled-names` ile var; o zaman karışık ad tipin
   kendi karışık adıdır (`$s5Ornek9GizliYapi33_<ayraç>LLV`). Yerel `-O` ikilisinde ayraç dizgisi yalnız (a) Swift
   sınıflarının ObjC çalışma zamanı adlarında (`_TtC5OrnekP33_<ayraç>11DosyaSinifi`, `_TtCV5OrnekP33_<ayraç>8GizliKap7IcSinif`)
   ve (b) özel protokolün karışık adında geçiyor. Çalışma zamanının kendisi bu tipleri `(unknown context at $…)` diye
   adlandırır. **Sonuç:** özel yapı / enum, içinde (ya da kendisi) ObjC adlı sınıf yoksa öntanımlı derlemede
   adlandırılamaz; okuyucu ad uydurmaz (`adsiz_ayrac_bulunamadi`). Ayraç kaynakları: adsız bağlamın karışık adı (varsa),
   yoksa Swift sınıfı betimleyicisinden (`ObjC sınıf nesnesi +64`) üst zincir yürünerek ObjC adındaki
   `P<uz><ayraç><uz><ad>` bileşeni (yapısal eşleme; iki farklı ayraç → eşleme yok). İşlev içi (yerel) tipler adsız kalır.
2. **Uzantının genel başlığı +12'de** (bayrak + üst + genişletilen bağlam); adsız bağlamınki +8'de. Genel başlık
   (uzantı / adsız) 8 bayttır (tipteki 16 baytlık başlığın önbellek / kalıp kısmı yok).
3. **Uzantı adı:** `(extension in <Modül>):<Genişletilen>.<Tip>`. Genişletilen karışık ad `\x01` / `\x02` simgesel
   başvuru içerebilir (`Foundation.Date` dolaylı başvuruyla bağ `_$s10Foundation4DateVMn`). Kısıtsız genel uzantıda
   (`SayxG`, `xSg`) demangle yalnız nominali yazar (`Swift.Array`). Genel gereksinimi olan uzantıya ad verilmez
   (`uzanti_kisitli`): `extension Array where Element == Int` için GT `Swift.Array<A where A == Swift.Int>`; ayrıca
   `extension Dictionary` (kısıtsız) da `Key: Hashable` gereksinimini taşıdığı için ad almaz (GT `Swift.Dictionary`).
   Aynı modülün tipine kısıtsız uzantıda üst bağlam tipin kendisidir (uzantı betimleyicisi yok).
4. **İçe aktarım bilgisi:** ad dizgisinden sonra boş dizgiyle biten etiketli dizgiler; görülen etiketler `N` (ABI adı:
   `KDDurumTuru` → `KDDurum`, `Code` → `KDHataKodu`, `Ic` → `kd_ic`, CF sınıfları `CFString` → `CFStringRef`), `S` (ad
   alanı, ada etkisi yok), `R` (ilgili varlık: `__C_Synthesized.related decl 'e' for KDHataKodu`). Bilinmeyen etiket → ad
   yok. Etiketli typedef'te (`typedef struct kd_ozel_etiket {…} KDOzel`) içe aktarım bilgisi yok, ad zaten etiket adı.
5. **Tip kaydı türü düşük iki bit** (0 doğrudan, 1 dolaylı, 2 / 3 ObjC sınıf adı → atlanır, sayaç). Araştırma betiği
   bit 0'ı dolaylı sayıp `~3` maskeliyordu; gerçek hedeflerde fark yok (H1).
6. **Zaman uyumsuz yöntem:** vtable uygulama göstericisi zaman uyumsuz işlev göstericisine gösterir (yerel sembol
   `async function pointer to Ornek.Hayvan.bekle()`); gövde +0'daki int32 göreli gösterici. H1 sayımları ham uygulamayla
   (başvuruyla aynı); yuvaya kanıt alanı `govde` eklendi.
7. **Geçersiz kılma kaydı** +0 sınıf, +4 yöntem betimleyicisi (ikisi de dolaylı olabilen), +8 uygulama. Yöntem
   alanından üst sınıfın vtable sırası çıkar (`ust_tip`, `ust_sira`, `yontem_turu`); yerel örnekte geçersiz kılan ve
   geçersiz kılınan yöntem adı sembollerde aynı: 10 / 10 (`-O`), 12 / 12 (`-Onone`).

## Kod

- `karadul/analyzers/ustveri/swift.py`: `SwiftOkuyucu` / `oku(goruntu)`; durumlar `goruntu.py`'den, `tutarsiz` /
  `kapali` yerel (objc.py gibi). `SwiftSonuc.swift_types()` (erişim fonksiyonları: `ad` = `type metadata accessor for
  <Tip>`, `nitelikli_ad`, `alt_kume`, `ad_neden`, `erisim_kodda`, `erisim_baslangic`, `erisim_paylasimli`,
  `ad_yazilabilir`) ve `swift_slots()` (vtable / geçersiz kılma / tanık; **ad alanı yok**). Kendi kendini doğrulama:
  `denetim` (erişim kodda / başlangıç, vtable, geçersiz kılma, uyum, tanık ilk sözcüğü). `tutarsiz` kuralı: kod
  bölümü dışında erişim fonksiyonu (adım ad listesi üretmez, kanıt yazar).
- `karadul/pipeline/steps/swift_metadata_recovery.py`: `requires=["binary_for_byte_match"]`; `produces=["swift_types",
  "swift_slots", "swift_status", "swift_types_path"]`; çıktı `static/swift_metadata.json` (`karadul.swift_metadata.v1`);
  bayrak `getattr(…, "enable_swift_metadata_recovery", False) is True`. Faz 1 listesine ve `steps/__init__.py`'ye
  EKLENMEDİ (P-ÜV6b).
- Sağlamlık: vtable / geçersiz kılma üst sınırı 20 000; bağlam derinliği 64; tanık taraması 512; desteklenmeyen genel
  bayrak → artçılar çözülmez (sayaç), ad ve erişim yine okunur; ters çevrilebilir protokol bayrağı → artçı yok (sayaç);
  bozuk / kesik görüntüde istisna yok (`hata` durumu yalnız beklenmeyen istisnada).

## Testler ve mutasyon

- `tests/test_puv3_swift.py`: 45 test (okuyucu 25 = karışık ad 11 parametre dahil, sağlamlık 8, adım 12 = bayrak 5
  parametre dahil; biri gerçek `goruntu.ac` + gerçek `Workspace`). Sentetik görüntü: modül + sınıf (vtable 3) + dolaylı
  üstlü iç içe yapı + genel sınıf (1 parametre, hizalama) + tekil başlatmalı ve dirençli üst sınıflı sınıflar + geçersiz
  kılma + adsız bağlamda üç tip (karışık adlı / ObjC adlı / kaynaksız) + uzantı (kısıtsız / kısıtlı) + içe aktarılan C
  tipi + yerel ve dış protokole uyum (tanık tablosu, tablo sınırı).
- `scripts/measurement/mutation_specs_puv3.json`: **18 / 18 öldü** (planın 8'i + 10 ek). İlk koşuda "karışık adda LL
  denetlenmez" mutantı yaşadı → test eklendi; ikinci koşu 18 / 18, `git diff` temiz.

## INERT yaması

`docs/arge/2026-11-23_dalga1/yamalar/PUV3__config.py.patch`: INERT satırı silinir, alan yorumu "okuyan:
pipeline/steps/swift_metadata_recovery.py (P-ÜV3)" olur. Yamasız dalda `test_p15a_etkisiz::test_inert_registry_is_accurate`
kırmızı (doğrulandı); yamalı hâlde `test_p15a_etkisiz` + `test_bayrak_on_paketi` + `test_puv3_swift` 210 geçti / 3 atlandı.

## Keşif ölçümü (dondurmadan önce)

### H0 — yerel örnekler (`puv3_olc.py ornek`; GT = sembollü kopyanın `Mn` / `Ma` sembolleri + `swift-demangle`)

Kaynak `scripts/arge/ustveri/swift_ornek/` (`main.swift`, `gizli.swift`, `uzanti.swift`, `ice_aktarim.swift`,
`cf_tipleri.swift`, `ornek.h`), `derle.sh`. İkililer depo dışında; sha256 (son derleme, 08:41):
`ornek_O` eb7285e5…ec5ea, `ornek_O.strip` 9751294c…3c6352, `ornek_Onone` 3c8873bf…2ec5, `ornek_Onone.strip`
5d3ef492…46859, `ornek_Oanon` c786141a…7f148, `ornek_Oanon.strip` 728168cd…0b (tam değerler
`~/karadul_olcum/runs/dalga1-2026-11-23/PUV3/ornek/sha256.txt`).

| Derleme | Tip (`Mn` sembollü) | Okunan | Erişim = `Ma` adresi | Soyulmuşta fark | Adsız: ad / doğru / adsız kalan | Uzantı | İçe aktarım | Öbür | Yanlış |
|---|---|---|---|---|---|---|---|---|---|
| `-O` | 64 | 64 | 64 / 64 | 0 | 9 / 9 / 7 | 8 / 8 / 3 (kısıtlı) | 10 / 10 / 0 | 27 / 27 | **0** |
| `-Onone` | 66 | 66 | 66 / 66 | 0 | 9 / 9 / 9 | 8 / 8 / 3 | 10 / 10 / 0 | 27 / 27 | **0** |
| `-O` + adsız karışık ad | 64 | 64 | 64 / 64 | 0 | 14 / 14 / 2 (işlev içi) | 8 / 8 / 3 | 10 / 10 / 0 | 27 / 27 | **0** |

**H0 tuttu:** `Mn` sembollü her tip okundu; erişim fonksiyonu adresi `Ma` sembolüyle aynı; ad verilen her tipte
nitelikli ad demangle çıktısıyla aynı (yanlış 0); her eksik için ≥ 3 örnek doğru (adsız 9, uzantı 8, içe aktarım 10);
soyulmuş kopyada okuyucu çıktısı sembollüyle aynı (3 / 3). Ad verilmeyenler: öntanımlı derlemede ayraçsız özel yapı /
enum ve işlev içi tipler; kısıtlı (ve `Dictionary` gibi gereksinimli) uzantı içindeki tipler. Çıktılar
`…/PUV3/h0_{O,Onone,Oanon}.json`.

### H1 — sayı eşitliği (`puv3_olc.py sayi`; GT'ye bakmaz)

| Hedef | Tip | Erişim fonksiyonu | vtable betimleyicisi | Kodda ayrık uygulama | Tanık kod göstericisi | Ek 15 bilgi alanı | Okuma hatası | Okuma süresi (yük altında) |
|---|---|---|---|---|---|---|---|---|
| Rectangle arm64 | 186 / 186 | 186 / 186 | 961 / 961 | 106 / 106 | 39 / 39 | 15 / 15 aynı | 0 | 0,02 sn |
| iTerm2 arm64 | 3 659 / 3 659 | 3 659 / 3 659 | 12 258 / 12 258 | 2 264 / 2 264 | 741 / 741 | 15 / 15 aynı | 0 | 0,32 sn |

**H1 tuttu** (ben / başvuru). Ek alanlar: tür dağılımı, genel tip, erişim kodda / başlangıç, çözülen sınıf, boş uygulama,
ayrık uygulama, vtable türleri, geçersiz kılma kaydı / ayrık uygulama, uyum kaydı, yerel protokole, tanık tablosu olan,
ilk sözcüğü doğrulanan, tanık başlangıç. Çıktılar `…/PUV3/h1_{Rectangle,iTerm2}.arm64.json`.

**Dürüstlük notu:** 08:2x'te (ObjC zinciri onarımından önce, `0a9a36a` okuyucusuyla) iTerm2 `sayi` çıktısında okuyucunun
alt küme sayıları da görüldü (GT'siz: adsız 1 156 tipin 126'sına ad, uzantı 12 / 10, içe aktarım 75 / 75, öbür 2 416;
sayaç `adsiz_ayrac_bulunamadi` 1 030, `uzanti_kisitli` 2). Okuyucu bu sayıya göre değiştirilmedi: sonraki iki değişiklik
(`53ef449` kanıt alanları, `1521528` ObjC zinciri) yerel örnekteki boşluktan (özel yapı içindeki sınıf) çıktı. Bu
sayılardan sonra iTerm2'de yalnız H1 alanlarına bakıldı. Rectangle (soyulmuş, GT yok): ad 180 / 186 (6 adsız).

### H4 — `swift_slots` ad adayı değil

Sentetik testte ve iki gerçek hedefte `swift_types` içinde yuva kaynaklı kayıt 0, `swift_slots` kayıtlarında ad alanı 0
(Rectangle 1 152 yuva, iTerm2 13 807 yuva, yerel `ornek_O.strip` 86 yuva). **H4 tuttu.**

### H5 — Swift'siz ikililer

`gh`, Ollama arm64, `limactl` (Mach-O, Swift bölümü yok) → `veri_yok` ("Swift tip / uyum bölümü yok"), tip 0;
Debian `cat` (ELF) → `veri_yok` ("Mach-O değil"); ek: terminal-notifier → `veri_yok`. **H5 tuttu** (`…/PUV3/h5.json`).

### Adım uçtan uca (bayrak açık, gerçek `goruntu.ac`, gerçek `Workspace`; `…/PUV3/adim_uctan.py`)

Rectangle arm64 `calisti`: 186 `swift_types` (180 `ad_yazilabilir`), 1 152 `swift_slots`, ad alanlı yuva 0, dosya
`static/swift_metadata.json` 186 kayıt, hata 0. Yerel `ornek_O.strip` (08:41 derlemesi) `calisti`: 64 `swift_types`
(54 `ad_yazilabilir`), 86 yuva, ad alanlı yuva 0. `gh` `veri_yok`. (`…/PUV3/adim_uctan.json`)

## Dondurma

Okuyucu (`karadul/analyzers/ustveri/swift.py`) `1521528`'deki hâliyle donduruldu; dondurmayı ilan eden commit `9d6ee9a`.
H2 ve H3 bundan sonra `puv3_olc.py sinama --sinama-izni` ile **bir kez** ölçülür; sonuç ne olursa olsun okuyucu
değişmez (ikinci tur ayrı pakettir).

## SINAMA — iTerm2 arm64 (bir kez; 2026-11-23 08:43:51–08:43:53, ağaç `9d6ee9a`, temiz)

Komut: `PYTHONDONTWRITEBYTECODE=1 python scripts/arge/ustveri/puv3_olc.py sinama $V/hedef/iTerm2.arm64 --sinama-izni
--cikti …/PUV3/sinama_iTerm2.json`. Girdi araştırma kopyası (sha256 `9fc127ad…`, HEDEF'in özgün dilimiyle aynı).
GT: aynı dilimin sembol tablosu; `Ma` sembolleri `xcrun swift-demangle` ile. Çıktıya ad yazılmadı (yalnız sayı).

| Hüküm | Ölçülen | Eşik | Sonuç |
|---|---|---|---|
| H2 erişim fonksiyonu `Ma` eki | 3 659 / 3 659 | 3 659 / 3 659 | **tuttu** |
| H2 tanık `TW` eki | 741 / 741 | 741 / 741 | **tuttu** |
| H3 ad verilen tip | **2 627 / 3 659** (%71,8) | ≥ 3 477 | **tutmadı** |
| H3 ad verilenlerde yanlış | **0 / 2 627** (%0; doğru Wilson %95 [0,9985; 1]) | ≤ %1 | tuttu |

Alt küme dökümü (ön kayıt §2 sınıflaması):

| Alt küme | Tip | Ad verilen | Doğru | Yanlış | Adsız bırakılan |
|---|---|---|---|---|---|
| adsız bağlam | 1 156 | 126 | 126 | 0 | 1 030 (ayraç bulunamadı) |
| uzantı | 12 | 10 | 10 | 0 | 2 (kısıtlı uzantı) |
| içe aktarım | 75 | 75 | 75 | 0 | 0 |
| öbür | 2 416 | 2 416 | 2 416 | 0 | 0 |
| **toplam** | **3 659** | **2 627** | **2 627** | **0** | **1 032** |

- GT'si olmayan ad verilen tip 0 (her erişim adresinde `Ma` sembolü var).
- **H3 hükmü (ön kayıt §3):** sayı şartı tutmadı; yanlış şartı tuttu. Hiçbir alt küme yanlış vermedi; kanal yalnız ad
  verebildiği 2 627 tip için ad üretir (ad verilemeyenler zaten `nitelikli_ad = None`). Eksik 1 032 tipin 1 030'u
  öntanımlı derlemede ayracı ikilide bulunmayan özel tipler (bkz. "Biçim" §1: yerel örnekte bilgi ikilide yok), 2'si
  kısıtlı uzantı. Okuyucu bu sonuca göre yeniden ayarlanmadı.
- Soyulmuş kopya (`ustveri_set/iTerm2/bin/iTerm2`, GT'siz karşılaştırma): okuyucu çıktısı özgün dilimle **aynı** (tip
  3 659, yuva 13 807, nitelikli ad 2 627, `ad_yazilabilir` 2 627; `…/PUV3/soyulmus_iTerm2.json`).

Ön kayıt hükümleri: **H0 tuttu, H1 tuttu, H2 tuttu, H3 tutmadı (sayı 2 627 < 3 477; yanlış 0 / 2 627 tuttu), H4 tuttu,
H5 tuttu.**
