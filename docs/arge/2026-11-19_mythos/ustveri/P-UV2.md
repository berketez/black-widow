# P-ÜV2 — Objective-C yöntem listesi okuyucu + `objc_metadata_recovery` (ilerleme)

Paket metni: `docs/arge/2026-11-20_dalga0/gonderim/PUV2.md`. Ortak brif: `docs/arge/2026-11-20_dalga0/ORTAK_D0.md`.
Plan: `ustveri/PLAN.md` "P-ÜV2". Kararlar: A-10, A-27, A-28.

- Başlangıç: 2026-11-20 10:46. Taban commit `3eb32df` (main; `git merge --ff-only main`).
- `karadul.__file__` worktree yolunu gösteriyor (doğrulandı).
- Koşu dizini: `~/karadul_olcum/runs/dalga0-2026-11-20/PUV2/`.
- Sert son 15:15.
- **Ön kayıt:** `on_kayit_PUV2.md`, commit `60d7595` (rebase öncesi `ef5983d`; koddan ve ölçümden önce).
- **Rebase:** 11:11'de bir kez `git rebase main` (P-ÜV0 `8844a08` main'de; çatışma yok). Aşağıdaki commit'ler rebase
  sonrası kimlikleriyle. `karadul.analyzers.ustveri.goruntu.__file__` worktree yolunu gösteriyor.
- **Okuyucu dondurma commit'i: `b160a04`** (iTerm2 sınama GT'si bundan sonra açıldı).

## Durum

| Kalem | Durum | Commit |
|---|---|---|
| Ön kayıt | yazıldı | `60d7595` |
| 1 okuyucu (sınıf, meta, kategori, protokol) | bitti; gerçek görüntüyle 6 / 6 | `3977815`, `b160a04` |
| 2 denetimler (IMP kodda, başlangıç, arite, paylaşımlı IMP) | bitti; 6 / 6 hedefte IMP başlangıç = ayrık IMP | `3977815` |
| 3 ad biçimi (tam ad + seçici ayrı alan; kategori adı ayrı; Swift köprüsü işareti) | bitti | `3977815` |
| 4 üretici adım `objc_metadata_recovery` | bitti; gerçek ikilide uçtan uca (terminal-notifier, Ollama, gh) | `3977815`, `6da42c6` |
| 5 sağlamlık (sayı sınırı, döngüsel üst sınıf, bölüm dışı ofset, istisna yok) | bitti (sentetik) | `3977815`, `9e5e3eb`, `a6c437d` |
| 6 eski `LC_DYLD_INFO` (Rectangle) | bitti: zincirli düzeltme 0, ham göstericiyle 450 / 450 aynı | `b160a04` |
| Mutasyon | 16 / 16 öldü (rebase sonrası yinelendi) | `ecc104a` |
| INERT yaması | bırakıldı | `2772118` |
| Rebase + 6 hedef kabulü | **H1 tuttu** (aşağıda) | `b160a04` |
| Keşif GT (terminal-notifier) | 32 / 32 doğru, farklı 0 | — |
| SINAMA GT (iTerm2) | dondurmadan sonra bir kez | — |
| Tam takım | sonda | — |

## Kabul (gerçek P-ÜV0 görüntüsüyle, 11:11–11:15, yük altında: load 5,4)

Betik `~/karadul_olcum/runs/dalga0-2026-11-20/PUV2/kabul.py --goruntu gercek`; çıktı `…/PUV2/kabul_gercek.json`.
Karşılaştırma: IMP'li her kayıt için (IMP, tür, sınıf, kategori, seçici, protokolde, swift, tip) sekizlisi ↔
`$V/objc/<ad>.tsv`, çoklu küme.

| Hedef | Yöntem kaydı (ben / başvuru) | Yalnız bende / yalnız başvuruda | IMP başlangıç / ayrık IMP | IMP kodda | Okuma hatası | Okuma süresi (yük altında) |
|---|---|---|---|---|---|---|
| terminal-notifier | 32 / 32 | 0 / 0 | 32 / 32 | 32 | 0 | 0,001 sn |
| iTerm2 arm64 | 41 305 / 41 305 | 0 / 0 | 41 305 / 41 305 | 41 305 | 0 | 0,59 sn (+ görüntü 0,62) |
| Ollama arm64 | 151 / 151 | 0 / 0 | 151 / 151 | 151 | 0 | 0,04 sn |
| Ollama x86_64 | 151 / 151 | 0 / 0 | 151 / 151 | 151 | 0 | 0,04 sn |
| limactl | 102 / 102 | 0 / 0 | 102 / 102 | 102 | 0 | 0,12 sn |
| Rectangle arm64 | 450 / 450 | 0 / 0 | 450 / 450 | 450 | 0 | 0,03 sn |

- **H1 tuttu:** 6 / 6 hedefte yöntem kaydı sayısı ve (adres, ad) listesi başvuruyla aynı; sınıf, Swift sınıfı,
  kategori, protokol, paylaşımlı IMP (0) ve arite (iTerm2 41 262 uyan / 43 uymayan) da aynı. IMP = fonksiyon
  başlangıcı 6 / 6. Okuma hatası sayaçları 0 (6 / 6). Durum 6 / 6 `calisti`; `ad_yazilabilir` = IMP'li kayıt (6 / 6).
- **H4 tuttu:** mutant (seçici başvurusu çözülmez) küçük biçimli kayıtlarda doğru seçici: terminal-notifier 0 / 32,
  iTerm2 0 / 41 305, Ollama arm64 0 / 151, limactl 0 / 102, Rectangle 0 / 450; Ollama x86_64'te küçük biçimli liste yok
  (151 kaydın hepsi büyük biçim) → o hedefte veri yok. (`…/PUV2/kabul_h4.json`)
- **H5 tuttu:** `gh` → `veri_yok` ("ObjC sınıf / kategori / protokol listesi bölümü yok"), yöntem 0.
- **Kalem 6:** Rectangle'da P-ÜV0 özeti zincirli düzeltme yeri 0 (eski düzen, ham gösterici); 450 / 450 aynı.
- **Adım uçtan uca** (bayrak açık, gerçek `goruntu.ac`, gerçek `Workspace`; `…/PUV2/adim_uctan.py`): terminal-notifier
  soyulmuş kopya (`ustveri_set/terminal-notifier/bin`) `calisti`, 32 yöntem, 32 `ad_yazilabilir`, dosya 32 kayıt;
  Ollama arm64 `calisti` 151; `gh` `veri_yok`; hata 0.

## Keşif GT — terminal-notifier (`…/PUV2/gt.py --ad terminal-notifier`, HEDEF'in kuralı)

- Özgün ve soyulmuş kopyada ad haritası aynı (okuyucu sembol okumaz). 32 IMP'in 32'sinde ObjC GT sembolü var.
- **32 / 32 doğru, yanlış 0** (birebir 31, kategori yazımı 1); Wilson %95 [0,8928, 1]. Ön kayıt §2'deki eşik notu
  gereği 0,999 eşiği burada uygulanmaz (n = 32); ölçüt "farklı ad 0" tuttu. GT'de ObjC adı olup okuyucuda olmayan
  10 adres (başvuruyla aynı sayı; IMP'i yöntem listesinde olmayan semboller).

## Tasarım kararları (koddan)

- Okuyucu `karadul/analyzers/ustveri/objc.py`, P-ÜV0 `Goruntu` arayüzüyle (ana oturumun 11:0x mesajı: `b049837`
  imzaları) yazıldı: `gosterici()` (int | `Bag` | None), `bolumler_adli`, `kod_bolumleri`, `Bolum.icerir`,
  `fonksiyon_baslangiclari()`, `cstr`, `u32` / `i32` / `u64`, `bicim`, `gosterici_boyutu`. Göreli ofset ve zincirli
  düzeltme `gosterici()`'nindir; okuyucuda yeniden yazılmadı. P-ÜV0 main'e girene kadar `goruntu` modülü dalda yok:
  okuyucu ondan bir şey içe aktarmıyor (duck typing); `BICIM_MACHO` ve durum adları yerel sabit (aynı dizgiler).
  Rebase'te `goruntu`'dan içe aktarılacak (§11 tek tanım kuralı).
- Durum sözlüğü P-ÜV1 / P-ÜV0 ile aynı: `calisti` / `veri_yok` / `desteklenmiyor` / `tutarsiz` / `kapali` / `hata`.
- **`tutarsiz` kuralı** (P-ÜV1'in K2'sinin karşılığı): kod bölümü dışında IMP ya da bölüm dışına gösteren göreli ofset
  varsa; adım ad listesi üretmez, kanıt (sayılar + neden) yazar. Fonksiyon başlangıcı olmayan IMP, paylaşımlı IMP ve
  arite uyumsuzluğu **kayıt düzeyinde** işaretlenir (`ad_yazilabilir = False` ilk ikisinde; arite yalnız kanıt:
  iTerm2'de başvuru 43 uymayan veriyor, ad yanlışlığı göstermez). Eşik uydurulmadı; P-ÜV6 ad kanalında karar verir.
- Yöntem kaydı alanları (JSON): `imp`, `adres` (onaltılık), `tur`, `sinif`, `kategori`, `secici`, `tam_ad`, `tip`,
  `swift`, `protokolde`, `sinif_dis`, `kaynak`, `liste_bicimi`, `imp_kodda`, `imp_baslangic`, `arite`,
  `imp_paylasimli`, `ad_yazilabilir`. Kategori yöntemi tam adda sınıf adıyla (`-[NSString kedice]`), kategori adı
  ayrı alanda (BULGULAR §6.1: serbest metin).
- Adım `karadul/pipeline/steps/objc_metadata_recovery.py`: bayrak `getattr(…, "enable_objc_metadata_recovery",
  False) is True`; görüntü `goruntu.ac(binary_for_byte_match)`; `GoruntuHatasi.durum` korunur; çıktı
  `static/objc_methods.json` (`schema karadul.objc_methods.v1`). Faz 1 listesine ve `steps/__init__.py`'ye
  EKLENMEDİ (P-ÜV6).
- Araştırma okuyucusundan farklar (bilerek): kategori sınıfı yerel ama sınıf listesinde değilse ad sınıfın kendi
  `class_ro_t`'sinden okunur (başvuru `None` yazıyordu; bilgi sayacı `yerel_sinif_listede_yok`); üst sınıf zinciri
  (döngü sayaçlı) eklendi; bölüm dışı göreli ofset kaydı atlanır (başvuru adsız kayıt bırakıyordu).

## Ön deneme (KABUL DEĞİL; araştırma `macho.py` bağdaştırıcısıyla, 11:0x)

P-ÜV0 main'e girmeden okuyucunun gerçek veride hatasını erken görmek için: kabul betiği
`~/karadul_olcum/runs/dalga0-2026-11-20/PUV2/kabul.py --goruntu arastirma` (görüntü yerine araştırma
`scripts/arge/ustveri/macho.py`; okuyucu ürün kodu). Yalnız keşif / sınama dışı hedefler; iTerm2 (sınama ikilisi) bu
denemede koşulmadı. Çıktı `…/PUV2/onden_arastirma.json`.

| Hedef | Yöntem kaydı (ben / başvuru) | Yalnız bende / yalnız başvuruda (8 sütun, çoklu küme) | IMP başlangıç / ayrık IMP | Okuma hatası |
|---|---|---|---|---|
| terminal-notifier | 32 / 32 | 0 / 0 | 32 / 32 | 0 |
| Ollama arm64 | 151 / 151 | 0 / 0 | 151 / 151 | 0 |
| Ollama x86_64 | 151 / 151 | 0 / 0 | 151 / 151 | 0 |
| limactl | 102 / 102 | 0 / 0 | 102 / 102 | 0 |
| Rectangle arm64 | 450 / 450 | 0 / 0 | 450 / 450 | 0 |
| `gh` | `veri_yok` (ObjC bölümü yok) | — | — | — |

Sınıf, Swift sınıfı, kategori, protokol, paylaşımlı IMP ve arite sayıları da 5 / 5 başvuruyla aynı. H4 ön denemesi
(mutant kaynak metinden kurulup): küçük biçimli kayıtlarda doğru seçici terminal-notifier 0 / 32, Ollama arm64 0 / 151,
limactl 0 / 102, Rectangle 0 / 450; Ollama x86_64'te küçük biçimli liste yok (H4 o hedefte veri yok).

## Testler ve mutasyon

- `tests/test_puv2_objc.py`: 51 test (okuyucu 24, tip kodlaması 15 parametre + 2, adım 10; biri gerçek `Workspace` ile). Sentetik görüntü:
  `Kedi` + meta sınıf (küçük biçim 2 yöntem seçici başvurusuyla, meta sınıfta büyük biçim 1 yöntem), Swift
  işaretli `Kopek` (`bits` yeniden konumlamayla, düşük bit 2), `NSString`'e `Ek` kategorisi (bağ, seçici doğrudan),
  `Sesli` protokolü.
- Mutasyon `scripts/measurement/mutation_specs_puv2.json`: **16 / 16 öldü** (planın 8'i + H4 + 7 ek).

## INERT yaması

`docs/arge/2026-11-20_dalga0/yamalar/PUV2__config.py.patch`: INERT satırı silinir, alan yorumu "okuyan:
pipeline/steps/objc_metadata_recovery.py (P-ÜV2)" olur. Yamasız dalda `test_p15a_etkisiz::test_inert_registry_is_accurate`
kırmızı (doğrulandı); yamalı hâlde `test_p15a_etkisiz` + `test_bayrak_on_paketi` + `test_puv2_objc` 220 geçti / 1
atlandı. **Not:** P-ÜV1'in yaması bir önceki satırı (`enable_go_metadata_recovery`) siliyor; iki yama art arda
`git apply` ile bağlam çakışması verebilir: `git apply --3way` ya da elle uygulanmalı (iki satır).

## Bekleme (11:1x; bitti 11:11)

- Bekleniyordu: P-ÜV0 gerçek `Goruntu` uygulamasının main'e girmesi (ana oturum haber verecek). Bu sürede tam takım (yama
  geçici uygulanmış, rebase öncesi) arka planda koşuyor; günlük `~/karadul_olcum/runs/dalga0-2026-11-20/PUV2/tam_takim_on.log`.
  Tahmini bitiş 11:30 (yük altında). Kabul betikleri hazır: `…/PUV2/kabul.py` (6 hedef + gh + H4), `…/PUV2/gt.py` (H2 / H3).

## Tam takım — ön koşu (rebase öncesi, yama geçici uygulanmış; 11:03–11:09, yük altında, load 8,8)

- `10 504 geçti / 82 atlandı / 152 seçilmedi / 7 kaldı` (365 sn). 7 kalanın 7'si ortam: worktree'de `scripts/node_modules`
  (`@babel/parser`) ve `vendor/gnulib-ref` yoktu (deobfuscator ×2, pipeline, project_reconstructor, ps3b ×3). ORTAK §2
  bağları kurulunca 7 test (ve dosyalarının kalanı) 21 / 21 geçti. P-ÜV2 değişikliğinden kalan test yok.
- Yama geri alındı (`git diff` temiz). Kesin tam takım rebase'ten sonra yinelenecek.

## SINAMA GT — iTerm2 arm64 (bir kez; okuyucu `b160a04`'te dondurulduktan sonra, 11:1x)

`…/PUV2/gt.py --ad iTerm2 --sinama-izni`; çıktı `…/PUV2/gt_iTerm2.json`. GT: HEDEF paketinin çıkarımı
(`ustveri_set/iTerm2/gt/`), sayım HEDEF'in kuralıyla (`ustveri_olc.kanal_olc`, `objc_yazimi`).

- Özgün dilim ve soyulmuş kopyada ad haritası aynı (41 305 IMP).
- **H2 tuttu:** ObjC GT sembolü olan IMP 33 611; **33 611 / 33 611 doğru, yanlış (farklı ad) 0** (birebir 31 431,
  kategori yazımı 2 180); Wilson %95 alt sınırı **0,999886 ≥ 0,999**. `ad_yazilabilir` alt kümesi aynı (33 611 / 33 611).
- **H3 tuttu:** ObjC GT sembolü olmayan IMP 7 694; bunların 7 420'si Swift sınıfı kaydı → **%96,44 ≥ %95**.
- Bilgi (ön kayıtta hüküm yok): bütün GT ile (adres başına, HEDEF kuralı) 41 305 adresin 33 611'i doğru, 7 694'ü
  "yanlış": o adreslerde GT'nin adı ObjC değil (çoğu Swift köprüsü; okuyucu `swift = true` işaretliyor). GT'de ObjC
  adı olup okuyucunun listesinde IMP'i olmayan 994 adres var (yöntem listesinde olmayan ObjC sembolleri).
- **P-ÜV6 için risk:** `swift = true` kayıtlar ve Swift işaretsiz 274 kayıt (7 694 − 7 420) GT'de ObjC adı taşımıyor;
  ad kanalı bunlara ObjC tam adını yazarsa HEDEF ölçüsünde "yanlış" sayılır. Bu iki kümenin GT ad türü dökümü
  bakılmadı (sınama GT'si bir kez açıldı; ikinci bakış yok).

Ön kayıt hükümleri: **H1 tuttu, H2 tuttu, H3 tuttu, H4 tuttu (Ollama x86_64'te veri yok), H5 tuttu.**
