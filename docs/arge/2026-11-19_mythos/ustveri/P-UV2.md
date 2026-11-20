# P-ÜV2 — Objective-C yöntem listesi okuyucu + `objc_metadata_recovery` (ilerleme)

Paket metni: `docs/arge/2026-11-20_dalga0/gonderim/PUV2.md`. Ortak brif: `docs/arge/2026-11-20_dalga0/ORTAK_D0.md`.
Plan: `ustveri/PLAN.md` "P-ÜV2". Kararlar: A-10, A-27, A-28.

- Başlangıç: 2026-11-20 10:46. Taban commit `3eb32df` (main; `git merge --ff-only main`).
- `karadul.__file__` worktree yolunu gösteriyor (doğrulandı).
- Koşu dizini: `~/karadul_olcum/runs/dalga0-2026-11-20/PUV2/`.
- Sert son 15:15.
- **Ön kayıt:** `on_kayit_PUV2.md`, commit `ef5983d` (koddan ve ölçümden önce).

## Durum

| Kalem | Durum | Commit |
|---|---|---|
| Ön kayıt | yazıldı | `ef5983d` |
| 1 okuyucu (sınıf, meta, kategori, protokol) | bitti (sentetik) | `11e30c7` |
| 2 denetimler (IMP kodda, başlangıç, arite, paylaşımlı IMP) | bitti (sentetik) | `11e30c7` |
| 3 ad biçimi (tam ad + seçici ayrı alan; kategori adı ayrı; Swift köprüsü işareti) | bitti | `11e30c7` |
| 4 üretici adım `objc_metadata_recovery` | bitti (sentetik) | `11e30c7` |
| 5 sağlamlık (sayı sınırı, döngüsel üst sınıf, bölüm dışı ofset, istisna yok) | bitti (sentetik) | `11e30c7` |
| 6 eski `LC_DYLD_INFO` (Rectangle) | P-ÜV0 gelince (kabulde) | — |
| Mutasyon | 16 / 16 öldü | `8f891e7` |
| INERT yaması | bırakıldı | `754359a` |
| Rebase + 6 hedef kabulü | PUV0 main'e girince | — |
| SINAMA GT (iTerm2) | dondurmadan sonra | — |
| Tam takım | sonda | — |

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
  `class_ro_t`'sinden okunur (başvuru `None` yazıyordu; bilgi sayacı `kategori_sinifi_listede_yok`); üst sınıf zinciri
  (döngü sayaçlı) eklendi; bölüm dışı göreli ofset kaydı atlanır (başvuru adsız kayıt bırakıyordu).

## Testler ve mutasyon

- `tests/test_puv2_objc.py`: 50 test (okuyucu 24, tip kodlaması 15 parametre + 2, adım 9). Sentetik görüntü:
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
