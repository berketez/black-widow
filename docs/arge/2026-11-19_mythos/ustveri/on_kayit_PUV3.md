# Ön kayıt — P-ÜV3 (Swift tip üst verisi okuyucu + `swift_metadata_recovery` üretici adımı), 2026-11-23

Bu metin koddan ve ölçümden ÖNCE commit'lenir. Tutmayan beklenti silinmez; eşik sonradan değişmez.
Paket metni `docs/arge/2026-11-23_dalga1/gonderim/PUV3.md`; plan `ustveri/PLAN.md` "P-ÜV3"; kararlar A-10, A-13, A-14,
A-27. Taban commit: `f2b0db5` (main; `git merge --ff-only main`).

**Bu kayıttan önce görülenler (dürüstlük notu):**
- Araştırma okuyucusu `scripts/arge/ustveri/swift_meta.py`, `swift_ad_dogrula.py` (kaynak kod).
- Başvuru çıktıları (`$V` = `~/karadul_olcum/runs/arge-2026-11-19/ustveri`): `$V/swift/Rectangle.arm64.json` bütünüyle
  (soyulmuş; sembol tablosu alanları 0); `$V/swift/iTerm2.arm64.json`'un **yalnız sayım alanları** (`tip`, `tur`,
  `genel_tip`, `adli_tip`, `erisim_*`, `sorun`, `vtable`, `uyum`, `birlesim`). iTerm2'nin `sembol_tablosu` alanı
  açılmadı; `$V/swift/iTerm2.arm64.ad.json` (ad örnekleri içerir) açılmadı.
- `ustveri/BULGULAR.md` §3.2'deki iTerm2 sayıları (`Ma` 3 659 / 3 659, `TW` 741 / 741, tam eşitlik 2 444 / 3 659;
  1 149 adsız bağlam, 19 uzantı, 47 içe aktarım). Ad metni görülmedi.
- iTerm2 GT dosyası (`~/karadul_olcum/ustveri_set/iTerm2/gt/`) açılmadı.

## 1. Hipotezler

Planın metni (aynen):

> H1: iki hedefte sayılar başvuruyla aynı. H2: iTerm2'de erişim fonksiyonu sembol eki 3 659 / 3 659, tanık eki
> 741 / 741. H3: üç eksik giderildikten sonra nitelikli ad tam eşitliği ≥ 3 477 / 3 659; ad verilenlerde yanlış ≤ %1.
> H4 (beklenen olumsuz): vtable yuvalarından yöntem adı üretilemez; kanal `swift_slots` için ad adayı yazmaz (0).
> H5: Swift olmayan ikilide durum `veri_yok`.

Gönderim metninin ekleri (aynen):

> H0 (keşif, yerel örnekler): sembollü kopyada tip betimleyicisi sembolü (`Mn`) olan her tip okunur; erişim fonksiyonu
> adresi `Ma` sembolünün adresiyle aynı; nitelikli ad `swift-demangle` çıktısıyla aynı — üç eksiğin her biri için en
> az 3 örnek tip, hepsi doğru. Soyulmuş kopyada okuyucu çıktısı sembollüyle aynı (fark 0).

> H3 (SINAMA, bir kez; okuyucu dondurulduktan sonra): iTerm2'de ad verilen tip ≥ 3 477 / 3 659 ve ad verilenlerde
> yanlış ≤ %1. İkisinden biri tutmazsa kanal yalnız tutan alt küme için ad üretir; hangi alt kümelerin (adsız bağlam /
> uzantı / içe aktarım / öbür) kaç yanlış verdiği yazılır, okuyucu sınama sonucuna göre YENİDEN AYARLANMAZ (ikinci tur
> ayrı pakettir).

## 2. İşlem tanımları (ölçümden önce sabitlenir)

- **Girdi:** `$V/hedef/Rectangle.arm64`, `$V/hedef/iTerm2.arm64` (araştırma kopyaları, ince dilim); H5 için `$V/hedef/gh`,
  `$V/hedef/Ollama.arm64`, `$V/hedef/limactl` (Mach-O, Swift bölümü yok) ve `~/karadul_olcum/n1_debian13/` altından bir
  ELF (`cat`). Okuyucu P-ÜV0 `goruntu.ac` görüntüsü üstünden çalışır. İkililer çalıştırılmaz, yerinde değiştirilmez.
- **Yerel örnekler (H0):** `scripts/arge/ustveri/swift_ornek/*.swift` (+ gerekirse C başlığı `-import-objc-header`
  ile), `/usr/bin/xcrun swiftc -O` ve `-Onone`; her derleme için sembollü kopya ve `/usr/bin/strip` ile soyulmuş kopya
  (`~/karadul_olcum/runs/dalga1-2026-11-23/PUV3/ornek/`). Derleme çıktısı çalıştırılmaz, depoya girmez.
- **GT (H0):** sembollü kopyada `/usr/bin/nm` ile tanımlı semboller; `$s…Mn` (tip betimleyicisi) ve `$s…Ma`
  (erişim fonksiyonu) sembolleri `xcrun swift-demangle` ile çözülür. `Mn` sembolünün adresi = okuyucunun tip
  betimleyicisi adresi eşlemesi; erişim fonksiyonu adresi = aynı tipin `Ma` sembolünün adresi; nitelikli ad = `Ma`
  sembolünün demangle çıktısından `type metadata accessor for ` öneki çıkarılmış metin (birebir dizgi eşitliği).
- **"Üç eksik" sınıflaması (tip başına, okuyucunun okuduğu bağlam zincirinden):** zincirde adsız bağlam (tür 2) varsa
  `adsiz`; yoksa ve uzantı bağlamı (tür 1) varsa `uzanti`; yoksa ve tipin kendisinde `HasImportInfo` (türe özgü
  bayrak bit 2) varsa `ice_aktarim`; yoksa `diger`. H0'ın "her eksik için en az 3 örnek tip" şartı bu sınıflamayla.
- **H0 "fark 0":** sembollü ve soyulmuş kopyada okuyucunun tip listesi (betimleyici adresi, tür, nitelikli ad, erişim
  fonksiyonu, genel mi) ve yuva listesi (vtable, geçersiz kılma, tanık) aynı.
- **H1 sayıları:** tip (sınıf / yapı / enum); erişim fonksiyonu (ayrık); vtable yöntem betimleyicisi; vtable'da kodda
  ayrık uygulama; tanık kod göstericisi (ayrık). Başvuru: Rectangle 186 / 186 / 961 / 106 / 39; iTerm2 3 659 / 3 659 /
  12 258 / 2 264 / 741. Ek bilgi satırları (hüküm dışı): tür dağılımı, genel tip, geçersiz kılma kaydı / ayrık
  uygulama, uyum kaydı, ilk sözcüğü doğrulanan tanık tablosu.
- **H2 (sınama, dondurmadan sonra bir kez):** iTerm2 soyulmamış diliminde erişim fonksiyonu adreslerinde tanımlı
  sembol `…Ma` ile biten adres sayısı / sembollü erişim adresi; tanık kod göstericisi adreslerinde `TW` / `TWTm` ile
  biten sembolü olan / sembollü. Beklenen 3 659 / 3 659 ve 741 / 741.
- **H3 (sınama, dondurmadan sonra bir kez):** iTerm2'de okuyucunun `swift_types` listesi (ad verilebilen erişim
  fonksiyonları). "Ad verilen tip" = okuyucunun nitelikli ad ürettiği (ad `None` olmayan) tip; "yanlış" = ad
  verilmiş ve erişim adresindeki `Ma` sembolünün demangle çıktısıyla birebir aynı değil (aynı adreste birden çok `Ma`
  sembolü varsa herhangi biriyle aynıysa doğru). Eşikler: ad verilen ≥ 3 477 (payda 3 659 = bütün tipler) ve
  yanlış / ad verilen ≤ %1. Wilson %95 aralığı (`ks1_olc.oran`) ayrıca yazılır. Alt küme dökümü (adsız / uzantı /
  içe aktarım / öbür) aynı sınıflamayla.
- **H4:** adımın ad adayı çıktısı (`swift_types`) içinde vtable / geçersiz kılma / tanık kaynaklı kayıt 0; `swift_slots`
  kayıtlarında ad alanı yok. Sentetik testte ve iki gerçek hedefte sayılır.
- **H5:** listelenen dört Swift'siz ikilide okuyucu ve adım durumu `veri_yok`, tip 0.
- **Dondurma:** H0, H1, H5 bittikten sonra okuyucu `karadul/analyzers/ustveri/swift.py`'nin commit'i dondurma commit'i
  olarak ilerleme dosyasına yazılır; H2 ve H3 ondan sonra bir kez ölçülür. Sınama sonucuna göre okuyucu değişmez.

## 3. Tutmazsa

Fark yazılır (hangi hedef, hangi sayı, kaç tip, hangi alt küme), başvuru betiği de denetlenir (hata iki yanda da
olabilir). H3 tutmazsa kanal yalnız tutan alt küme için ad üretir (karar P-ÜV6'nın); ikinci ayar turu ayrı pakettir.
Eşik ve tanımlar değişmez.
