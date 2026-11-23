# PUV3 — P-ÜV3: Swift tip üst verisi okuyucu ve üretici adım

Önce oku (sırayla, baştan sona): `docs/arge/2026-11-23_dalga1/ORTAK_D1.md`, `docs/arge/2026-11-20_dalga0/ORTAK_D0.md`, `docs/arge/2026-11-18_onarim/ONARIM_BRIF.md`, `docs/arge/2026-11-19_mythos/KARARLAR.md` (A-10, A-13, A-14, A-27), `docs/arge/2026-11-19_mythos/ustveri/PLAN.md` §0 ve "P-ÜV3" (kalemler, biçim, kabul, sınama ve mutasyon: aynen uygula), `docs/arge/2026-11-19_mythos/ustveri/BULGULAR.md`'nin Swift bölümü, `docs/arge/2026-11-19_mythos/ustveri/P-UV2.md` (aynı kalıbın ObjC örneği: okuyucu + üretici adım + durum sözlüğü + INERT yaması; yapıyı ondan al).

Kod başvuruları: `karadul/analyzers/ustveri/goruntu.py` (`Goruntu`, `Bag`; arayüz — değiştirme), `karadul/analyzers/ustveri/objc.py` ve `karadul/pipeline/steps/objc_metadata_recovery.py` (kalıp), araştırma betikleri `scripts/arge/ustveri/swift_meta.py`, `swift_ad_dogrula.py` (çalışan başvuru; ürün kodu onlardan yeniden yazılır, kopyalanmaz).

## Neden

Hedef setinde Swift taşıyan uygulamalar (iTerm2, Rectangle) var; bugün ürün Swift üst verisini hiç okumuyor. Bu paket tip adlarını ve tip başına erişim fonksiyonunu (ad verilebilir) ve vtable / tanık tablosu yuvalarını (yalnız kanıt satırı) okur. Çıktıya bağlama bu pakette değil (P-ÜV6b).

## Ana oturumun hükümleri (plan metninin önüne geçer)

1. **Keşif / sınama ayrımı.** iTerm2 hedef setinin SINAMA ikilisidir; araştırma turunda Swift için de kullanıldı (tam eşitlik 2 444 / 3 659 oradan). Bu pakette "üç eksik"in (adsız bağlam, uzantı bağlamı, içe aktarım adı) hata ayıklaması iTerm2'de YAPILMAZ. Keşif verisi:
   - **Yerelde derlenen Swift örnekleri** (senin yazdığın kaynak; indirme yok): `scripts/arge/ustveri/swift_ornek/*.swift` — `private` / `fileprivate` tipler, uzantı içinde tipler, iç içe tipler, genel (generic) sınıf ve yapı, protokol uyumları (yerel ve dış protokol), sınıf vtable'ı (yöntem, init, getter / setter, zaman uyumsuz yöntem), geçersiz kılma, içe aktarılan C / ObjC tipine uzantı (`HasImportInfo`), `@objc` sınıf. Derleme: `/usr/bin/xcrun swiftc -O` ve `-Onone`, çıktı `~/karadul_olcum/runs/dalga1-2026-11-23/PUV3/ornek/` (sembollü kopya + `/usr/bin/strip` ile soyulmuş kopya). Derleme çıktısı ÇALIŞTIRILMAZ, depoya girmez (yalnız kaynak, sayı ve sha256). GT: sembollü kopyanın sembol tablosu + `/usr/bin/xcrun swift-demangle`.
   - Rectangle arm64 (soyulmuş; GT yok): yalnız sayı eşitliği (`$V/swift/Rectangle.json`).
   - iTerm2'de **sayı eşitliği** (H1: tip 3 659 vb.; `$V/swift/iTerm2.json` başvurusu) keşifte serbesttir (GT'ye bakmaz). **Ad eşitliği (H2, H3)** yalnız okuyucu dondurulduktan sonra BİR kez.
2. `swift_slots` ad adayı değildir (plan kalem 3); adım çıktısında ayrı anahtar.
3. Bayrak `binary_reconstruction.enable_swift_metadata_recovery` (BAYRAK ekledi; INERT'te). Adım bayrağı `getattr(…, "enable_swift_metadata_recovery", False) is True` ile okur; INERT satırını silen ve `# ETKİSİZ` yorumunu düzelten yamayı bırakırsın: `docs/arge/2026-11-23_dalga1/yamalar/PUV3__config.py.patch`. Adım Faz 1 listesine ve `steps/__init__.py`'ye EKLENMEZ (P-ÜV6b).
4. Durum sabitleri: `goruntu.py`'dekileri içe aktar; orada olmayanları (`tutarsiz`, `kapali`) `objc.py`'deki gibi kendi modülünde tanımla (tek tanıma taşıma P-ÜV6b'de).
5. Biçim bilgisi planda yazılı (kaynak swiftlang/swift başlıkları, 2026-11-19). Ağa çıkamazsın; makinedeki Swift araç zincirinin başlıkları (`/Library/Developer/CommandLineTools/…` altında `swift/ABI/*.h` varsa) ve yerel örneklerin `xcrun swift-demangle` / `/usr/bin/nm` çıktısı doğrulama kaynağındır. Plandaki bir ofset yerel örnekle tutmuyorsa örneğe uy, farkı ilerleme dosyana yaz.

## Yazabileceğin dosyalar (hepsi yeni)

`karadul/analyzers/ustveri/swift.py`; `karadul/pipeline/steps/swift_metadata_recovery.py`; `tests/test_puv3_swift.py`; `scripts/measurement/mutation_specs_puv3.json`; `scripts/arge/ustveri/swift_ornek/` (kaynaklar + derleme / GT betiği); `scripts/measurement/ustveri_olc.py`'ye Swift ad eşitliği kolu gerekiyorsa DOKUNMA, kendi betiğini yaz (`scripts/arge/ustveri/puv3_olc.py`); `docs/arge/2026-11-19_mythos/ustveri/on_kayit_PUV3.md`, `docs/arge/2026-11-19_mythos/ustveri/P-UV3.md` (ilerleme dosyası); yama `docs/arge/2026-11-23_dalga1/yamalar/PUV3__config.py.patch`.

**Dokunma:** var olan bütün dosyalar (`karadul/analyzers/swift_binary.py`, `goruntu.py`, `objc.py`, `go_pclntab.py`, `stages.py`, `config.py`, `steps/__init__.py`, `_feedback_naming_*.py`). Ghidra koşusu YOK.

## Ön kayıt (`on_kayit_PUV3.md`; ölçümden önce commit)

Plandaki H1–H5 aynen, şu eklerle:
> H0 (keşif, yerel örnekler): sembollü kopyada tip betimleyicisi sembolü (`Mn`) olan her tip okunur; erişim fonksiyonu adresi `Ma` sembolünün adresiyle aynı; nitelikli ad `swift-demangle` çıktısıyla aynı — üç eksiğin her biri için en az 3 örnek tip, hepsi doğru. Soyulmuş kopyada okuyucu çıktısı sembollüyle aynı (fark 0).
> H3 (SINAMA, bir kez; okuyucu dondurulduktan sonra): iTerm2'de ad verilen tip ≥ 3 477 / 3 659 ve ad verilenlerde yanlış ≤ %1. İkisinden biri tutmazsa kanal yalnız tutan alt küme için ad üretir; hangi alt kümelerin (adsız bağlam / uzantı / içe aktarım / öbür) kaç yanlış verdiği yazılır, okuyucu sınama sonucuna göre YENİDEN AYARLANMAZ (ikinci tur ayrı pakettir).

## Sıra

1. Ön kayıt → commit. 2. Yerel örnekler + GT betiği → commit. 3. Okuyucu (tipler, erişim fonksiyonu, nitelikli ad) + sentetik testler. 4. Vtable / geçersiz kılma / uyum / tanık tablosu. 5. Üretici adım + yama. 6. Sağlamlık (kesik girdi, üst sınırlar, desteklenmeyen genel bayrak) + mutasyon (≥ 8). 7. Keşif ölçümü (H0, H1 sayı eşitliği Rectangle + iTerm2, H5). 8. Dondur (commit'i yaz) → H2, H3'ü bir kez ölç. 9. Tam takım (yama geçici uygulanmış), geri al.

## Sert son: 11:30

Yetişmezse öncelik: tip adı + erişim fonksiyonu (ad kanalının girdisi) tam ve ölçülmüş olsun; vtable / tanık yuvaları "kalan"a yazılabilir.

## Dönüş mesajı

İlk satır gerçek uygulama sayıları: iTerm2 ad verilen tip x / 3 659, yanlış y; Rectangle tip 186 / 186. Sonra H0–H5, test / mutant sayıları, dondurma commit'i, commit listesi, yama, P-ÜV6b'ye notlar (ad adayı olacak alan, kanıt satırı olacak alan, bilinen yanlış alt kümeleri).
