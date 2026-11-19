# Hat: ÜST VERİ (A3, I2, I4; yayın kapısı G4) — tur 1

Hat dizinin: `docs/arge/2026-11-19_mythos/ustveri/`, betikler `scripts/arge/ustveri/`, veri `~/karadul_olcum/runs/arge-2026-11-19/ustveri/`. Önce `ORTAK_BRIF.md`, sonra `KARARLAR.md`.

## Neden şimdi

Yön kararında (`YON.md` §4) bu hat "geliştirme setinde nüfusu yok" diye ertelenmişti. Bugünkü gösteri koşusu (Ollama.app 0.40.3 ana ikilisi, 51,8 MB; Go + C++ + Cocoa) nüfusu getirdi ve iki şey gösterdi:
- Ghidra 12.1.2 bu ikilinin Go sürümünü tanımıyor: `Untested Go version [1.26.0] … Missing Go bootstrap type info, unable to extract Go RTTI info`.
- Karadul'un Go, Rust, RTTI, DWARF kanalları K-4 ile bayrak arkasında ve kapalı; gerçek koşuda hiç ölçülmedi (`docs/arge/2026-11-18_onarim/P13b.md`).

Berke'nin sorusu: "50 MB'lık gerçek bir uygulamada bu yazılım analistin işine yarar mı?" Geliştirme seti düz C; gerçek uygulamalar Go, Swift, Objective-C, C++ taşıyor.

## Soru

Derleyicinin ve dil çalışma zamanının soyulmuş ikilide bıraktığı üst veriden (Go `pclntab` / `moduledata`; Objective-C sınıf, yöntem ve seçici listeleri; Swift tip üst verisi; C++ RTTI / vtable) kaç fonksiyona **kesin** ad verilebilir? Karadul'un var olan kanalları bugün bunu okuyabiliyor mu? Sahte üst veri nasıl ayırt edilir?

## Yasak cevap (literatürün beklediği)

- "Üst veri derleyicinin yazdığı şeydir, güvenilirdir; oku ve ada yaz." (I4'ün aykırı öncülü tam bunu sorguluyor.)
- "Mac'te ad sorunu çözülmüş sorundur." Sayıyla göster ya da çürüt.

## Aykırı öncüller (sına)

1. **Gerçek uygulamalarda doğru adın büyük kısmı hesaplamadan değil üst veriden gelir; düz C'den oluşan geliştirme seti ürünün gerçek değerini olduğundan düşük gösteriyor.** Elindeki açık kaynak uygulamalarda say: üst veriden kesin adlanabilen fonksiyon / toplam fonksiyon; dil başına.
2. **Üst verinin bir kısmı çalışma için zorunludur, bir kısmı serbest metindir.** Saldırgan zorunlu alanı bozarsa ikili çalışmaz; serbest metni (ad dizgisi) istediği gibi yazar. Hangi alan hangisi? Ad, zorunlu yapılarla (fonksiyon sınırı tablosu, yöntem listesi ↔ uygulama adresi) tutarlıysa "kesin", yalnız serbest metinse "aday" mı olmalı?
3. **I2'nin aykırı öncülü:** "Mach-O'da `LC_MAIN` girişi zaten `main`'dir; sorun kurtarma değil, kanalların `entry` adını tanımaması." Doğruysa bu bir pakettir.

## Hedefler (yalnız açık kaynak; makinede hazır, indirme yok)

- `~/karadul_olcum/runs/gosteri-2026-11-19/ollama/girdi/Ollama` (MIT; evrensel Mach-O; Go 1.26 + C++ + Cocoa). Gösteri koşusu aynı dizinde sürüyor: `girdi/` dışına dokunma; `CIKIS` dosyası oluşunca `ws/` ve `out/` salt okur kullanılabilir.
- `/opt/homebrew/Cellar/gh/2.105.0/bin/gh` (MIT; Go), `/opt/homebrew/Cellar/lima/2.3.0/bin/limactl` (Apache-2.0; Go).
- Geliştirme setinin Mach-O ikilileri (`~/karadul_olcum/runs/urun-onarim-a62f15e/mac/`) ve P-S3b'nin Mach-O kabul seti: I2 için.
- Makinedeki başka açık kaynak Swift / Objective-C uygulaması varsa (lisansını doğrula) ekle. **Kapalı kaynak uygulamaları (Microsoft, DeepL, ChatGPT vb.) analiz etme**; depo herkese açık.
- Kopyalarını kendi veri dizinine al; yerinde değiştirme. Hiçbir hedef çalıştırılmaz.

## Bu turun kalemleri (hepsi; zaman kısıtı yok)

1. **Envanter.** Hedef başına: dil karışımı, dilim, soyulma durumu, sembol tablosu var mı, hangi üst veri bölümleri var (`__gopclntab` / `runtime.pclntab` imzası, `__objc_*`, `__swift5_*`, RTTI), Go sürümü.
2. **Go.** `pclntab`'ı ikiliden doğrudan okuyan araştırma betiği (Go 1.18+ başlık biçimleri; 1.26'yı ikilinin kendisinden doğrula, ezberden yazma). Say: fonksiyon girişi, ad, kaynak dosya yolu; paket kırılımı (çalışma zamanı / standart kitaplık / üçüncü taraf / programın kendi paketi). Doğrulayıcı: sembol tablosu olan ikilide ad ↔ adres birebir karşılaştırma; olmayan ikilide iç tutarlılık (adresler `__text` içinde, artan, işlev sınırlarıyla uyumlu). Karadul'un var olan Go kodu (`karadul/analyzers/go_binary.py`, `karadul/reconstruction/go_reconstructor.py`, K-4 Go kanalı) aynı ikililerde ne veriyor: çağır ve karşılaştır (salt okur; ürün kodunu değiştirme).
3. **Objective-C / Swift.** Yöntem listelerinden (sınıf, seçici → uygulama adresi) ve Swift üst verisinden adlanabilen fonksiyon sayısı. Ghidra'nın kendi verdiği adlarla farkı gösteri koşusu bitince `ws/` çıktısından say; bitmediyse açık ölçüm olarak bırak.
4. **C++ RTTI.** Sınıf adı kurtarılabilen vtable sayısı; vtable yuvalarından adlanabilen (sınıf + yuva) fonksiyon sayısı. `karadul/analyzers/cpp_rtti.py`'nin bugünkü durumu (üretici adımı yok: IMZA-16).
5. **Mach-O `main` (I2).** Aykırı öncül 3'ü geliştirme setinin Mach-O ikililerinde sına: `LC_MAIN` giriş adresi GT'deki `main` ile aynı mı; `_recover_main_from_entry` neden 6 / 6'da bulamıyor (P-S3b notu).
6. **Düşman girdi (I4).** Alanları "çalışma için zorunlu" / "serbest metin" diye sınıfla (Go, ObjC, Swift, RTTI için ayrı tablo; kaynak: çalışma zamanının bu alanı nerede okuduğu). Küçük deney: bir Go ikilisinin kopyasında (veri dizininde) `pclntab` ad dizgilerinden birkaçını değiştir, ikiliyi çalıştırmadan önerdiğin tutarlılık denetiminin bunu yakalayıp yakalamadığını say. Yakalayamıyorsa bunu açıkça yaz: o zaman üst veri adı "kesin" değil "üst veriden, doğrulanamaz" etiketiyle yazılmalı.
7. **Bütçe.** Hedef başına tablo: toplam fonksiyon; üst veriden kesin adlanabilen; Ghidra'nın zaten adlandırdığı; Karadul'un bugün adlandırdığı; kalan. Aykırı öncül 1 için hüküm.
8. **PLAN.** Kanalların açılması için Opus paketleri (Go sürüm desteği, ObjC / Swift okuyucu, RTTI üretici adımı, `main`, etiket ve güven kuralı, düşman girdi denetimi), kabul ölçütleri ve ön kayıt metinleriyle. Bağımsız doğrulama için gereken veri (kaynağı bilinen, sembollü derlenebilen Go / Swift programları) indirme listesi olarak.

## Kurallar ve çakışmalar

- Ghidra koşma (gösteri koşusu kullanıyor). İkiliyi doğrudan oku (`lief`, `otool`, `nm`, kendi ayrıştırıcın).
- Ürün kodunu değiştirme; ürün fonksiyonlarını yalnız çağır.
- Ad listelerini belgeye dökme; sayı ve birkaç örnek yeter.
- Her sayı betikten. `PLAN.md` kendi başına uygulanabilir olmalı (yazan orada olmayacak).
- K-4 kararı geçerli: ad üreten kanal bayrak arkasında ve ölçülerek açılır.
