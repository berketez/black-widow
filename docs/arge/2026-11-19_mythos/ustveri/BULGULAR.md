# ÜST VERİ hattı — bulgular (tur 1, 2026-11-19)

- Hat metni: `docs/arge/2026-11-19_mythos/HAT_USTVERI.md`. Defter: `DEFTER.md` (aynı dizin).
- Betikler: `scripts/arge/ustveri/`. Veri kökü: `~/karadul_olcum/runs/arge-2026-11-19/ustveri/` (aşağıda `$V`).
- Bütün tablolar tek betiğin çıktısıdır: `PYTHONDONTWRITEBYTECODE=1 python scripts/arge/ustveri/tablo.py > $V/tablolar.md`. Tabloları besleyen JSON'ları üreten komutlar her bölümün başında.
- Ghidra koşulmadı; hiçbir hedef ikili çalıştırılmadı. İkililer `$V/hedef/` altındaki kopyalardan okundu.
- Terimler: **üst veri** = derleyicinin / dil çalışma zamanının ikilide bıraktığı tablolar (Go `pclntab`, ObjC yöntem listeleri, Swift tip betimleyicileri, C++ RTTI). **Kesin ad** = fonksiyonun tam adı üst veriden okunuyor. **Yuva** = üst veri fonksiyonun adresini ve ait olduğu tipi veriyor ama yöntem adını vermiyor (C++ vtable, Swift vtable / tanık tablosu).

## 0. Hükümler

| Öncül | Hüküm | Dayanak |
|---|---|---|
| Yasak cevap 1: "üst veri güvenilirdir; oku ve yaz" | **Çürütüldü (ad metni için).** Derleyicinin yazdığı hâliyle ad doğru (Go 125 125 / 125 125, ObjC 33 643 / 33 643), ama ad dizgisi çalışma için zorunlu değil: bozma deneyinde ikinci kaynağı olmayan fonksiyonlarda son bileşen değişikliği 0 / 134 ve 0 / 116, tutarlı sahtecilik 0 / 86 ve 0 / 451 yakalandı. | §6 |
| Yasak cevap 2: "Mac'te ad sorunu çözülmüş sorundur" | **Çürütüldü (dile göre).** Soyulmuş Swift uygulamasında (Rectangle) üst veriden kesin ad %26,5; C++'ta 0 (yalnız sınıf + yuva); düz C'de 0. Go ve ObjC'de doğru. | §7 |
| Aykırı öncül 1: gerçek uygulamada doğru adın büyük kısmı üst veriden gelir | **Go ağırlıklı ikililerde tuttu** (Ollama uygulaması %83,0; Go komut satırı araçları %92,2–%100, `gh` tanım gereği %100), **Swift / C++ / C'de tutmadı**. Ürün bugün bu adların hiçbirini okumuyor (K-4 Go kanalı 0–2 fonksiyon). | §2, §7 |
| Aykırı öncül 2: üst verinin bir kısmı zorunlu, bir kısmı serbest metin | **Tuttu ve ölçüldü.** Fonksiyon sınırları / gönderim hedefleri zorunlu; Go fonksiyon adı, C++ sınıf adı, ObjC kategori adı serbest metin; ObjC seçicisi ve Go arayüz yöntem adı gönderim anahtarı. Alan tabloları §6.1. | §6 |
| Aykırı öncül 3 (I2): `LC_MAIN` girişi zaten `main` | **Tuttu:** GT'li 8 / 8; Homebrew'da `_main` sembollü 1 169 / 1 169. Ürün 0 / 8'inde `main` veriyor; neden: kurtarma kodu yalnız `__libc_start_main` kalıbını arıyor. Tek paket. | §5 |

### Kanal kesinliği özeti

Sembol tablosu duran ikililerde, üst veriden okunan adın sembolle karşılaştırması (ayrıntı ilgili bölümlerde):

| Kanal | Doğrulayıcı ikililer | Doğru / sembolü olan | Kesinlik (Wilson %95) | Wilson alt sınırı ≥ 0,909 (A-2) |
|---|---|---|---|---|
| Go `pclntab` adı (yazım kuralları dahil) | docker-cli 1.24.4, docker-compose 1.23.8 | 125 125 / 125 125 | %100,000 (%99,997–%100,000) | evet (0,999969) |
| ObjC yöntem listesi (`±[Sınıf seçici]`) | terminal-notifier, iTerm2 arm64 | 33 643 / 33 643 | %100,000 (%99,989–%100,000) | evet (0,999886) |
| Swift erişim fonksiyonu (tür: sembol `Ma` ekli) | iTerm2 arm64 | 3 659 / 3 659 | %100,0 (%99,9–%100,0) | evet (0,998951) |
| Swift tip adı, nitelikli ad tam eşit (bugünkü araştırma okuyucusu) | iTerm2 arm64 | 2 444 / 3 659 | %66,8 (%65,3–%68,3) | hayır (0,652513) |
| C++ typeinfo sınıf adı | btop, iTerm2, llama-server arm64, Ollama x86_64 | 2 028 / 2 028 | %100,0 (%99,8–%100,0) | evet (0,998109) |
| C++ vtable ↔ sınıf adı | btop, iTerm2, llama-server arm64 | 1 328 / 1 328 | %100,0 (%99,7–%100,0) | evet (0,997116) |
| C++ yuva işlevi sınıfa (ya da tabanına) ait | btop, iTerm2, llama-server arm64 | 7 098 / 7 119 | %99,7 (%99,5–%99,8) | evet (0,995494) |
| Mach-O `LC_MAIN` girişi = `main` (GT'li) | htop, tmux + P-S3b kabul seti (6) | 8 / 8 | %100,0 (%67,6–%100,0) | hayır (0,675592) |
| Mach-O `LC_MAIN` girişi = `_main` sembolü | Homebrew çalıştırılabilirleri | 1 169 / 1 169 | %100,0 (%99,7–%100,0) | evet (0,996725) |

- Bu kesinlikler **derleyicinin yazdığı hâliyle** üst veri içindir; kasıtlı değiştirilmiş üst veriyi kapsamaz (§6).
- Mach-O `main` satırında GT'li 8 ikilinin Wilson alt sınırı 0,676 (n küçük); geniş nüfus satırı (1 169 / 1 169) sembol tablosuna karşı aynı kuralı ölçüyor.

## 1. Envanter (kalem 1)

Komut: `python scripts/arge/ustveri/envanter.py $V/hedef/<…> --cikti $V/envanter.json`.

| Hedef | Dilim | Boyut (bayt) | Kod (bayt) | Dil işareti | Go sürümü | Fonksiyon başlangıcı | Sembol | Kod sembollü başlangıç | Hata ayıklama sembolü |
|---|---|---|---|---|---|---|---|---|---|
| Ollama | x86_64 | 27 653 376 | 6 230 627 | Go, Objective-C, C++ (libc++ bağlı) | go1.26.0 | 13 027 | 932 | 528 | 0 |
| Ollama | arm64 | 26 627 984 | 5 524 396 | Go, Objective-C, C++ (libc++ bağlı) | go1.26.0 | 12 952 | 899 | 528 | 0 |
| gh | arm64 | 39 146 642 | 15 008 536 | Go | go1.27.4 | yok | 147 | — | 0 |
| limactl | arm64 | 34 610 480 | 14 577 300 | Go, Objective-C | go1.27.3 | 40 917 | 812 | 411 | 0 |
| ollama-cli | x86_64 | 27 206 368 | 13 647 259 | Go, C++ (libc++ bağlı) | go1.26.0 | 27 394 | 1 493 | 601 | 0 |
| ollama-cli | arm64 | 24 846 672 | 11 745 720 | Go, C++ (libc++ bağlı) | go1.26.0 | 27 293 | 1 491 | 601 | 0 |
| colima | arm64 | 10 502 002 | 4 417 248 | Go | go1.26.4 | 13 121 | 192 | 36 | 0 |
| docker-brew | arm64 | 29 097 186 | 12 048 784 | Go | go1.27.4 | 35 776 | 198 | 27 | 0 |
| arduino-cli | arm64 | 27 106 578 | 10 314 232 | Go | go1.27.3 | 29 738 | 196 | 27 | 0 |
| docker-cli | arm64 | 41 735 936 | 11 953 928 | Go | go1.24.4 | yok | 43 498 | — | 0 |
| docker-compose | arm64 | 74 451 488 | 29 221 288 | Go | go1.23.8 | 90 257 | 111 847 | 90 257 | 0 |
| iTerm2 | x86_64 | 71 401 408 | 26 463 671 | Objective-C, Swift, C++ (libc++ bağlı) | — | 109 915 | 796 393 | 109 102 | 546 695 |
| iTerm2 | arm64 | 68 937 440 | 23 474 484 | Objective-C, Swift, C++ (libc++ bağlı) | — | 109 608 | 815 811 | 108 776 | 541 872 |
| Rectangle | x86_64 | 949 456 | 583 726 | Objective-C, Swift, C++ (libc++ bağlı) | — | 2 454 | 687 | 0 | 1 |
| Rectangle | arm64 | 882 048 | 492 200 | Objective-C, Swift, C++ (libc++ bağlı) | — | 2 401 | 672 | 0 | 1 |
| terminal-notifier.macho | arm64 | 132 896 | 28 276 | Objective-C | — | 92 | 819 | 92 | 412 |
| btop | arm64 | 1 169 064 | 852 820 | C++ (libc++ bağlı) | — | 1 952 | 975 | 193 | 0 |
| llama-server | arm64 | 17 927 776 | 7 757 216 | C++ (libc++ bağlı) | — | 17 211 | 32 317 | 17 210 | 0 |

Okuma notları:
- Hedeflerin kaynağı ve lisansı: Ollama 0.40.3 uygulama ikilisi ve aynı paketin `ollama` komut satırı ile `llama-server` ikilisi (MIT; paketin `Resources/` dizinindeki lisans dosyaları), `gh` 2.105.0 (MIT), `limactl` 2.3.0 (Apache-2.0), `colima` 0.10.3 (MIT), `docker` 29.10.0 (Homebrew; Apache-2.0), `arduino-cli` 1.6.0 (GPL-3.0), `btop` 1.4.8 (Apache-2.0), `terminal-notifier` 3.1.0 (MIT) — lisanslar Homebrew formüllerinden; Rectangle 0.94 (MIT) ve iTerm2 3.7.7 (GPL-2.0) — depo `LICENSE` dosyalarından (2026-11-19). `docker-cli` ve `docker-compose` kopyaları Docker Desktop paketinin içinden alındı; ikisi de açık kaynak projelerin derlemesi (Apache-2.0; ana paket yolu `github.com/docker/cli/cmd/docker`, `github.com/docker/compose/v2/cmd`) ve makinedeki **sembol tablosu duran** tek Go ikilileri. Yalnız doğrulayıcı olarak kullanıldılar; paketin kapalı kaynak parçalarına dokunulmadı.
- Soyulma durumu: Ollama arm64'te 12 952 fonksiyon başlangıcının 528'inde sembol var; `gh` iç bağlayıcıyla üretilmiş (`LC_FUNCTION_STARTS` yok, kod sembolü 0). iTerm2 soyulmamış (815 811 sembol, 541 872'si hata ayıklama kaydı), `llama-server` soyulmamış.
- Swift bölümü (`__swift5_*`) yalnız iTerm2 ve Rectangle'da var; Ollama, `gh`, `limactl`'de yok.
- Go sürümleri: 1.23.8, 1.24.4, 1.26.0, 1.26.4, 1.27.3, 1.27.4. `pclntab` imzası hepsinde `0xfffffff1`.

## 2. Go `pclntab` (kalem 2)

Komutlar: `python scripts/arge/ustveri/go_say.py $V/hedef/<ad> --cikti $V/go/<ad>.json --liste $V/go/<ad>.tsv`; ürün karşılaştırması `PYTHONPATH=. python scripts/arge/ustveri/karadul_go_olc.py $V/hedef/<ad> --cikti $V/karadul_go/<ad>.json`.

### 2.1 Biçim: ikiliden ve resmî kaynaktan doğrulananlar

Kaynak: Go kaynak ağacı `release-branch.go1.26` ve `release-branch.go1.27` (github.com/golang/go; 2026-11-19): `src/runtime/symtab.go`, `src/runtime/runtime2.go`, `src/internal/abi/symtab.go`, `src/debug/buildinfo/buildinfo.go`.

1. **Go 1.26: `pcHeader.textStart` kaldırıldı.** Kaynakta alan `_ uintptr`; açıklaması: eskiden metin başlangıç adresiydi, yeniden konumlama gerektirdiği için bırakıldı, `moduledata.text` kullanılmalı. İkilide: 1.26.0 / 1.26.4 / 1.27.3 / 1.27.4 dilimlerinin 9'unda başlığın o alanı `0x0`; 1.23.8 / 1.24.4'te gerçek adres (aşağıdaki tablo, 3. sütun). Metin tabanı `moduledata`'dan okunmadıkça 1.26+ ikililerde hiçbir fonksiyon adresi hesaplanamaz.
2. **Go 1.27: tip verisinin yerleşimi değişti.** `moduledata`'ya `typedesclen`, `itaboffset`, `itabsize` eklendi; `runtime/iface.go` `addModuleItabs` itab'ları `types + itaboffset`'ten yürüyor. Mach-O'da `__typelink` / `__itablink` bölümleri yok (`__go_type`, `__go_func` var).
3. **`funcID` numaraları sürüme bağlı.** 1.23 / 1.24'te sarmalayıcı kimliği 22, 1.26+'da 23.
4. `moduledata` sembolsüz ikilide bulunuyor: ilk alanı `pcHeader` adresi olan tek veri yeri (11 dilimin 11'inde tek aday; zincirli düzeltmeli ikililerde düzeltme zinciri çözülerek).
5. Ghidra 12.1.2 kurulumundaki Go sürüm verisi `go1.15.0` … `go1.25.0` (`Ghidra/Features/Base/data/typeinfo/golang/`); bu hattaki 11 Go diliminin 9'u ≥ 1.26.

### 2.2 Sayım

| Hedef | Go | Giriş | Adlı | Dosya yolu olan | Ayrık dosya | Yalnız satır içi ad | Çalışma zamanı | Standart | Üçüncü taraf | Kendi | Derleyici | Paketsiz |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| gh | 1.27.4 | 40 384 | 40 383 | 40 381 | 2 803 | 7 109 | 1 661 | 11 381 | 22 270 | 4 385 | 650 | 36 |
| limactl | 1.27.3 | 40 321 | 40 320 | 40 318 | 2 613 | 6 939 | 1 697 | 11 324 | 24 699 | 1 927 | 609 | 64 |
| Ollama.arm64 | 1.26.0 | 10 601 | 10 600 | 10 598 | 840 | 3 584 | 1 580 | 6 657 | 594 | 1 257 | 435 | 77 |
| Ollama.x86_64 | 1.26.0 | 10 676 | 10 675 | 10 673 | 856 | 3 572 | 1 579 | 6 692 | 596 | 1 257 | 437 | 114 |
| ollama-cli.arm64 | 1.26.0 | 25 164 | 25 163 | 25 161 | 1 603 | 5 942 | 1 683 | 10 379 | 6 133 | 6 026 | 892 | 50 |
| ollama-cli.x86_64 | 1.26.0 | 25 267 | 25 266 | 25 264 | 1 628 | 5 926 | 1 681 | 10 417 | 6 156 | 6 029 | 894 | 89 |
| colima | 1.26.4 | 13 082 | 13 081 | 13 079 | 903 | 3 143 | 1 657 | 8 568 | 1 520 | 863 | 437 | 36 |
| docker-brew | 1.27.4 | 35 749 | 35 748 | 35 746 | 2 080 | 5 718 | 1 715 | 10 255 | 20 265 | 2 549 | 919 | 45 |
| arduino-cli | 1.27.3 | 29 711 | 29 710 | 29 708 | 2 094 | 6 188 | 1 668 | 10 319 | 13 500 | 3 793 | 388 | 42 |
| docker-cli | 1.24.4 | 35 049 | 35 048 | 35 046 | 1 987 | 4 970 | 1 557 | 9 030 | 20 102 | 2 795 | 1 523 | 41 |
| docker-compose | 1.23.8 | 90 078 | 90 077 | 90 077 | 4 302 | 7 006 | 1 551 | 9 041 | 75 616 | 1 477 | 2 331 | 61 |

- "Adlı" olmayan tek giriş her ikilide metin başlangıcındaki adsız kayıttır. Dosya yolu olmayanlar `go:textfipsstart` / `go:textfipsend` işaretleri.
- "Yalnız satır içi ad": `funcnametab`'da duran ama hiçbir girişe bağlı olmayan adlar (başka fonksiyonların içine gömülmüş fonksiyonlar). Bu turda yalnız sayıldı.
- Paket sınıfı kuralı (`go_pclntab.sinif`): `main` ve ana modül yolu altındaki paketler "kendi"; ana modülün `vendor/` dizini ve ilk yol öğesi nokta içerenler "üçüncü taraf"; `runtime`, `runtime/…`, `internal/runtime/…` "çalışma zamanı"; kalan noktasız yollar "standart"; `type:` / `go:` önekliler "derleyici".

### 2.3 Doğrulama

| Hedef | Go | Giriş | Sembolü olan giriş | Ad birebir | `.abi0` ekiyle | Orta nokta yazımıyla | Farklı | Uyum |
|---|---|---|---|---|---|---|---|---|
| docker-cli | 1.24.4 | 35 049 | 35 049 | 34 710 | 328 | 10 | 1 | %99,997 (%99,984–%99,999) |
| docker-compose | 1.23.8 | 90 078 | 90 078 | 89 699 | 360 | 18 | 1 | %99,999 (%99,994–%100,000) |

- "Farklı" 1'er giriş adsız metin başlangıcıdır (sembolde `runtime.text` / `go:buildid`). Adı olan girişlerin hepsinde ad sembolle aynı: iki ikilide toplam 125 125 / 125 125.
- İki yazım farkı kural olarak sayıldı: sembolde `.abi0` eki (688) ve tip adındaki orta noktanın (`·`) sembolde nokta yazılması (28). `pclntab` yazımı çalışma zamanının kendi bastığı addır.

| Hedef | Go | textStart (başlık) | K1 artan | K2 bölüm dışı | K4 pcsp: tam / dolguyla / kısa (asm) / kısa / taşan | K5 findfunctab uyumlu / alt kova | K6 girişlerin başlangıç olanı / Go aralığında tabloda olmayan | K7 bl hedefi: giriş / Duff içi / başka gövde içi | K8 özel funcID: runtime önekli / toplam |
|---|---|---|---|---|---|---|---|---|---|
| gh | 1.27.4 | 0x0 | 0 | 0 | 40 370 / 0 / 10 / 1 / 0 | 58 621 / 58 621 | başlangıç tablosu yok | 252 310 / 0 / 0 | 19 / 19 |
| limactl | 1.27.3 | 0x0 | 0 | 0 | 40 308 / 0 / 9 / 1 / 0 | 56 674 / 56 674 | 40 321 / 0 | 244 813 / 0 / 0 | 20 / 20 |
| Ollama.arm64 | 1.26.0 | 0x0 | 0 | 0 | 10 598 / 0 / 0 / 0 / 0 | 16 335 / 16 335 | 10 601 / 0 | 70 356 / 0 / 0 | 20 / 20 |
| Ollama.x86_64 | 1.26.0 | 0x0 | 0 | 0 | 11 / 10 662 / 0 / 0 / 0 | 19 026 / 19 026 | 10 676 / 0 | ölçülmedi (x86_64) | 20 / 20 |
| ollama-cli.arm64 | 1.26.0 | 0x0 | 0 | 0 | 25 161 / 0 / 0 / 0 / 0 | 40 573 / 40 573 | 25 164 / 0 | 177 063 / 0 / 0 | 21 / 21 |
| ollama-cli.x86_64 | 1.26.0 | 0x0 | 0 | 0 | 15 / 25 249 / 0 / 0 / 0 | 48 011 / 48 011 | 25 267 / 0 | ölçülmedi (x86_64) | 21 / 21 |
| colima | 1.26.4 | 0x0 | 0 | 0 | 13 079 / 0 / 0 / 0 / 0 | 17 239 / 17 239 | 13 082 / 0 | 74 562 / 0 / 0 | 20 / 20 |
| docker-brew | 1.27.4 | 0x0 | 0 | 0 | 35 746 / 0 / 0 / 0 / 0 | 47 050 / 47 050 | 35 749 / 0 | 197 460 / 0 / 0 | 20 / 20 |
| arduino-cli | 1.27.3 | 0x0 | 0 | 0 | 29 698 / 0 / 9 / 1 / 0 | 40 275 / 40 275 | 29 711 / 0 | 172 285 / 0 / 0 | 20 / 20 |
| docker-cli | 1.24.4 | 0x100001000 | 0 | 0 | 35 046 / 0 / 0 / 0 / 0 | 46 689 / 46 689 | başlangıç tablosu yok | 190 666 / 6 413 / 0 | 18 / 18 |
| docker-compose | 1.23.8 | 0x100002d30 | 0 | 0 | 90 077 / 0 / 0 / 0 / 0 | 114 114 / 114 114 | 90 078 / 126 | 443 490 / 21 159 / 0 | 19 / 19 |

- Sembol tablosundan bağımsız iki yapısal doğrulayıcı var: (a) `LC_FUNCTION_STARTS` tablosu olan 9 dilimin hepsinde `pclntab` girişlerinin tamamı fonksiyon başlangıcı (Go aralığında tabloda olmayan başlangıç yalnız docker-compose'da 126: `duffzero+N` / `duffcopy+N` etiketleri); (b) arm64'teki 9 dilimde doğrudan çağrı (`bl`) hedefleri: Go aralığına düşen bütün hedefler ya bir giriş ya da (Go ≤ 1.25) `runtime.duffzero` / `runtime.duffcopy` gövdesi; başka gövde içi hedef 0.
- K4'te "kısa" kalan 10–11 fonksiyon elle yazılmış birleştirici dili (`klauspost/compress`) ve onun önündeki tek Go fonksiyonu; x86_64'te fonksiyonlar 32'ye hizalı olduğu için "dolguyla" sütunu dolu.
- **Sınır:** Go ≥ 1.26 için sembollü doğrulayıcı makinede yok. 1.26 / 1.27'de ad ↔ adres bire bir karşılaştırması yapılamadı; yapısal denetimler ve `funcID` çapaları (19–21 fonksiyon, hepsi beklenen adı taşıyor) var. Bire bir doğrulama için veri PLAN §9'da.

### 2.4 Karadul'un var olan Go kodu aynı ikililerde

| Hedef | Hedef türü | `_extract_gopclntab` yöntemi | Ad | Adresli | Gerçek `pclntab` adı | Fonksiyon adı olmayan | K-4 Go kanalı: `nm` sembolü | `pclntab` girişine denk gelen / giriş |
|---|---|---|---|---|---|---|---|---|
| gh | go_binary | strings_regex | 11 138 | 0 | 8 010 | 3 128 | 0 | 0 / 40384 |
| limactl | go_binary | strings_regex | 10 417 | 0 | 8 242 | 2 175 | 446 | 2 / 40321 |
| Ollama.arm64 | go_binary | strings_regex | 6 934 | 0 | 4 890 | 2 044 | 555 | 2 / 10601 |
| Ollama.evrensel | universal_binary | strings_regex | 7 003 | 0 | 4 890 | 2 113 | 555 | 2 / 10601 |
| ollama-cli.arm64 | go_binary | strings_regex | 10 027 | 0 | 7 172 | 2 855 | 1 283 | 2 / 25164 |
| colima | go_binary | strings_regex | 8 526 | 0 | 6 002 | 2 524 | 40 | 2 / 13082 |
| docker-brew | go_binary | strings_regex | 10 293 | 0 | 7 317 | 2 976 | 33 | 2 / 35749 |
| arduino-cli | go_binary | strings_regex | 10 395 | 0 | 7 441 | 2 954 | 33 | 2 / 29711 |
| docker-cli | go_binary | nm | 35 009 | 35 009 | 34 669 | 340 | 42 382 | 32405 / 35049 |
| docker-compose | go_binary | nm | 90 144 | 90 144 | 89 638 | 506 | 110 615 | 82103 / 90078 |

- `GoBinaryAnalyzer._extract_gopclntab` (`karadul/analyzers/go_binary.py`) `pclntab`'ı ayrıştırmıyor: sırayla `go tool objdump` (makinede `go` yok), `nm`, `strings` + düzenli ifade deniyor. Soyulmuş ikililerde son yola düşüyor: **adres yok**, bulunan "adların" %20,9–%30,2'si fonksiyon adı değil (gerçek adların bulunan payı %19,9–%46,3).
- K-4 Go kanalı (`_add_go_demangler`, `karadul/pipeline/steps/_feedback_naming_candidates.py`) `nm -P` sembollerini okuyor: soyulmuş 7 hedefte 0–2 fonksiyon. Sembollü ikililerde 32 405 / 35 049 ve 82 103 / 90 078: `is_go_symbol` gerçek Go fonksiyon adlarının bir kısmını reddediyor.
- Evrensel dosyada (Ollama) tür `universal_binary`, dil `unknown`; Go çözümleyicisi evrensel dosyayı açmıyor.
- Ürün koşusunda (Ghidra dahil) bu kanalların verdiği ad sayısı ölçülmedi (Ghidra koşulmadı); yukarıdaki sayılar kanalların **girdisinin** üst sınırıdır.

## 3. Objective-C ve Swift (kalem 3)

Komutlar: `python scripts/arge/ustveri/objc_meta.py $V/hedef/<ad> --cikti $V/objc/<ad>.json --liste $V/objc/<ad>.tsv`; `python scripts/arge/ustveri/swift_meta.py $V/hedef/<ad> --cikti $V/swift/<ad>.json`; `python scripts/arge/ustveri/swift_ad_dogrula.py $V/hedef/iTerm2.arm64 --cikti $V/swift/iTerm2.arm64.ad.json`.

### 3.1 Objective-C

Biçim kaynağı: apple-oss-distributions/objc4 `runtime/objc-runtime-new.h` (2026-11-19); zincirli düzeltmeler SDK `<mach-o/fixup-chains.h>`.

| Hedef | Sınıf | Swift sınıfı | Kategori | Yöntem kaydı | Ayrık IMP | Fonksiyon başlangıcı olan | Arite uyan / uymayan | Protokol yöntemi | ObjC sembollü IMP | Ad aynı (birebir + kategori yazımı) | Farklı |
|---|---|---|---|---|---|---|---|---|---|---|---|
| terminal-notifier | 1 | 0 | 1 | 32 | 32 | 32 | 32 / 0 | 4 | 32 | 31 + 1 | 0 |
| iTerm2.arm64 | 2 557 | 1 047 | 67 | 41 305 | 41 305 | 41 305 | 41 262 / 43 | 6 315 | 33 611 | 31 431 + 2 180 | 0 |
| Ollama.arm64 | 5 | 0 | 1 | 151 | 151 | 151 | 151 / 0 | 15 | 0 | 0 + 0 | 0 |
| Ollama.x86_64 | 5 | 0 | 1 | 151 | 151 | 151 | 151 / 0 | 15 | 0 | 0 + 0 | 0 |
| limactl | 14 | 0 | 0 | 102 | 102 | 102 | 102 / 0 | 16 | 0 | 0 + 0 | 0 |
| Rectangle.arm64 | 135 | 126 | 0 | 450 | 450 | 450 | 450 / 0 | 13 | 0 | 0 + 0 | 0 |

- iTerm2'de (soyulmamış) ObjC sembolü olan 33 611 uygulama adresinin 33 611'inde üst veri adı sembolle aynı. Sembolü ObjC biçiminde olmayan 7 694 adres Swift sınıflarının ObjC'ye açılan köprüleri (Swift sınıfındaki kayıt 7 420).
- Yöntem listesindeki her uygulama adresi kod bölümünde ve bir fonksiyon başlangıcı (6 hedefte 6'sında tam).
- "Arite uymayan" 43 kayıt (iTerm2): seçicideki iki nokta sayısı ile tip kodlamasındaki argüman sayısı farklı; incelenmedi.
- Karadul'da ObjC sınıf / yöntem listesi okuyan kod yok (`grep -rn "__objc_classlist" karadul` → 0, 2026-11-19); ObjC adları yalnız Ghidra'nın kendi çözümleyicisinden gelebilir. **Açık ölçüm:** Ghidra'nın Ollama'da bu 151 yönteme ad verip vermediği (gösteri koşusu 12:16'da bitmemişti).

### 3.2 Swift

Biçim kaynağı: swiftlang/swift `include/swift/ABI/MetadataValues.h`, `Metadata.h`, `GenericContext.h` (2026-11-19).

| Hedef | Tip (sınıf / yapı / enum) | Erişim fonksiyonu | vtable betimleyicisi | Uygulaması boş | Ayrık uygulama (kodda) | Tanık kod göstericisi | Erişim: `Ma` ekli / sembollü | Tanık: `TW` ekli / sembollü | Swift sembollü kod adresi | Üst veriden ulaşılan |
|---|---|---|---|---|---|---|---|---|---|---|
| Rectangle.arm64 | 186 (134 / 34 / 18) | 186 | 961 | 855 | 106 | 39 | 0 / 0 | 0 / 0 | 0 | 0 |
| iTerm2.arm64 | 3 659 (1 104 / 1 206 / 1 349) | 3 659 | 12 258 | 9 868 | 2 264 | 741 | 3 659 / 3 659 | 741 / 741 | 60 771 | 6 725 |

- Swift üst verisi **fonksiyon adı taşımıyor**. Verdiği: tip adı ve tip başına bir erişim fonksiyonu (derleyici üretimi), sınıf vtable'ında yöntem türü (yöntem / init / getter / setter / modify) ve sırası, tanık tablosunda protokol + sıra.
- iTerm2'de Swift sembollü 60 771 kod adresinin 6 725'ine (%11,1) üst veriden ulaşılıyor; tam ad verilebilenler yalnız 3 659 erişim fonksiyonu.
- vtable betimleyicilerinin çoğunda uygulama göstericisi boş (iTerm2 9 868 / 12 258, Rectangle 855 / 961): derleyici bu yöntemleri doğrudan çağrıya çevirmiş.
- Sembol denetimi: erişim fonksiyonlarının 3 659 / 3 659'unda sembol `Ma` ekli; tanık göstericilerinin 741 / 741'inde `TW` ekli; vtable türü ↔ sembol eki: getter 233 / 235, setter 77 / 77, modify 18 / 18, init 32 / 32, yöntem 1 903 / 1 903 (`$V/swift/iTerm2.arm64.json`).
- **Tip adının tam eşitliği** (bugünkü araştırma okuyucusuyla): 2 444 / 3 659. Kalanın 1 149'u adsız bağlamdaki (`private`) tipler, 19'u uzantı bağlamı, 47'si içe aktarılan C tipleri (betimleyicideki ikinci ad okunmuyor). Okuyucunun eksiği; biçimin değil.
- Karadul'un `swift_binary.py`'si `nm` + `xcrun swift-demangle` + `strings` kullanıyor; `__swift5_types` okuyan kod yok.

## 4. C++ RTTI (kalem 4)

Komutlar: `python scripts/arge/ustveri/cpp_rtti_tara.py $V/hedef/<ad> --cikti $V/rtti/<ad>.json`; `PYTHONPATH=. python scripts/arge/ustveri/karadul_rtti_olc.py $V/hedef/<…> > $V/rtti/karadul_cpp_rtti.jsonl`.

Biçim kaynağı: Itanium C++ ABI (vtable ve RTTI yerleşimi), llvm-project `libcxxabi/src/private_typeinfo.h`. Tarama sembol tablosuna bakmıyor: typeinfo nesnesi, ilk sözcüğü `__cxxabiv1` sınıf tip bilgisi vtable'ına **içe aktarım bağı** olan nesnedir (bu bağ ada göre çözüldüğü için soyulmuş ikilide de durur).

| Hedef | typeinfo (sınıf adı) | vtable | Yuva | İçe aktarım yuvası | Ayrık işlev | Çok sınıfta görünen | `__ZTI` aynı / sembollü | `__ZTV` aynı / sembollü | Yuva işlevi: kendi sınıf / taban / başka / sembollü |
|---|---|---|---|---|---|---|---|---|---|
| btop | 42 | 36 | 187 | 54 | 84 | 12 | 1 / 1 | 1 / 1 | 2 / 0 / 0 / 2 |
| iTerm2.arm64 | 18 | 10 | 74 | 10 | 64 | 0 | 18 / 18 | 10 / 10 | 63 / 1 / 0 / 64 |
| llama-server.arm64 | 1 994 | 1 317 | 10 415 | 1 162 | 7 053 | 122 | 1 994 / 1 994 | 1 317 / 1 317 | 7 023 / 9 / 21 / 7 053 |
| Ollama.arm64 | 19 | 8 | 92 | 21 | 68 | 3 | 0 / 0 | 0 / 0 | — |
| Ollama.x86_64 | 19 | 8 | 92 | 21 | 68 | 3 | 15 / 15 | 0 / 0 | — |

Karadul `cpp_rtti.CppRttiAnalyzer` (aynı ikililer):

| Hedef | Sınıf | vtable'ı olan | Yöntem |
|---|---|---|---|
| Ollama.arm64 | 2 | 0 | 0 |
| Ollama.x86_64 | 17 | 0 | 0 |
| btop | 18 | 1 | 4 |
| iTerm2.arm64 | 22 | 6 | 85 |
| llama-server.arm64 | 2 023 | 1 317 | 14 892 |

- Sembollü `llama-server`'da 1 994 / 1 994 typeinfo adı ve 1 317 / 1 317 vtable sembolle aynı; yuvalardaki 7 053 işlevin 7 023'ünün sembolü sınıfın kendi adını, 9'unun taban sınıf adını taşıyor; 21'i başka (şablon yardımcıları).
- **`karadul/analyzers/cpp_rtti.py` soyulmuş ikilide çalışmıyor:** typeinfo ve vtable'ı `_ZTI` / `_ZTV` sembollerinden buluyor. Ollama arm64'te vtable 0, yöntem 0 (tarama: 8 vtable, 68 işlev); btop'ta 1 vtable, 4 yöntem (tarama: 36 vtable, 84 işlev). Sembol durduğunda ise yöntem adları zaten sembol tablosunda. Yani IMZA-16 yalnız "üretici adımı bağla" işi değil: okuyucunun sembolsüz çalışması gerekiyor.
- Sınıf adı yöntem adı değildir: yuvadan gelen aday `Sınıf::vfunc_N`'dir; N'inci yuvanın hangi yöntem olduğu RTTI'de yok.
- Tarama yalnız zincirli düzeltmeli Mach-O'da denendi (eski `LC_DYLD_INFO` bağ kodları ve ELF okunmadı).

## 5. Mach-O `main` (kalem 5, I2)

Komutlar: `python scripts/arge/ustveri/macho_main.py gt --cikti $V/main/gt.json`; `python scripts/arge/ustveri/macho_main.py nufus /opt/homebrew/Cellar --cikti $V/main/nufus_homebrew.json`.

| İkili | `LC_MAIN` girişi = GT `_main` | Ghidra'nın o adresteki adı | Ürünün `main` verdiği fonksiyon | `main_recovered` | `__libc_start_main` geçen dosya |
|---|---|---|---|---|---|
| htop | evet | entry (thunk) | 0 | None | 0 |
| tmux | evet | entry | 0 | None | 0 |
| gettext | evet | entry | 0 | None | 0 |
| envsubst | evet | entry | 0 | None | 0 |
| idn2 | evet | entry | 0 | None | 0 |
| gsort | evet | entry | 0 | None | 0 |
| gmktemp | evet | entry | 0 | None | 0 |
| xz | evet | entry | 0 | None | 0 |

Toplam: 8 / 8; %100,0 (%67,6–%100,0).

Homebrew nüfusu: çalıştırılabilir 1 188; `_main` sembollü 1 169; giriş = `_main` 1 169 (%100,0 (%99,7–%100,0)); `_main` sembolü olmayan 19 (Go 5).

- `_recover_main_from_entry` (`karadul/stages.py:1816`) yalnız decompile çıktısında `__libc_start_main(FUN_…` kalıbını arıyor (`_LIBC_START_MAIN_RE`, satır 1720). Mach-O'da bu çağrı yok: dyld, `LC_MAIN` girişini doğrudan `main` olarak çağırır. 8 / 8 ikilide kalıp 0 dosyada geçiyor.
- htop'ta giriş 4 baytlık bir atlama (Ghidra `thunk` sayıyor; GT'de de `_main` aynı adreste 4 bayt). Ad bekleyen nüfus thunk'ları saymadığı için htop'ta `main` nüfusta değil.
- Go: dış bağlayıcılı derlemelerde giriş `pclntab`'a göre `main` (çalışma zamanının C girişi; kullanıcının `main.main`'i değil); iç bağlayıcılı derlemelerde `_rt0_arm64_darwin` (`$V/main/go_giris.txt`). `pclntab` varsa onun adı geçerli olmalı.
- `main`'den yayılan kanalların (`usage` geleneği) Mac'teki farkı bu turda ölçülmedi (ürün koşusu ister).

## 6. Düşman girdi (kalem 6, I4)

### 6.1 Hangi alan zorunlu, hangisi serbest metin

"Okuyan yer" sütunu çalışma zamanının kaynak kodundan (2026-11-19'da okundu). "Zorunlu" = bozulursa program olağan çalışmasında bozulur; "serbest" = yalnız hata dökümü / yansıtma / tanılama okur.

**Go** (`runtime/symtab.go`, `runtime/traceback.go`, `runtime/iface.go`, `internal/abi/type.go`; dal `release-branch.go1.27`)

| Alan | Okuyan yer | Sınıf |
|---|---|---|
| `pcHeader` imza, `minLC`, `ptrSize` | `moduledataverify1` (açılışta) | zorunlu |
| `ftab` giriş ofsetleri, `findfunctab` | `findfunc` (yığın açma, çöp toplayıcı); sıra ve `minpc` / `maxpc` açılışta denetlenir | zorunlu |
| `_func.pcsp`, `pcdata`, `funcdata`, `funcID`, `flag`, `deferreturn` | `traceback.go` `resolveInternal` / `next` (yığın açma), çöp toplayıcı yığın taraması | zorunlu |
| **`_func.nameOff` → fonksiyon adı** | `traceback.go`: `funcNamePiecesForPrint`, `printFuncName`, `showfuncinfo`, `isExportedRuntime`, `isSystemGoroutine` — yalnız dökümün ne basacağı; yığın açma ad okumuyor | **serbest metin** |
| `pcfile`, `pcln`, `cutab`, `filetab` (dosya, satır) | `funcline1` — döküm ve `runtime.Caller` çıktısı | serbest metin |
| `itab.Fun[]` | arayüz çağrısının hedefi | zorunlu |
| Arayüz ve somut tip **yöntem adı** (tip verisi) | `iface.go` `itabInit`: çalışma anında kurulan itab'da ad dizgisi ve tip karşılaştırılır | gönderim anahtarı (iki yanda aynı olmak zorunda; metnin kendisi serbest) |
| `Method.Tfn` / `Ifn` | yansıtma ile çağrı, itab kurulumu | zorunlu (kullanılıyorsa) |

**Objective-C** (objc4 `objc-runtime-new.h`, `objc-runtime-new.mm`)

| Alan | Okuyan yer | Sınıf |
|---|---|---|
| Yöntem listesi IMP'i | ileti gönderimi | zorunlu |
| **Seçici dizgisi** | `fixupMethodList` → `sel_registerNameNoLock`: seçicinin kimliği dizginin içeriği; çağıran ve tanımlayan aynı dizgiyi paylaşır | gönderim anahtarı. Sistem çerçevelerinin çağırdığı seçiciler (protokol / üst sınıf yöntemleri) sözleşmeyle sabit; yalnız uygulamanın kendi içinde kullanılanlar tutarlı biçimde değiştirilebilir |
| Tip kodlaması dizgisi | `method_t::getCachedDescription`; olağan gönderimde okunmuyor (yönlendirme / yansıtma okur) | serbest metin (olağan akışta) |
| Sınıf adı | `addNamedClass` (ada göre kayıt; çakışmada `inform_duplicate`), ada göre sınıf arama | kısmen zorunlu (nib, `NSClassFromString`, çakışma) |
| Kategori adı | yalnız tanılama çıktıları (`attachCategories` vb.) | serbest metin |

**C++ (Itanium ABI)** (llvm-project `libcxxabi/src/private_typeinfo.cpp`, `libcxx/include/typeinfo`)

| Alan | Okuyan yer | Sınıf |
|---|---|---|
| vtable işlev yuvaları | sanal çağrı | zorunlu |
| vtable[−2] tepeye uzaklık, vtable[−1] typeinfo göstericisi | `__dynamic_cast`; istisna yakalama | zorunlu (`dynamic_cast` / istisna kullanılıyorsa) |
| typeinfo'nun kendi vtable bağı, taban listesi (`__base_type`, `__base_info`) | `__dynamic_cast` taban araması, `can_catch` | zorunlu (aynı koşulla) |
| **Sınıf adı dizgisi** | `type_info` eşitliği: Apple arm64'te iki ad da "tekil" ise yalnız gösterici karşılaştırılır; ikisi de "tekil değil" (ad göstericisinin en üst biti) ise `strcmp` | çoğunlukla serbest metin (Ollama arm64'te 19 adın 15'i "tekil değil" işaretli: bunlarda içerik karşılaştırılır) |

**Swift** (swiftlang/swift `Metadata.h`, `stdlib/public/runtime/MetadataLookup.cpp`)

| Alan | Okuyan yer | Sınıf |
|---|---|---|
| Betimleyiciler arası göreli göstericiler, erişim fonksiyonu, vtable / tanık uygulama göstericileri | üst veri kurulumu, sanal çağrı, protokol çağrısı | zorunlu |
| **Tip adı dizgisi** | `_contextDescriptorMatchesMangling`: tip ada göre arandığında dizgi karşılaştırılır; ama `_findContextDescriptor` önce simgesel başvuruyu (doğrudan gösterici) kullanır | çoğunlukla serbest metin (ada göre aramada zorunlu) |
| Alan adları (`__swift5_reflstr`) | yansıtma (`Mirror`) | serbest metin |

### 6.2 Önerilen tutarlılık denetimi ve deney

Tasarım (`scripts/arge/ustveri/go_tip.py`, `go_tutarlilik.py`): adı, çalışma için zorunlu ikinci bir yapıyla karşılaştır.
- T1: `itab.Fun[i]`'nin gösterdiği fonksiyonun adı arayüzün i. yöntem adıyla bitmeli.
- T2: somut tipin yöntem tablosundaki `Tfn` / `Ifn` adresindeki fonksiyonun adı yöntem adıyla bitmeli; paket öneki tipin paket yolu olmalı (T2p).
- T3: kaynak dosya dizini ↔ paket yolu. T4: derleme birimi çoğunluk paketi. T5: `funcID` çapası. Yapısal: K1–K9 (§2.3).

Komutlar: `python scripts/arge/ustveri/go_tutarlilik.py $V/hedef/<ad> --cikti $V/dusman/<ad>_taban.json`; `python scripts/arge/ustveri/dusman_deney.py $V/hedef/<ad> --cikti-dizini $V/dusman`. Kurallar `gh` üstünde kuruldu ve donduruldu; `limactl` sınama birimi. Ön kayıt `DEFTER.md` §7.3 (koşudan önce).

| İkili | Tür | Bozulan | İkinci kaynaklı | Güçlü denetim yakaladı | İkinci kaynaklıda | İkinci kaynaksızda | Yalnız T4 | K4 | Hiçbiri | Bozulmayanda yeni işaret |
|---|---|---|---|---|---|---|---|---|---|---|
| gh | A_son_bilesen | 200 | 66 | 66 (%33,0 (%26,9–%39,8)) | 66 | 0 | 0 | 0 | 134 | 0 |
| gh | B_paketler_arasi_takas | 200 | 68 | 181 (%90,5 (%85,6–%93,8)) | 68 | 113 | 18 | 0 | 1 | 0 |
| gh | C_paket_ici_takas | 200 | 73 | 73 (%36,5 (%30,1–%43,4)) | 73 | 0 | 0 | 0 | 127 | 0 |
| gh | D_tutarli_sahtecilik | 86 | 71 | 0 (%0,0 (%0,0–%4,3)) | 0 | 0 | 0 | 0 | 86 | 0 |
| gh | E_yapisal_takas | 200 | 76 | 65 (%32,5 (%26,4–%39,3)) | 65 | 0 | 0 | 160 | 18 | 0 |
| limactl | A_son_bilesen | 200 | 84 | 84 (%42,0 (%35,4–%48,9)) | 84 | 0 | 0 | 0 | 116 | 0 |
| limactl | B_paketler_arasi_takas | 200 | 92 | 192 (%96,0 (%92,3–%98,0)) | 92 | 100 | 8 | 0 | 0 | 0 |
| limactl | C_paket_ici_takas | 200 | 82 | 82 (%41,0 (%34,4–%47,9)) | 82 | 0 | 0 | 0 | 118 | 0 |
| limactl | D_tutarli_sahtecilik | 451 | 344 | 0 (%0,0 (%0,0–%0,8)) | 0 | 0 | 0 | 0 | 451 | 0 |
| limactl | E_yapisal_takas | 200 | 87 | 67 (%33,5 (%27,3–%40,3)) | 67 | 0 | 1 | 166 | 20 | 0 |

Bozulmamış ikilide denetimler (taban):

| İkili | Fonksiyon | T1 uyan / bakılan | T2 uyan / bakılan | T2 paket uyan / bakılan | T3 uyan / bakılan | T4 uyan / bakılan | T5 | İkinci kaynaklı fonksiyon |
|---|---|---|---|---|---|---|---|---|
| gh | 40 384 | 6 333 / 6 333 | 26 258 / 26 258 | 26 236 / 26 238 | 31 330 / 31 483 | 38 356 / 39 697 | 19 / 19 | 13 188 (%32,7 (%32,2–%33,1)) |
| limactl | 40 321 | 8 426 / 8 426 | 31 105 / 31 105 | 30 891 / 31 057 | 30 167 / 32 532 | 38 372 / 39 647 | 20 / 20 | 15 608 (%38,7 (%38,2–%39,2)) |

Okuma:
1. **A (adın son bileşenini değiştir):** yalnız ikinci kaynağı olan fonksiyonlar yakalanıyor (66 / 66, 84 / 84); ikinci kaynağı olmayanlarda **0 / 134 ve 0 / 116**. İkinci kaynağı olan fonksiyon oranı `gh` %32,7, `limactl` %38,7.
2. **B (paketler arası ad takası):** %90,5 ve %96,0; çoğunu T3 yakalıyor. Ama T3'ün bozulmamış ikilideki yanlış alarmı derleme düzenine bağlı: `gh` 153 / 31 483, `limactl` 2 365 / 32 532 (mutlak dosya yolları).
3. **C (aynı paket içinde ad takası):** yine yalnız ikinci kaynağı olanlar (73, 82); olmayanlarda 0 / 127, 0 / 118.
4. **D (tip verisi + `pclntab` birlikte, tutarlı):** **0 / 86 ve 0 / 451.** Bu, kaynak düzeyinde ad karıştırıcıların (ör. garble) ürettiği durumun ikili düzeyindeki karşılığı; denetimle ayırt edilemez.
5. **E (komşu `_func` kayıtlarını takas et):** K4 %80 ve %83 yakalıyor; ön kayıttaki ≥ %95 **tutmadı**. Komşu fonksiyonların boyu aynıysa `pcsp` kapsaması farkı görmüyor. Üst veriyi fonksiyonun içeriğine bağlayan denetim yok.
6. Bozulmayan fonksiyonlarda yeni güçlü işaret 0 (10 koşuda).

**Hüküm (ölçülen):** Go fonksiyon adı, derleyicinin yazdığı hâliyle doğrudur ama **doğrulanamaz**: tutarlılık denetimi ucuz tahrifatın bir kısmını yakalar, ad metninin gerçekliğini kanıtlamaz. Hat metnindeki koşul gerçekleşti: üst veri adı "kesin" değil, **"üst veriden"** etiketiyle yazılmalı; ikinci kaynağı olan adlar ayrıca işaretlenebilir ("üst veriden, çift kaynaklı"). Etiket ve güven kuralı önerisi PLAN P-ÜV6'da; kararı ana oturum verir.

ObjC, Swift ve C++ için bozma deneyi yapılmadı (alan tabloları kaynak okumasına dayanıyor): **yön gösterici**.

## 7. Bütçe (kalem 7)

Komut: `python scripts/arge/ustveri/butce.py --cikti $V/butce.json <ad=yol> …` (tam komut `DEFTER.md` §8). Nüfus `LC_FUNCTION_STARTS`; `gh`'te bu tablo olmadığı için `pclntab` girişleri (o yüzden `gh` satırı tanım gereği %100).

| Hedef | Fonksiyon | Go adı | ObjC yöntemi | Swift erişim | **Üst veriden kesin** | Tip + yuva (ad yok) | Sembol tablosunda (soyulmuş hâliyle) | Kesin ∪ sembol | **Kalan** | Kalanın yuvalısı |
|---|---|---|---|---|---|---|---|---|---|---|
| Ollama.arm64 | 12 952 | 10 600 | 151 | 0 | 10 751 (%83,0 (%82,3–%83,6)) | 68 | 528 | 11 276 | 1 676 (%12,9 (%12,4–%13,5)) | 68 |
| Ollama.x86_64 | 13 027 | 10 675 | 151 | 0 | 10 826 (%83,1 (%82,5–%83,7)) | 68 | 528 | 11 351 | 1 676 (%12,9 (%12,3–%13,5)) | 68 |
| ollama-cli.arm64 | 27 293 | 25 163 | 0 | 0 | 25 163 (%92,2 (%91,9–%92,5)) | 0 | 601 | 25 761 | 1 532 (%5,6 (%5,3–%5,9)) | 0 |
| gh | 40 383 | 40 383 | 0 | 0 | 40 383 (%100,000 (%99,990–%100,000)) | 0 | 0 | 40 383 | 0 (%0,000 (%0,000–%0,009)) | 0 |
| limactl | 40 917 | 40 320 | 102 | 0 | 40 422 (%98,8 (%98,7–%98,9)) | 0 | 411 | 40 830 | 87 (%0,2 (%0,2–%0,3)) | 0 |
| colima | 13 121 | 13 081 | 0 | 0 | 13 081 (%99,7 (%99,6–%99,8)) | 0 | 36 | 13 114 | 7 (%0,053 (%0,026–%0,110)) | 0 |
| docker-brew | 35 776 | 35 748 | 0 | 0 | 35 748 (%99,9 (%99,9–%99,9)) | 0 | 27 | 35 772 | 4 (%0,011 (%0,004–%0,029)) | 0 |
| arduino-cli | 29 738 | 29 710 | 0 | 0 | 29 710 (%99,9 (%99,9–%99,9)) | 0 | 27 | 29 734 | 4 (%0,013 (%0,005–%0,035)) | 0 |
| iTerm2.arm64 | 109 608 | 0 | 41 305 | 3 659 | 44 964 (%41,0 (%40,7–%41,3)) | 3 128 | 108 776 | 108 776 | 832 (%0,8 (%0,7–%0,8)) | 0 |
| Rectangle.arm64 | 2 401 | 0 | 450 | 186 | 636 (%26,5 (%24,8–%28,3)) | 220 | 0 | 636 | 1 765 (%73,5 (%71,7–%75,2)) | 220 |
| llama-server.arm64 | 17 211 | 0 | 0 | 0 | 0 (%0,000 (%0,000–%0,022)) | 7 053 | 17 210 | 17 210 | 1 (%0,006 (%0,001–%0,033)) | 0 |
| btop | 1 952 | 0 | 0 | 0 | 0 (%0,0 (%0,0–%0,2)) | 84 | 193 | 193 | 1 759 (%90,1 (%88,7–%91,4)) | 82 |
| htop | 605 | 0 | 0 | 0 | 0 (%0,0 (%0,0–%0,6)) | 0 | 0 | 0 | 605 (%100,0 (%99,4–%100,0)) | 0 |
| tmux | 2 572 | 0 | 0 | 0 | 0 (%0,0 (%0,0–%0,1)) | 0 | 0 | 0 | 2 572 (%100,0 (%99,9–%100,0)) | 0 |
| gsort | 357 | 0 | 0 | 0 | 0 (%0,0 (%0,0–%1,1)) | 0 | 0 | 0 | 357 (%100,0 (%98,9–%100,0)) | 0 |
| xz | 131 | 0 | 0 | 0 | 0 (%0,0 (%0,0–%2,8)) | 0 | 0 | 0 | 131 (%100,0 (%97,2–%100,0)) | 0 |

Go ikililerinde Go dışı kod (C / C++ / ObjC) ve Go adlarının paket sınıfı:

| Hedef | Go dışı fonksiyon | ObjC'den kesin | Sembollü | Kalan | Go: kendi | Go: üçüncü taraf | Go: standart + çalışma zamanı | Go: derleyici + paketsiz |
|---|---|---|---|---|---|---|---|---|
| Ollama.arm64 | 2 352 | 151 | 525 | 1 676 | 1 257 | 594 | 8 237 | 512 |
| Ollama.x86_64 | 2 352 | 151 | 525 | 1 676 | 1 257 | 596 | 8 271 | 551 |
| ollama-cli.arm64 | 2 130 | 0 | 598 | 1 532 | 6 026 | 6 133 | 12 062 | 942 |
| gh | 0 | 0 | 0 | 0 | 4 385 | 22 270 | 13 042 | 686 |
| limactl | 597 | 102 | 408 | 87 | 1 927 | 24 699 | 13 021 | 673 |
| colima | 40 | 0 | 33 | 7 | 863 | 1 520 | 10 225 | 473 |
| docker-brew | 28 | 0 | 24 | 4 | 2 549 | 20 265 | 11 970 | 964 |
| arduino-cli | 28 | 0 | 24 | 4 | 3 793 | 13 500 | 11 987 | 430 |

Sütunların karşılığı (hat metnindeki tablo):
- **Toplam fonksiyon:** `Fonksiyon`.
- **Üst veriden kesin adlanabilen:** `Üst veriden kesin`.
- **Ghidra'nın zaten adlandırdığı:** **açık ölçüm.** Gösteri koşusu 12:16'da bitmemişti; öbür hedeflerde Ghidra koşulmadı. Alt sınır olarak "sembol tablosunda" sütunu verildi (Ghidra sembol tablosundaki adları alır). Ghidra'nın Go desteği 1.25'te bitiyor (§2.1 madde 5); ObjC çözümleyicisinin Ollama'daki çıktısı bilinmiyor.
- **Karadul'un bugün adlandırdığı (üst veri kanallarından):** Go kanalı girdisi 0–2 fonksiyon (§2.4); RTTI 0 (§4); ObjC / Swift okuyucusu yok; Mach-O `main` 0 / 8 (§5). Ürün koşusundaki gerçek sayı ölçülmedi (Ghidra koşmadan ölçülemez).
- **Kalan:** `Kalan`.

**Aykırı öncül 1 için hüküm:**
- Go taşıyan gerçek uygulamalarda fonksiyonların %83,0–%100'ünün tam adı ikilide yazılı ve ürün bunu bugün okumuyor. Bu ikililerde hesaplamayla ad üretmek yerine önce okumak gerekir; geliştirme seti (düz C) bu değeri hiç göstermiyor.
- Ama adların çoğu kitaplık adı: Go adlarının %72,3–%93,6'sı standart kitaplık, çalışma zamanı ya da üçüncü taraf; programın kendi paketleri %4,8–%23,9 (Ollama uygulaması: 1 257 fonksiyon).
- Go dışı kısımda (Ollama: 2 352 fonksiyon; C / C++ / ObjC) üst veri yalnız 151 ObjC yöntemine ad veriyor; 1 676 fonksiyon (%71,3) adsız kalıyor. Swift (%26,5), C++ (0) ve C (0) için öncül tutmuyor: orada ad yine hesaplamadan ya da kimlik eşlemesinden gelmek zorunda.

## 8. Açık ölçümler ve sınırlar

1. Ghidra'nın Ollama'da verdiği adlar (Go, ObjC) ve üst veri adlarıyla farkı: gösteri koşusu bitince `ws/` çıktısından sayılacak (PLAN P-ÜV8 kalem 6).
2. Go ≥ 1.26'da ad ↔ adres bire bir doğrulaması (sembollü ikili yok).
3. ELF ve PE'de Go `pclntab` / RTTI: bu tur yalnız Mach-O okudu.
4. ObjC / Swift / C++ için bozma deneyi yok.
5. Kanalların ürün koşusundaki etkisi (Ghidra'nın o adreste fonksiyon açıp açmadığı; `gh` gibi başlangıç tablosu olmayan ikililerde Ghidra'nın kaç fonksiyon bulduğu) ölçülmedi.
6. Satır içi gömülmüş fonksiyon adları (`FUNCDATA_InlTree`) okunmadı.
7. Model hükmü ya da insan değerlendirmesi kullanılmadı; bütün doğrulayıcılar sembol tablosu ya da yapısal denetim.

## 9. Dosyalar

| Ne | Yol |
|---|---|
| Mach-O okuyucu (dilim, bölüm, sembol, zincirli düzeltme, fonksiyon başlangıçları) | `scripts/arge/ustveri/macho.py` |
| Go `pclntab` / `moduledata` / `buildinfo` okuyucu; sayım ve denetim | `scripts/arge/ustveri/go_pclntab.py`, `go_say.py` |
| Go tip verisi (itab, yöntem tablosu); tutarlılık denetimi; bozma deneyi | `scripts/arge/ustveri/go_tip.py`, `go_tutarlilik.py`, `dusman_deney.py` |
| ObjC; Swift; Swift ad doğrulama | `scripts/arge/ustveri/objc_meta.py`, `swift_meta.py`, `swift_ad_dogrula.py` |
| C++ RTTI taraması | `scripts/arge/ustveri/cpp_rtti_tara.py` |
| Mach-O `main` | `scripts/arge/ustveri/macho_main.py` |
| Ürün kodunu çağıran ölçümler | `scripts/arge/ustveri/karadul_go_olc.py`, `karadul_rtti_olc.py` |
| Envanter, bütçe, tablolar | `scripts/arge/ustveri/envanter.py`, `butce.py`, `tablo.py` |
| Hedef kopyaları | `$V/hedef/` |
| Çıktılar | `$V/envanter.json`, `$V/go/`, `$V/karadul_go/`, `$V/objc/`, `$V/swift/`, `$V/rtti/`, `$V/main/`, `$V/dusman/`, `$V/butce.json`, `$V/tablolar.md` |
