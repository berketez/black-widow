# ÜST VERİ hattı — defter (tur 1, 2026-11-19)

Yarıda kalırsa sonraki ajan buradan sürdürür. Sayılar betik çıktısıdır; betik yolu ve komutu her kayıtta yazılı.

- Hat metni: `docs/arge/2026-11-19_mythos/HAT_USTVERI.md`
- Betikler: `scripts/arge/ustveri/`
- Veri: `~/karadul_olcum/runs/arge-2026-11-19/ustveri/` (aşağıda `$V`)
- Komutların hepsi depo kökünden, `PYTHONDONTWRITEBYTECODE=1 python scripts/arge/ustveri/<betik>.py …` biçiminde.

## 0. Başlangıç (11:30)

- Okunanlar: `ORTAK_BRIF.md`, `KARARLAR.md`, `HAT_USTVERI.md`, `YON.md`, soru listesi A3 / I2 / I4, `2026-11-18_onarim/P13b.md`.
- Gösteri koşusu durumu (11:30): `~/karadul_olcum/runs/gosteri-2026-11-19/ollama/` içinde `CIKIS` yok (koşu 2 sürüyor; deneme 1 "Objective-C Message Analyzer" 22+ dk döndüğü için kesilmiş, `gosteri.yaml` notu). `ws/` ve `out/` okunmadı.
- Hedef kopyaları `$V/hedef/` altına alındı (yerinde değişiklik yok, çalıştırma izni kaldırıldı): `Ollama` (evrensel; sha256 `233793c7…` = `girdi/sha256`), `Ollama.arm64`, `Ollama.x86_64` (`/usr/bin/lipo -thin`), `gh` (2.105.0), `limactl` (2.3.0).
- **Araç tuzağı:** PATH'te `otool`, `nm`, `lipo`, `strings` conda sürümleri önde (`/opt/anaconda3/bin`). Bu hatta yalnız `/usr/bin/…` sürümleri ve kendi ayrıştırıcım kullanılıyor.
- `go` derleyicisi makinede yok: Go ikilisi derlenemez; doğrulayıcı olarak sembol tablosu duran hazır Go ikilileri aranacak.

## 1. Bölme kararı (sayılara bakmadan önce)

Bu hat GT'ye bakarak ad kuralı kurmuyor; üst veri alanlarını biçim belgesine göre okuyor. Yine de iki yerde aşırı uyum riski var, bölme şöyle:

- **Go `pclntab` okuyucusu:** biçim kaynağı Go kaynak ağacı (`src/internal/abi/symtab.go`, `src/runtime/symtab.go`, `src/debug/gosym/pclntab.go`). Okuyucu `gh` üstünde geliştirilir (keşif); `limactl`, Ollama arm64 / x86_64 ve makinede bulunacak öbür Go ikilileri sınama birimidir (okuyucu dondurulduktan sonra sayılır).
- **Mach-O `main` (I2):** `LC_MAIN` kuralı tek satırlık bir biçim kuralı (GT'ye bakılarak ayarlanacak parametresi yok). Geliştirme setinin Mac ikililerinin tamamı sınama birimi; coreutils (Homebrew) tek birim sayılır, birim başına ayrıca raporlanır.
- **Düşman girdi denetimi:** denetim kuralları `gh` kopyasında tasarlanır; bozma deneyi `gh` (keşif) ve `limactl` (sınama) kopyalarında ayrı ayrı koşulur. Bozma türleri deneyden önce §6'da listelenir.

## 2. Go `pclntab` (kalem 2) — 11:31–11:45

**Biçim doğrulaması (ezberden değil).** Kaynak: Go kaynak ağacı, `release-branch.go1.26` ve `release-branch.go1.27` (github.com/golang/go ham dosyaları, 2026-11-19): `src/runtime/symtab.go` (`pcHeader`, `moduledata`, `functab`, `findfuncbucket`, `moduledataverify1`, `pcvalue` / `step`), `src/runtime/runtime2.go` (`_func`), `src/internal/abi/symtab.go` (imza sabitleri, `FuncID`), `src/debug/buildinfo/buildinfo.go`.
- **Go 1.26 değişikliği:** `pcHeader`'ın eski `textStart` alanı artık `_ uintptr` (kaynaktaki not: yeniden konumlama gerektirdiği için bırakıldı; `moduledata.text` kullanılır). İkilide doğrulandı: Go 1.26.0 / 1.26.4 / 1.27.3 / 1.27.4 ikililerinin hepsinde başlığın 24. baytındaki alan `0`; Go 1.23.8 / 1.24.4 ikililerinde `__text` içindeki gerçek adres. `textStart`'a güvenen her okuyucu 1.26+'da bütün adresleri yanlış hesaplar ya da pes eder (Ghidra 12.1.2'nin Ollama'daki "Untested Go version [1.26.0]" uyarısının bağlamı).
- **Go 1.27 değişikliği:** `moduledata`'ya `typedesclen`, `itaboffset`, `itabsize` eklendi; Mach-O'da `__typelink` / `__itablink` bölümleri yok, yerine `__go_type` / `__go_func` var (gh, limactl, arduino-cli, docker-brew). Tip verisini bölüm adından arayan kod 1.27'de bulamaz.
- `FuncID` numaralandırması sürüme bağlı: 1.24'te sarmalayıcı kimliği 22, 1.26+'da 23 (araya `runCleanups` girdi). Sabit tabloyla okuyan kod eski sürümde yanlış etiketler (ilk koşuda `docker-cli`'de 6 443 "uymayan" bunu gösterdi; denetim sürümden bağımsız değişmeze çevrildi).

**Okuyucu.** `scripts/arge/ustveri/go_pclntab.py` (kitaplık) + `go_say.py` (sayım, denetim). `gh` üstünde geliştirildi (keşif); başlık ve tablo çözümü `gh`'ten sonra **değişmedi**. Sınama birimlerinde koşunca üç ölçüm denetimi inceltildi (okuyucu değil, denetim ölçütü; kayıt için):
1. K4 (pcsp kapsaması): amd64'te fonksiyonlar 32'ye hizalı, eşik sabit 16 yerine "giriş adreslerinin en büyük ortak böleni" yapıldı.
2. K7 (`bl` hedefleri): Go ≤ 1.25 arm64'te `runtime.duffzero` / `runtime.duffcopy` gövdesinin ortasına çağrı olağan (docker-cli 6 413, docker-compose 21 159; hepsi bu iki fonksiyonda). Ayrı sayaç.
3. K8 (`funcID`): sürümden bağımsız değişmez + 1.26 / 1.27 tablosu.
4. Sembol tablosu karşılaştırmasına iki yazım kuralı eklendi: sembolde `.abi0` eki; tip adındaki orta nokta (`·`) sembolde nokta.

**Komut (hedef başına):** `PYTHONDONTWRITEBYTECODE=1 python scripts/arge/ustveri/go_say.py $V/hedef/<ad> --cikti $V/go/<ad>.json --liste $V/go/<ad>.tsv`

**Hedefler (11 dilim, 6 Go sürümü):** gh 1.27.4, limactl 1.27.3, Ollama arm64 / x86_64 1.26.0, ollama-cli arm64 / x86_64 1.26.0 (aynı uygulama paketinin `Resources/ollama` ikilisi; MIT), colima 1.26.4 (MIT), docker-brew 1.27.4 (Homebrew `docker`; Apache-2.0), arduino-cli 1.27.3 (GPL-3.0), docker-cli 1.24.4 ve docker-compose 1.23.8.
- **Kaynak notu:** `docker-cli` ve `docker-compose` kopyaları `/Applications/Docker.app/Contents/Resources/` altından alındı. Docker Desktop kapalı kaynak bir pakettir; bu iki ikili ise açık kaynak projelerin derlemesi (`__go_buildinfo` ana paket yolu `github.com/docker/cli/cmd/docker` ve `github.com/docker/compose/v2/cmd`; ikisi de Apache-2.0). Makinede **sembol tablosu soyulmamış** tek Go ikilileri bunlar (43 498 ve 111 847 sembol); yalnız "ad ↔ adres" doğrulayıcısı olarak kullanıldı. Paketin kapalı kaynak parçalarına (`compose-bridge` dahil) dokunulmadı. Berke'ye bildirilecek (BERKE.md).

**Sonuç (özet; tablo BULGULAR.md'de):**
- Okuyucu 11 dilimin 11'inde çalıştı. K1 (artan), K2 (`__text` ve `moduledata.text…etext` içinde), K5 (`findfunctab` alt kovaları), K9 (`minpc` / `maxpc`) ihlali 0.
- **Sembol tablosu doğrulaması:** docker-cli 35 049 girişin 35 048'inde, docker-compose 90 078 girişin 90 077'sinde `pclntab` adı = sembol adı (yazım kuralları dahil); kalan 1'er giriş adsız `runtime.text` başlangıcı. Sembolsüz ikililerde bağımsız yapısal doğrulayıcı: `LC_FUNCTION_STARTS` (bu tablonun olduğu 9 dilimde `pclntab` girişlerinin hepsi fonksiyon başlangıcı; Go aralığında `pclntab`'da olmayan başlangıç yalnız docker-compose'da 126, hepsi `duffzero+N` / `duffcopy+N` etiketleri) ve `bl` hedefleri (arm64 9 dilimde Go aralığına düşen bütün doğrudan çağrılar ya bir girişe ya Duff gövdesine gidiyor; başka gövde içi hedef 0).
- **Neden olmadı / dikkat:** Go ≥ 1.26 için sembollü doğrulayıcı makinede yok (1.23 / 1.24 var). 1.26 / 1.27'de adların doğruluğu yapısal denetimlerle ve `funcID` çapalarıyla (19–21 fonksiyon) destekli; bire bir ad karşılaştırması için sembollü derleme gerek (indirme listesi PLAN'da).

**Karadul'un var olan Go kodu** (`scripts/arge/ustveri/karadul_go_olc.py`; çıktılar `$V/karadul_go/`):
- `go` aracı makinede yok → `GoBinaryAnalyzer._extract_gopclntab` soyulmuş ikililerde `strings` + düzenli ifade yoluna düşüyor: gh'te 11 138 "ad", **adresli 0**, 8 010'u gerçek `pclntab` adı (40 295 ayrık adın %19,9'u), 3 128'i fonksiyon adı değil. Adres olmadığı için hiçbir fonksiyona ad bağlanamaz.
- K-4 Go kanalı (`_add_go_demangler`) `nm -P` sembollerini okuyor, `pclntab`'ı okumuyor: gh 0 / 40 384, limactl 2 / 40 321, Ollama arm64 2 / 10 601, ollama-cli 2 / 25 164, colima 2 / 13 082, arduino-cli 2 / 29 711, docker-brew 2 / 35 749. Sembollü docker-cli'de 32 405 / 35 049, docker-compose'da 82 103 / 90 078 (`is_go_symbol` gerçek Go fonksiyon adlarının bir kısmını reddediyor).
- Evrensel Ollama dosyasında tür `universal_binary`, dil `unknown` (`metadata.go_slice = true` yazılıyor ama Go çözümleyicisi evrensel dosyayı açmıyor: `core/target.py` yorumu).

## 3. Objective-C (kalem 3) — 11:45–11:52

- Biçim kaynağı: apple-oss-distributions/objc4 `runtime/objc-runtime-new.h` (2026-11-19): `method_t` küçük biçim (3 × int32 göreli; `name` seçici başvurusuna gösterir), `smallMethodListFlag` 0x80000000, `class_ro_t`, `category_t`, `protocol_t`. Zincirli düzeltmeler: SDK `<mach-o/fixup-chains.h>` (yerel dosya).
- Betik: `scripts/arge/ustveri/objc_meta.py` (+ `macho.py`). **Bölme:** keşif `terminal-notifier` (MIT, Homebrew; 32 yöntem, sembollü); sınama iTerm2 3.7.7 arm64 (GPL-2.0; **soyulmamış**, 815 811 sembol → GT), Ollama arm64 / x86_64, limactl, Rectangle 0.94 arm64 (MIT; soyulmuş). Okuyucu keşiften sonra değişmedi.
- Komut: `python scripts/arge/ustveri/objc_meta.py $V/hedef/<ad> --cikti $V/objc/<ad>.json --liste $V/objc/<ad>.tsv`
- Sonuç: iTerm2'de 41 305 yöntem kaydı, hepsi kod bölümünde ve `LC_FUNCTION_STARTS` başlangıcı; ObjC sembolü olan 33 611 IMP'in 33 611'inde üst veri adı = sembol adı (31 431 birebir, 2 180'i sembolde kategori adı yazımı farkıyla). Sembolsüz 7 694 IMP Swift sınıflarının `@objc` köprüleri (Swift sınıfında kayıt 7 420). Ollama arm64 151 yöntem / 12 952 fonksiyon; limactl 102 / 40 917; Rectangle 450 / 2 401.
- Not: yöntem listesi adı, çalışma zamanının gönderim anahtarıdır (seçici dizgisi); bkz. §6 alan tablosu.

## 4. Swift (kalem 3) — 11:52–11:56

- Biçim kaynağı: swiftlang/swift `include/swift/ABI/MetadataValues.h`, `Metadata.h`, `GenericContext.h` (2026-11-19). `docs/ABI/TypeMetadata.rst`'nin betimleyici bölümü "out of date" uyarılı; kullanılmadı.
- Betik: `scripts/arge/ustveri/swift_meta.py`. Keşif Rectangle (sembolsüz; yalnız akıl sağlığı: 186 tip, 186 erişim fonksiyonu, hepsi fonksiyon başlangıcı); sınama iTerm2 (GT). Okuyucu iTerm2'den sonra değiştirilmedi.
- iTerm2: 3 659 tip → 3 659 erişim fonksiyonu, hepsinin sembolü `…Ma` ile bitiyor (3 659 / 3 659); vtable betimleyicisi 12 258, bunların 9 868'inde uygulama göstericisi boş (derleyici doğrudan çağrıya çevirmiş), kodda 2 264 ayrık uygulama; tanık tablosu kod göstericisi 741, hepsi `…TW` sembollü.
- **Asıl bulgu:** Swift üst verisi fonksiyon ADI taşımıyor; tip adı + yuva sırası taşıyor. iTerm2'de Swift sembollü 60 771 kod adresinin üst veriden ulaşılanı 6 725; tam ad verilebilen yalnız erişim fonksiyonları (3 659; derleyici üretimi). "Mac'te ad sorunu çözülmüş" öncülü Swift için tutmuyor.

## 5. C++ RTTI (kalem 4) — 11:56–12:02

- Biçim kaynağı: Itanium C++ ABI (vtable ve RTTI yerleşimi), llvm-project `libcxxabi/src/private_typeinfo.h`; çalışma zamanının okuma yerleri §6'da.
- Betik: `scripts/arge/ustveri/cpp_rtti_tara.py` (sembolsüz tarama: typeinfo = ilk sözcüğü `__cxxabiv1` sınıf tip bilgisi vtable'ına içe aktarım bağı olan nesne). Keşif btop, iTerm2 arm64; sınama llama-server arm64 (Ollama paketinden, MIT; sembollü → GT), Ollama arm64 / x86_64.
- **Sınamada bulunan eksik (kayıt):** x86_64 dilimde 19 typeinfo'nun 15'i bulunamadı; neden: dışa açık (zayıf) typeinfo ve ad dizgisine başvurular yeniden konumlama değil **ada göre bağ** (zayıf sembol birleştirme). Tarayıcıya "bağ adı aynı ikilide tanımlıysa yerel adrese çevir" eklendi; sonra arm64 ve x86_64 dilimleri aynı sayıyı veriyor (19 typeinfo, 8 vtable, 68 işlev). llama-server sayıları 1 974 → 1 994 typeinfo, 1 297 → 1 317 vtable oldu.
- Sonuç: llama-server'da 1 994 / 1 994 typeinfo adı ve 1 317 / 1 317 vtable adı sembolle aynı; yuvadaki 7 053 sembollü işlevin 7 023'ünün sembolü sınıfın kendi adını, 9'unun taban sınıf adını taşıyor, 21'i başka (şablon yardımcıları; aynı kodun birleştirilmesi). Ollama arm64: 19 sınıf adı, 8 vtable, 68 işlev (12 952 fonksiyonda).
- **Karadul `cpp_rtti.py`** (`scripts/arge/ustveri/karadul_rtti_olc.py`; çıktı `$V/rtti/karadul_cpp_rtti.jsonl`): typeinfo ve vtable'ı `_ZTI` / `_ZTV` SEMBOLLERİNDEN buluyor. Soyulmuş Ollama arm64'te 2 "sınıf" (içe aktarılan semboller), vtable 0, yöntem 0; btop'ta 1 vtable / 4 yöntem (tarama: 36 vtable / 84 işlev). Sembollü llama-server'da 2 023 sınıf, 1 317 vtable. Yani bugünkü kod yalnız sembol tablosu durduğunda çalışıyor; o durumda adlar zaten sembolde.

## 6. Mach-O `main` (kalem 5, I2) — 12:02–12:07

- Betik: `scripts/arge/ustveri/macho_main.py` (`gt` ve `nufus` kipleri). Çıktı `$V/main/gt.json`, `$V/main/nufus_homebrew.json`, `$V/main/go_giris.txt`.
- GT'li 8 Mach-O (geliştirme seti: htop, tmux; P-S3b kabul seti: gettext, envsubst, idn2, gsort, gmktemp, xz): `LC_MAIN` giriş adresi = GT `_main` **8 / 8**; Ghidra'nın o adresteki adı `entry` 8 / 8; ürünün `main` verdiği ikili 0 / 8; decompile çıktısında `__libc_start_main` geçen dosya 0 / 8 (`_recover_main_from_entry` yalnız bu ELF / glibc kalıbını arıyor). htop'ta `entry` 4 baytlık thunk (GT `_main` da 4 bayt: doğrudan `CommandLine_run`'a atlıyor).
- Homebrew nüfusu (`/opt/homebrew/Cellar`, 1 188 çalıştırılabilir Mach-O; 3 dk 33 sn): `_main` sembolü olan 1 169'un 1 169'unda giriş = `_main`. `_main` sembolü olmayan 19'un 5'i Go.
- Go: dış bağlayıcılı (cgo) derlemelerde giriş `pclntab`'a göre `main` (çalışma zamanının C girişi; kullanıcının `main.main`'i değil), iç bağlayıcılı derlemelerde (`gh`, `docker-cli`) `_rt0_arm64_darwin`. Kural: `pclntab` varsa `pclntab` adı geçerlidir.
- **Aykırı öncül 3 tuttu:** iş kurtarma değil, `LC_MAIN` girişine `main` adını yazmak (ve gelenek kanallarının `entry`'yi `main` saymaları). Tek paket.

## 7. Düşman girdi (kalem 6, I4) — 12:07–

### 7.1 Çalışma zamanı adı nerede okuyor (kaynak, 2026-11-19)

- **Go** (`release-branch.go1.27`): `src/runtime/traceback.go` — fonksiyon adını okuyan her yer (`funcNamePiecesForPrint`, `printFuncName`, `showfuncinfo`, `isExportedRuntime`, `printcreatedby1`, `isSystemGoroutine`) yalnız yığın dökümünün ne basacağını belirliyor; yığın açma (`resolveInternal`, `next`) ad okumuyor, `funcID`, `pcsp`, `pcdata`, `funcdata`, `flag` okuyor. `src/runtime/symtab.go` `moduledataverify1`: imza, `minLC`, `ptrSize`, `ftab` sırası, `minpc` / `maxpc` denetleniyor; ad tablosu denetlenmiyor. `src/runtime/iface.go` `itabInit`: arayüz yöntemi ↔ somut tip yöntemi eşlemesi **tip verisindeki ad dizgisi** (ve tip) karşılaştırılarak yapılıyor; `itab.Fun[]` arayüz çağrısının hedefi.
- **Objective-C** (objc4 `objc-runtime-new.h`): yöntem listesi kaydı (seçici, tip kodlaması, IMP); küçük biçimde `name` seçici başvurusuna gösterir. Seçici dizgisi gönderim anahtarıdır.
- **C++** (llvm-project `libcxxabi/src/private_typeinfo.cpp`, `libcxx/include/typeinfo`): `__dynamic_cast` vtable'ın −2. (tepeye uzaklık) ve −1. (typeinfo) sözcüklerini ve taban listelerini okur; sanal işlev yuvalarını okumaz. Apple arm64'te `type_info` eşitliği: iki ad da "tekil" ise gösterici karşılaştırması, ikisi de "tekil değil" (ad göstericisinin en üst biti) ise `strcmp`.
- **Swift** (swiftlang/swift `Metadata.h`): betimleyiciler göreli göstericilerle bağlı; tip adı dizgisi `Name` alanında.

### 7.2 Go için tutarlılık denetimi (tasarım; `scripts/arge/ustveri/go_tip.py`, `go_tutarlilik.py`)

T1 itab yuvası ↔ arayüz yöntem adı; T2 somut tipin yöntem tablosu (`Tfn` / `Ifn`) ↔ yöntem adı (+ `T2p` paket yolu); T3 kaynak dosya dizini ↔ paket; T4 derleme birimi çoğunluk paketi; T5 `funcID` çapası; T6 biçim. Yapısal denetimler (K1–K9) `go_say.py`'de.

**Keşif (bozulmamış `gh`):** ilk koşuda T1 6 227 / 6 547, T2 25 924 / 26 258 çıktı. Yanlış alarmların üç kaynağı bulundu ve kural düzeltildi (hepsi `gh` üstünde, bozma deneyinden ÖNCE):
1. budanmış yöntemlerin yer tutucusu `runtime.unreachableMethod` (T1'den dışlandı);
2. tip parametreli alıcı (`(*T[string]).Get`): son bileşen köşeli ayraçlar atıldıktan sonra alınmalı;
3. paket yolundaki nokta sembolde `%2e` diye kaçırılıyor (`v0%2e0%2e2`).
Düzeltmeden sonra bozulmamış `gh`: T1 6 333 / 6 333, T2 26 258 / 26 258 (paket 26 236 / 26 238), T3 31 330 / 31 483, T4 38 356 / 39 697, T5 19 / 19. T4 gürültülü (yanlış alarm 1 341: `//go:linkname` ile başka pakette tanımlanan `runtime.*` ve otomatik sarmalayıcılar); ad kararına girmemeli, ayrı sayılır. İkinci kaynağı olan fonksiyon (T1 ∪ T2 ∪ T5 kapsamı): 13 188 / 40 384.
**Kurallar burada donduruldu.** Sınama birimi: `limactl`.

### 7.3 Bozma deneyi — ön kayıt (koşudan önce yazıldı)

Betik: `scripts/arge/ustveri/dusman_deney.py`; tohum 20261119; her türde 200 fonksiyon (D'de 20 yöntem adı); kopya üstünde, ikili çalıştırılmaz. Güçlü denetim = T1, T2, T2p, T3, T5, T6 (T4 ayrı sütun).

| Tür | Bozma | Beklenti (güçlü denetimle yakalanan) |
|---|---|---|
| A | Rastgele 200 fonksiyonun adının son bileşeni yerinde, aynı uzunlukta değiştirilir (harf kaydırma) | Yalnız ikinci kaynağı olan fonksiyonlar yakalanır: `gh`'te kapsam 13 188 / 40 384 ≈ %33 → 200'ün 50–80'i. İkinci kaynağı olmayan düz fonksiyonlarda **0**. |
| B | Farklı paketlerden 100 çiftin `nameOff` alanı takas edilir | ≥ %90 (T3 dosya ↔ paket) |
| C | Aynı paket ve aynı derleme biriminden 100 çiftin `nameOff` alanı takas edilir | Yalnız ikinci kaynağı olanlar: %25–45; düz fonksiyonlarda 0 |
| D | Tutarlı sahtecilik: 20 yöntem adı hem tip verisinde hem o adı taşıyan bütün `pclntab` adlarında aynı biçimde değiştirilir | **0** (denetim yakalayamaz; sınır) |
| E | Yapısal: komşu 100 fonksiyon çiftinin `_func` kayıtları takas edilir (adres aynı, üst veri komşununki) | ≥ %95 (K4: `pcsp` tablosu fonksiyon boyunu kaplamıyor) |

Tutmazsa silinmez; sonuç §7.4'e yazılır.

### 7.4 Bozma deneyi — sonuç (12:10–12:12)

Komut: `python scripts/arge/ustveri/dusman_deney.py $V/hedef/<ad> --cikti-dizini $V/dusman` (`<ad>` = `gh`, `limactl`). Çıktı `$V/dusman/<ad>.deney.json`; A türünün bozuk kopyası `$V/dusman/<ad>.A.bozuk` (salt okur, çalıştırma izni yok), yama listesi `<ad>.A.yamalar.json`.

| Tür | `gh` (keşif) | `limactl` (sınama) | Ön kayıt | Hüküm |
|---|---|---|---|---|
| A son bileşen | 66 / 200; ikinci kaynaklı 66 / 66, ikinci kaynaksız 0 / 134 | 84 / 200; 84 / 84, 0 / 116 | 50–80 (gh); ikinci kaynaksızda 0 | **tuttu** (limactl'de kapsam %38,7 olduğu için 84) |
| B paketler arası takas | 181 / 200 (+18 yalnız T4, 1 hiçbiri) | 192 / 200 (+8 yalnız T4) | ≥ %90 | **tuttu** (gh'te sınırda: %90,5) |
| C paket içi takas | 73 / 200; ikinci kaynaksız 0 / 127 | 82 / 200; 0 / 118 | %25–45; ikinci kaynaksızda 0 | **tuttu** |
| D tutarlı sahtecilik | 0 / 86 | 0 / 451 | 0 | **tuttu** (denetim yakalayamıyor) |
| E yapısal takas | K4 160 / 200; hiçbiri 18 | K4 166 / 200; hiçbiri 20 | ≥ %95 | **tutmadı** (%80, %83) |

- **E neden tutmadı:** komşu iki fonksiyonun boyu aynıysa (ya da `pcsp` tablosu hizalama dolgusu içinde bitiyorsa) K4 farkı görmüyor. Üst veri kaydını fonksiyonun **içeriğine** bağlayan denetim yok (ör. `pcsp` değerleri ↔ giriş bölümündeki yığın ayarlama komutları). Bu, kod çözme isteyen ayrı bir denetimdir; PLAN'da açık kalem.
- **Sınamada görülen:** T3 (dosya ↔ paket) yanlış alarmı derleme düzenine bağlı. `gh` (`-trimpath`) 153 / 31 483; `limactl` (`-trimpath` yok, mutlak yollar) 2 365 / 32 532. T3 eşiği tek ikiliden genellenemez; ad kararına tek başına girmemeli.
- **Sonuç (ölçülen):** Go fonksiyon adı serbest metin. Adın son bileşenini değiştiren saldırgan, ikinci kaynağı (itab / yöntem tablosu) olmayan fonksiyonlarda **hiç** yakalanmıyor (0 / 134, 0 / 116; 0 / 127, 0 / 118); tip verisini de birlikte değiştirirse hiçbir fonksiyonda yakalanmıyor (0 / 86, 0 / 451). Denetim ucuz tahrifatı (paket değiştirme, yöntem adı değiştirme) yakalıyor, ad metninin gerçekliğini kanıtlamıyor.

## 8. Bütçe (kalem 7) — 12:12–12:16

- Betik: `scripts/arge/ustveri/butce.py`; çıktı `$V/butce.json`. Tabloların hepsi `scripts/arge/ustveri/tablo.py` ile üretildi (`$V/tablolar.md`).
- Ollama arm64 (gösteri hedefi): 12 952 fonksiyon; üst veriden kesin ad 10 751 (Go 10 600 + ObjC 151); sembol tablosunda (soyulmuş hâliyle) 528; kalan 1 676; C++ vtable yuvası 68. Go adlarının 1 257'si programın kendi paketi, 594'ü üçüncü taraf, 8 237'si standart kitaplık + çalışma zamanı.
- Salt Go araçları %98,8–%100; Swift uygulaması Rectangle %26,5; düz C (htop, tmux, gsort, xz) 0.
- Paket sınıflamasında düzeltme (12:15): ana modülün `vendor/` dizini "kendi" sayılıyordu (docker-cli, docker-brew'da üçüncü taraf 0 görünüyordu); "üçüncü taraf"a alındı, Go sayımı ve bütçe yeniden koşuldu.
- **Ghidra'nın kendi adları:** gösteri koşusu 12:16'da hâlâ sürüyor (`CIKIS` yok) → Ollama için "Ghidra'nın zaten adlandırdığı" sütunu **açık ölçüm**. Kurulumdan okunan olgu: Ghidra 12.1.2'nin Go sürüm verisi `go1.15.0` … `go1.25.0` (`Ghidra/Features/Base/data/typeinfo/golang/`); 1.26 ve 1.27 yok. Bu hattaki 11 Go diliminin 9'u ≥ 1.26.

## 9. Swift tip adının tam eşitliği (ek ölçüm, 12:17)

- Betik: `scripts/arge/ustveri/swift_ad_dogrula.py` (`xcrun swift-demangle` yalnız sembol metnini çözer). Çıktı `$V/swift/iTerm2.arm64.ad.json`.
- iTerm2: 3 659 tipin 2 444'ünde üst veriden kurulan nitelikli ad = sembolün çözülmüş adı; 1 149'u adsız bağlam içinde (`private` / `fileprivate` tipler: sembolde `(Ad in _AYRAÇ)` biçimi; betik bu biçimi kurmuyor), 19'u uzantı bağlamında, 47'si farklı (içe aktarılan C tipleri: betimleyicide ikinci bir "ABI adı" var, okunmuyor: `Decimal` ↔ `NSDecimal`).
- Yani tip adında bile okuyucunun üç eksiği var (adsız bağlam ayracı, uzantı bağlamı, içe aktarım adı). PLAN P-ÜV3'ün kalemleri.

## 10. Başka hatlar için notlar

- **KİMLİK:** Sekiz Go hedefinde Go fonksiyonlarının %72,3–%93,6'sı standart kitaplık, çalışma zamanı ya da üçüncü taraf modül; programın kendi paketleri %4,8–%23,9 (`$V/butce.json` `go_sinif`). Üçüncü taraf modüllerin yolu ve sürümü `__go_buildinfo`'da yazılı (bağımlılık satırı: gh 153, limactl 95, arduino-cli 73, ollama-cli 51, Ollama uygulaması 18, colima 17; docker-brew 0: bağımlılıkları `vendor/` altında). Adı bozulmuş (garble) bir Go ikilisinde "aynı modülün aynı sürümünün başvuru derlemesi" kimlik eşlemesi için doğrudan veri: modül yolu + sürüm ikilinin içinde.
- **KİMLİK / ÖZ KOD:** `funcnametab`'da hiçbir girişe bağlı olmayan 3 100–7 100 ad var (satır içi gömülmüş fonksiyonlar). `FUNCDATA_InlTree` ile "bu fonksiyonun gövdesine şu fonksiyonlar gömüldü" bilgisi çıkarılabilir; bu turda sayım dışında okunmadı.
- **ÖLÇÜ:** Go / ObjC adları C tanımlayıcısı değil (`github.com/cli/cli/v2/api.(*Client).REST`, `-[AppDelegate applicationDidFinishLaunching:]`). `c_identifier` bunları alt çizgili biçime çeviriyor; "tam eşitlik" ölçüsü özgün ad üstünden tanımlanmalı (PLAN P-ÜV6, P-ÜV8).
- **OLGU:** Mach-O'da `entry` = `main` (8 / 8); olgu tablosunda `main` satırı Mac birimlerinde `entry` adıyla duruyor olabilir.

## 11. Yaratıcılık protokolü: uygulandı mı (tek satır)

1. **Denetlenebilir soru:** evet — her kalem bir sayım; doğrulayıcı sembol tablosu (Go 125 125, ObjC 33 643, C++ 2 028 ad) ya da yapısal denetim; model hükmü kullanılmadı.
2. **Uzlaşıyı kır:** evet — iki yasak cevap sayıyla çürütüldü (ad metni doğrulanamıyor: 0 / 134, 0 / 86; Swift %26,5, C++ ve C 0); üç aykırı öncül sınandı (1 dile göre, 2 ve 3 tuttu). Farklı model ailesi kullanılmadı (codex / alt ajan yasak).
3. **Tek hatta kal:** evet — KİMLİK, ÖZ KOD, ÖLÇÜ konularına girilmedi; gözlemler §10'da not.
4. **İnsan uzman:** hayır — bu tur uzman okuması yok; etiket kararı (PLAN P-ÜV6 kalem 5) ana oturuma, indirme / çalıştırma izni Berke'ye bırakıldı.

## 12. Tur sonu (12:32)

- Yazılanlar: `BULGULAR.md` (tablolar `scripts/arge/ustveri/tablo.py` çıktısından; şablon + tablo birleştirmesi oturum içinde yapıldı, şablon kalıcı değil — tabloların kaynağı `$V/tablolar.md`), `PLAN.md` (10 paket: P-ÜV0–9), `BERKE.md`.
- Sekiz kalemin durumu: 1 envanter tam; 2 Go tam (Go ≥ 1.26 için sembollü doğrulama açık: veri yok); 3 ObjC / Swift tam, **Ghidra farkı açık** (gösteri koşusunda `CIKIS` 12:31'de yoktu); 4 RTTI tam (yalnız zincirli düzeltmeli Mach-O); 5 `main` tam; 6 alan tabloları + Go deneyi tam (ObjC / Swift / C++ deneyi yok: yön gösterici); 7 bütçe tam, "Ghidra'nın zaten adlandırdığı" sütunu açık (alt sınır: sembol tablosu); 8 plan tam.
- Tutmayan ön kayıt: E türü (yapısal takas) ≥ %95 beklenirken %80 ve %83.
- Araç notu: depo kancası (`check-consistency.sh`) `TOHUM` adlı sabiti `tests/test_dogrulama_seti_kura.py`'deki ilgisiz sabitle çakışma saydı; deney sabiti `DUSMAN_DENEY_TOHUMU` olarak adlandırıldı (değer 20261119, ön kayıttaki tohum).
- Veri dizini 824 MB (`$V/hedef` kopyaları, iki bozuk kopya, fonksiyon listeleri). Silme yapılmadı; onay bekliyor.
- Ürün koduna, `tests/`'e, `scripts/measurement/`'e ve öbür hatların dizinlerine yazılmadı; git'te durum değiştiren komut çalıştırılmadı.
- **Sonraki ajan için ilk üç iş:** (a) gösteri koşusu bittiyse P-ÜV9 kalem 1 (Ghidra ↔ üst veri) — `ws/` salt okur; (b) Berke'nin Go derleyicisi kararı; (c) Dalga 0: P-ÜV0 + P-ÜV5.
- Kayıt: son sözdizimi denetiminde (`python -m py_compile scripts/arge/ustveri/*.py`) `scripts/arge/ustveri/__pycache__/` oluştu (16 `.pyc`; `.gitignore` kapsıyor). "Silme yok" kuralı gereği bırakıldı. Bu betikleri değiştiren ajan için uyarı: aynı saniyede ve aynı boyda yapılan düzenlemede eski `.pyc` geçerli sayılabilir (bilinen tuzak); düzenlemeden sonra dosyaya `touch` at ya da dizini onayla temizlet.
