# Karadul genel tarama raporu — 2026-11-18

- **Taranan sürüm:** 1.23.1, `main` HEAD e9d2d08 (çalışma ağacı temiz; tarama hiçbir ürün dosyasını değiştirmedi).
- **İsteyen:** Berke. Amaç: eksik, hatalı, yanlış ne varsa çıkarmak; onarımı sonra Opus ajanları bu rapora göre yapacak.
- **Durum:** tarama kapandı; onarım Berke "başla" deyince §5'teki sırayla başlar. Bu dizin commit'siz (K-7).
- **Yön kararı (Berke, 2026-11-18):** Karadul kapsamlı bir tersine mühendislik aracıdır; küçültülmeyecek. Yanlış iddia üreten katmanlar silinmeyecek ya da kalıcı kapatılmayacak, **sağlam biçimde oturtulacak** (onar + ölç). Yeni özellik eklenmeyecek; var olan düzeltilecek.
- **Bu dosya** özet, temalar, onarım planı ve kararları taşır. Her bulgunun tam metni (yer, kanıt, onarım kapsamı, nasıl sınanır) kulvar dosyalarındadır; bulgu kimliği (ör. `IMZA-05`) hangi dosyada olduğunu söyler. Tam liste: `DIZIN.md`.

## 0. Yöntem ve güven

| Kulvar | Dosya | Kim | Kapsam |
|---|---|---|---|
| MEK | `kulvar_MEK.md` | ana oturum | tam test takımı, CI dışı testler, pyflakes, mypy, erişim ve ayar haritaları, CLI duman testi, arayüzün tarayıcıda canlı denemesi, JS hattı denemesi, HEAD ile 14 gerçek ikili koşusu |
| BORU | `kulvar_BORU.md` | Opus ajanı | `stages.py`, `pipeline/`, çekirdek akış, toplu çalıştırma |
| AD | `kulvar_AD.md` | Opus ajanı | fonksiyon/değişken adlandırma hattı |
| TIP | `kulvar_TIP.md` | Opus ajanı | tip ve yapı kurtarma, akış, yorum, algoritma tanıma, hesaplama paketleri |
| IMZA | `kulvar_IMZA.md` | Opus ajanı | imza veritabanı, YARA, capa, anti-debug, paketleyici, ikili istihbarat |
| ARAYUZ | `kulvar_ARAYUZ.md` | Opus ajanı | çıktı ağacı, raporlar, web arayüzü, paketleme, belgeler |
| LM | `kulvar_LM.md` | Opus ajanı | KaradulLM kodu + vizyona göre boşluk analizi |
| MUH | `kulvar_MUH.md` | Opus ajanı | mühendislik (engineering) paketi, başvuru karşılaştırma |
| BICIM | `kulvar_BICIM.md` | Opus ajanı | hedef tanıma, JS/Java/.NET/Python/Go/Swift hatları |
| GHIDRA | `kulvar_GHIDRA.md` | Opus ajanı | Ghidra köprüsü, alt süreçler, dinamik analiz, CLI, ayar yükleme |

- Ajanlar salt okur çalıştı; her biri yalnız kendi bulgu dosyasını yazdı. Kanıtların çoğu gerçek çıktıdan: 119 ikilinin 1.22.1 koşusu (`~/karadul_olcum/runs/urun-yeni2-f30ac9a/`) ve bu oturumda HEAD ile yapılan 14 ikililik koşu (`~/karadul_olcum/runs/genel-tarama-2026-11-18/`).
- **Güven etiketleri:** her bulguda "kesin" (çalıştırılıp gösterildi), "yüksek" (kod baştan sona izlendi) ya da "şüphe" yazıyor. Ana oturum ağır bulguları ayrıca koddan ya da çıktıdan yeniden doğruladı; bunlar `DIZIN.md`'de **D** ile işaretli. İşaretsizler ajan bulgusudur: onarım ajanı işe başlamadan önce "Nasıl sınanır" satırındaki denemeyle kusuru kendi gözüyle görmelidir.
- Bilinen açık kusurlar taramadan önce `00_bilinenler.md`'de toplandı; her kulvar dosyasının sonunda bunların bugünkü durumu var.
- Bakılamayan yerler §8'de.

## 1. Özet

**Sayı:** 137 bulgu (11 kritik, 47 yüksek, 66 orta, 13 düşük) + 105 küçük kalem. 48'ini ana oturum koddan ya da gerçek çıktıdan ayrıca doğruladı; ağır bulguların HEAD'de (1.23.1) sürdüğü 14 ikililik yeni koşuyla gösterildi (`kulvar_MEK.md`).

**Sağlam olan:**
- Test takımı temiz: 8 289 geçti / 0 kaldı; CI dışı 153 testin 141'i geçti, 0 kaldı.
- Ana akış uçtan uca çalışıyor: 14 gerçek ikilinin 14'ü bitti.
- Ad hattının "kesin" etiketi ölçümle destekli (~%97); README durumu dürüst anlatıyor.
- Arayüz çalışıyor; XSS, yol geçişi, jeton/Host/Origin açığı bulunmadı.
- Mühendislik paketi başarım sorunu çıkarmıyor (toplam sürenin %5,4'ü); güven değerlerinde [0,1] dışı ya da NaN yok.

**En ağır on şey (sırayla):**
1. **Zararsız programlara sahte iddia yazılıyor.** 119 ikilinin 119'unda "CFD / roket yörüngesi / matris çözücü", 16'sında "VPN tüneli"; her ikilide "Bluetooth", "Encryption", "OpenGL"; `ls` "MPRESS ile paketli", `pwd` "anti-debug", `chmod` "ECC" (ARAYUZ-01 = MUH-03, IMZA-01, 02, 04, 05, TIP-08, 09). HEAD'de 14/14 ikilide sürüyor.
2. **Üç güvenlik açığı analistin makinesini hedef alabilir:** üretilen `build.gradle` / `.csproj` içine analiz edilen dosyadan kaçışsız metin (BICIM-04); hedef adındaki yazım hatasının çalışma dizinindeki Python dosyasını çalıştırması (BICIM-07); `--dynamic` ile başlatılan hedefin kancasız sürdürülüp analizden sonra öldürülmemesi ve çalıştırma kapısının YAML'da `"false"` dizgisiyle açılması (GHIDRA-11, GHIDRA-07).
3. **Koda yanlış ad ve tip yazılıyor, süzgeçlerin yanından:** parametrelere `0xffffffffffffffff`, `long`, `DAT_…` adları (MUH-01; 117 ikili), dizgiye `double` tipi (TIP-06, 11), iki tmux ikilisinde 236 seçenek adı fonksiyon adı olmuş (AD-01), gnulib'siz programlara gnulib adı 0,95 güvenle (AD-03, 07), glibc fonksiyonlarına "opencv / psycopg2" kitaplığı %98 güvenle (IMZA-07).
4. **`types.h` sahte yapılarla dolu:** 5 585 yapının koda bağlananı 3; ofsetler ölçeksiz, alanlar üst üste, her alana sabit "0,80 güven" (TIP-07, ARAYUZ-18).
5. **Raporlar verisini bulamıyor:** IOC bölümü hiç dolamaz, SARIF'te kripto bulgusu 0 (openssl'de 72 algoritma varken), temiz raporda paket/anti-debug bölümü yok, "taranamadı" ile "temiz" ayırt edilmiyor (ARAYUZ-02, 08, 17, IMZA-11, 15).
6. **"Başarılı" her zaman başarılı demek değil:** `analyze` çıkış kodu hep 0, `reconstruct` bayrağı fiilen hep doğru, Ghidra düşse de `static` başarılı, `batch` her hedefi başarılı sayıyor, fonksiyon sayacının yarısı içe aktarım taslağı (MEK-01, BORU-05, 07, GHIDRA-09, 10).
7. **"Hesaplama" kolları ve yedi ad kanalı sonuç üretemiyor:** CFG-iso, füzyon, MaxSMT, parametre yayılımı, capa, PDB/DWARF/Binary Ninja/TRex/Rust/Go, RTTI (T5). Nedenler yapısal ve artık biliniyor; hiçbiri "eşiği gevşet" ile çözülmez.
8. **Ağ sözü tutmuyor:** `.d.ts` indirmesi, `npx --yes @electron/asar` ve güncelleme sorgusu ağ bayrağına bakmıyor (MEK-03, 04, BICIM-06).
9. **Veri kökü karışıklığı ve BSim:** `--output-dir` verilen her koşu (arayüz ve ölçüm dahil) dış imza, FLIRT ve n-gram verisini göremiyor (GHIDRA-14); BSim deposu paralel koşuda kilitleniyor ve sembollü kopyaların adlarını sızdırıyor (GHIDRA-01, 02).
10. **Ölü ve çift kod:** `stages.py`'de ~2 750 ölü satır hâlâ düzeltme alıyor; "eski monolit" etiketli bir blok aslında etkin ve yapı kurtarmayı, CFG-iso'yu, füzyonu her ikilide ikinci kez koşturuyor (BORU-01, 12).

**Vizyona göre:** KaradulLM bugün hiçbir yere bağlı değil; üç okuma aracı var; denetim katmanı yazılmamış; 5/5 çekimserliğin nedeni bilgi eksikliği. Arayüzde sohbet, yan panel ve canlı ajan görünümünün hiçbir parçası yok. Yol ve ince ayar sorusunun cevabı §7'de.

**Plan:** 27 paket, 8 dalga, aynı anda en çok 4 ajan; önce ölçüm zemini (P00), sonra güvenlik ve yanıltan katmanlar (§5). Senden beklenen dokuz karar §6'da.

## 2. Analist bugün ne görüyor — yanıltan çıktının envanteri

Zararsız, herkesin bildiği programlar Karadul'dan geçince rapora ve koda yazılanlar. Hepsi gerçek çıktıdan; "HEAD" sütunu bugünkü 1.23.1 koşusunda da görüldüğünü gösterir.

| Program | Karadul'un yazdığı | Nerede görünüyor | Gerçek | Kök neden | HEAD |
|---|---|---|---|---|---|
| `cp`, `mv`, `mkdir`, `install`, `who` (+11 ikili) | "VPN Tunnel Setup Pipeline" | `reports/report.md`, `report.html` | VPN yok | yalnız libc ithal adlarından şablon doldurma (ARAYUZ-01, MUH-03) | — (bu ikililer HEAD'de koşulmadı) |
| 119 ikilinin 119'u | "Transient CFD Time-Stepping", "Rocket / Trajectory Simulation Loop", "Matrix Solve Pipeline" | aynı | `malloc → fflush → free` zinciri "matris çözücü" sayılıyor | ARAYUZ-01 (kök: `composition_analyzer.py`) | tmux, zstd'de görüldü |
| `true` dahil 119/119 | "Bluetooth", "Encryption", "OpenGL"; 107'sinde "SHA-256" | `static/intelligence_report.json` → HTML "Architecture Analysis" | `_ITM_deregisterTMCloneTable` içinde "BLE" ve "der" geçiyor; `GLIBC_` "OpenGL" sayılıyor | IMZA-01 | — |
| redis-cli, redis-check-rdb | "SIP (System Integrity)", "Kernel Extension" (risk: kernel) | aynı | `siphash`, `maskModuleConfigFlags` | IMZA-01 | — |
| `ls`, `sort`, `dir`, `vdir`, `dircolors`, htop, sqlite3, openssl, zstd (13 ikili) | "MPRESS_Packed" (paketli) | SARIF `KRDL003 warning` | `compress` sözcüğü | IMZA-05, ARAYUZ-17 | openssl, zstd'de görüldü |
| `tree` | "ASPack_Packed" | SARIF | 6 baytlık rastgele dizi | IMZA-05 | — |
| redis | "Delphi_Compiler" | SARIF | `tObject` | IMZA-05 | — |
| `pwd` ve 13 ikili daha (AArch64) | "Anti-Debug Findings [MED] — RDTSC_Timing" | `report.md`, SARIF | x86 işlem kodu `0F 31` ARM ikilide rastgele bayt olarak aranıyor | IMZA-02 | — |
| `chmod`, `mkfifo`, `md5sum` (30 ikili, 162 etiket) | "Galois field operations (ECC, AES-GF), asymmetric, confidence 55%" | ürün kodu: `out/src/**/*.c` başlık ve satır içi yorum | `mode`, `mode_t` içinde "mod" | TIP-09 | — |
| `tail` ve başkaları (6 etiket) | "Password-based key derivation (PBKDF2, scrypt)" | aynı | dizgide "iteration" | TIP-09 | — |
| redis, sqlite3, coreutils (4 291 etiket) | `@security Code injection/hooking mechanism`, "Handles authentication/credentials", "Handles sensitive key material" | ürün kodu başlığı | adın içinde "patch" (dis**patch**er), "token", "key" geçiyor | TIP-08 | — |
| `tree` ve 116 Debian ikilisi (2 955 eşleşme) | `__printf_chk` → kitaplık "opencv_python_headless" %98; `__assert_fail` → "cffi"; `fgetfilecon` → "psycopg2_binary" | `out/report.html` ad tablosu, `naming_map.json` | glibc / libselinux | IMZA-07 | — |
| redis `lolwutUnstableCommand` | `double sdsnewlen_ret_164;` | ürün kodu | sds dizgisi (`char *`); "8.0.2" dizgisi kayan nokta sanılıyor | TIP-06, TIP-11 | — |
| 116 ikili | `types.h`'de 5 585 `recovered_struct`, alan başına "confidence 0.80"; koda bağlanan 3 | `out/src/include/types.h` | ofset ölçeklenmiyor, ilgisiz `param_1`'ler tek yapıda | TIP-07, ARAYUZ-18 | — |
| tmux | 101 fonksiyona seçenek adı (`monitor-silence` → `monitor_silence`) güven 0,80 | `naming_map.json`, ürün kodu | fonksiyonun okuduğu seçeneğin adı, kendi adı değil | AD-01 | — |
| redis-cli, openssl, zstd, Mac tmux | gnulib adı (`full_write`, `close_stdout`) güven 0,95 | aynı | bu programlar gnulib içermiyor | AD-03, AD-07 | — |
| openssl | SARIF'te kripto bulgusu 0 | `report.sarif.json` | `algorithms.json`'da 72 algoritma var | ARAYUZ-17 | görüldü |
| hepsi | "Coverage N/A%", "Modules 0", "Deobf Steps 0" | üç rapor | alan hiç üretilmiyor | ARAYUZ-07 | — |

Buna karşılık **sessiz kalan** yerler (analist "yok" sanır, aslında "bakılmadı"):

| Ne | Durum | Bulgu |
|---|---|---|
| capa (yetenek tespiti) | öntanımlı açık görünüyor, hiçbir girdide çalışmıyor | IMZA-06 |
| Malware IOC bölümü | hiçbir koşuda dolamaz (yol ve şema) | ARAYUZ-02 |
| Temiz rapor (`out/report.html`) | paketleyici / anti-debug / IOC bölümü yok | ARAYUZ-08 |
| "Ad güvenilirliği düşük" SARIF uyarısı | hiçbir koşuda çıkmaz (ölçülmüş yanlış oran %29,7 iken) | ARAYUZ-17 |
| İmza veritabanı yokken | 9,2 M yerine 7 674 adla koşar, hiçbir çıktı söylemez | IMZA-11 |
| Tarama hata verince | "0 bulgu" yazılır, "taranamadı" denmez | IMZA-15 |
| Boru hattı başarısız olunca | `karadul analyze` çıkış kodu 0, hata satırı yok | MEK-01 |

## 3. Temalar

Her tema: ne oluyor, neden, hangi bulgular, onarımın yönü. Onarım yönü Berke'nin kararına göre yazıldı: katman kalır, kanıta bağlanır, ölçülür.

### T1. Kanıtsız hüküm veren tespit katmanları
- **Ne:** Beş ayrı katman tek ve zayıf bir kanıtla hüküm veriyor: alt dizgi eşleşmesi, sözcük sınırı yok, harf duyarsız, 1–2 baytlık desen, mimariye ve dosya biçimine bakılmıyor. Sonuç §2'deki tablo.
- **Bulgular:** IMZA-01 (ikili istihbarat), IMZA-02/03 (anti-debug), IMZA-04 (paketleyici), IMZA-05 (YARA kuralları), TIP-09 (yapısal algoritma etiketi), TIP-08 (`@security` etiketi), ARAYUZ-01 (bileşim şablonları), MUH kulvarı (mühendislik paketinin iddiaları).
- **Ortak kök:** kurallar yazılırken masum ikilide denenmemiş. `ab986da` sabit katmanında doğru kuralı kurmuştu (tam belirteç + en az iki ayırt edici kanıt); aynı kural öbür katmanlara uygulanmamış.
- **Onarım yönü:** her katman için aynı dört adım: (1) deseni kod/veri bölümüne, mimariye ve biçime bağla; (2) sözcük sınırı ve harf duyarlılığı; (3) tek kanıtla hüküm yok, en az iki bağımsız kanıt; (4) **masum ikili kapısı**: 119 ikililik geliştirme seti + macOS sistem ikilileri + birkaç masum PE üstünde yanlış pozitif sayısı ölçülür, sayı test olarak kilitlenir. Gerçek pozitif seti de (openssl, UPX'li örnek, x86 `rdtsc` içeren örnek) yanında durur ki sıkılaştırma doğruyu da düşürmesin.

### T2. Rapor ile veri arasındaki sözleşme kopuk
- **Ne:** Raporlayıcılar var olmayan dosyayı, yanlış aşamanın yanlış türdeki alanını ya da hiç üretilmeyen anahtarı okuyor. Dört ayrı HTML/Markdown/SARIF/JSON üreticisi aynı koşu için farklı şey söylüyor.
- **Bulgular:** ARAYUZ-02 (IOC), ARAYUZ-07 (dolmayan sayaçlar), ARAYUZ-08 (iki ayrı HTML üreticisi), ARAYUZ-17 (SARIF), IMZA-11 ve IMZA-15 ("taranamadı" ↔ "temiz"), BORU-10 (yayılım sayacı), AD-04 (sahte "çok kaynaklı uzlaşma" sayacı), B-B7 (doğrulanmamış tanıtım cümleleri `report_generator.py:438-464`).
- **Onarım yönü:** tek bir "rapor verisi" katmanı: her bölüm verisini adı belli bir yapıttan alır; yapıt yoksa bölüm "veri yok" der, 0 ya da boş göstermez. Her tarama adımı durumunu yazar (`çalıştı / araç yok / hata / desteklenmiyor`). Sözleşme testleri sentetik şemayla değil, gerçek koşudan alınmış yapıtlarla yazılır.

### T3. Ad hattı: süzgeçlerin yan yolları ve sabit güvenler
- **Ne:** Ölçülüp susturulmuş sinyaller başka kapıdan geri giriyor; ön adların hepsi kanıt gücünden bağımsız 0,95 alıyor; imza veritabanı ada tek kitaplık tutuyor.
- **Bulgular:** AD-01 (`kebap_ad`: ölçülmüş 239 yanlış / 0 doğru, hâlâ açık), AD-02 (`api_param_reverse` rolü ad yapıyor), AD-03 (gnulib parmak izi program/platform bakmıyor), AD-06 (Faz 1 çıkarıcısının süzgeci atlanıyor), AD-07 (sabit 0,95), AD-09 (susan dizgi sinyali ön ad olarak dönüyor), AD-04/05 (NameMerger etkisiz ama süzgeçsiz yan yol taşıyor), AD-08 (yerel adlar ikili genelinde numaralanıyor: `buf_308`), AD-10 (n-gram kanalı `--output-dir` ile sessizce çalışmıyor), AD-11 ve B-C6 (elle verilen ad ezilebiliyor), IMZA-07/08/09 (imza veritabanı), MEK-11 (`entry` → CoreGraphics; Mach-O'da `main` kaçıyor).
- **Onarım yönü:** tek kural: **koda yazılan her ad aynı kapıdan geçer** (geçerlilik + çakışma + susturma + eşik + köken kaydı); ön ad da, birleştirici de, n-gram da. Güven kanaldan ölçülmüş değeri taşır ya da boş kalır. Ölçülmüş karar (`kebap_ad`, `api_param_reverse`) karar tablosuna ölçüm kaydıyla işlenir. Her değişiklik `urun_olc.py` ile ön kayıtlı ölçülür (ad davranışı değişiyor).

### T4. Tip ve yapı: ad üstünden birleştirme
- **Ne:** Tip ve yapı katmanları değişkeni yalnız adıyla tanıyor. Ghidra her fonksiyonda `param_1`, `uVar1` adlarını yeniden kullandığı için bir fonksiyonun kanıtı başka fonksiyona tip olarak yazılıyor; yapılar ilgisiz fonksiyonların erişimlerinden kuruluyor; dizgi sabitleri kod sanılıyor.
- **Bulgular:** TIP-06, TIP-11 (yanlış tip), TIP-07, ARAYUZ-18 (sahte yapılar), TIP-04, TIP-05 (mühendislik yapı hattı Ghidra'nın gerçek alan adlarını eziyor, koda bağlanmıyor), BORU-01, BORU-02 (yapı kurtarma iki kez koşuyor, yedeğini girdi sayıyor).
- **Onarım yönü:** anahtar `(fonksiyon, değişken)`; desenler dizgi ve yorum örtüldükten sonra çalışır; ofset tabanın işaretçi tipine göre ölçeklenir; Ghidra'nın somut tipi yalnız daha bilgili ve aynı genişlikte tiple değişir; koda bağlanamayan yapı `types.h`'ye "bağsız aday" olarak ayrı yazılır. Ölçüm: DWARF tip tabanı hazır (`dwarf_tip.py`, T0a/T0b); "Ghidra'dan daha kötü tip yazma" oranı kapı olur.

### T5. Koşan ama sonuç üretmeyen kollar
- **Ne:** Aşağıdaki kollar her ikilide çalışıyor ya da "var" diye belgeleniyor, ama yapısal nedenle sonuç üretemiyor:

| Kol | Neden üretemiyor | Bulgu |
|---|---|---|
| CFG-iso eşleme | sorgu düğümleri `{"instr": N}`, şablonlar gerçek komut adı; LSH hiç aday döndüremez | TIP-01 |
| Hesaplama füzyonu | en iyi tek kanıtlı aday 0,182 olasılık alır, eşik 0,90; iki kaynağın anahtarı (ad ↔ adres) kesişmez; sonucu okuyan yok | TIP-02, BORU-03 |
| MaxSMT yapı kurtarma | ofset, P-code'un adres alanı kimliğinden (433) okunuyor; çıktıyı okuyan yok (bayrak kapalı) | TIP-03, BORU-04 |
| Parametre adı yayılımı | hesaplanıp atılıyor, sayaç "yayıldı" diyor | BORU-10 |
| PDB / Binary Ninja / TRex / DWARF / Rust / Go ad kanalları | ad birleştiricisine girdi olarak geçirilmiyor; tüketici adım üreticileriyle aynı paralel düzeyde | BORU-14, IMZA-13 |
| capa | `backend="auto"` capa 9.4'te geçersiz; CLI yolu güvenli dizin listesine takılıyor | IMZA-06 |
| C++ RTTI kurtarma | ayar okunmuyor, akışa bağlı değil (yalnız `karadul rtti`) | IMZA-16 |
| Paralel adlandırma koşucusu | beklenen yöntemler yok | AD-12 |
| n-gram yerel ad kanalı | veri yolu `project_root`'a bağlı | AD-10 |

- **Onarım yönü:** her kol için "girdi → çıktı → tüketici" zinciri uçtan uca kurulur ve en az bir gerçek ikilide sonucun ad haritasına ya da koda ulaştığı gösterilir. Açılan her ad kanalı ölçümsüz açılmaz (plan v2 ilkesi): önce bayrak arkasında, sonra ön kayıtlı ölçüm. Zincir kurulana kadar rapor "çalıştı, 0 sonuç" yerine "bağlı değil" yazar.

### T6. Boru hattının dürüstlüğü
- **Ne:** Başarı bayrakları ve çıkış kodları gerçeği taşımıyor; aynı iş iki kez koşuyor; ölü kod etkin kod sanılıp düzeltiliyor.
- **Bulgular:** MEK-01 (`analyze` çıkış kodu), BORU-05 (`reconstruct` fiilen hep başarılı), BORU-07 (`batch` her hedefi başarılı sayıyor), BORU-06 (belirlenimci hata aşamayı 4 kez koşturuyor), BORU-01 (çift koşu), BORU-09 (aynı saniyede aynı çalışma dizini), BORU-11 (paralel düzeyde yerinde yazma/okuma yarışı), BORU-12 (`stages.py`'de ~2 750 ölü satır, 2026-11-12'de bile düzeltme almış), BORU-08 (`.app` içinde JAR).
- **Onarım yönü:** başarı = "proje kuruldu ve adlandırma hatasız"; kısmi durum ayrı alan; CLI aşama hatalarını yazar ve çıkış kodu verir. Ölü kodun silinmesi küçültme sayılmaz (hiç çalışmayan kopya); yine de silme Berke'nin açık onayına bağlıdır (§6 K-3).

### T7. Arayüz
- **Ne:** Çalışıyor, güvenli (XSS yok; jeton, Host ve Origin denetimi her uçta), görsel olarak tamam. Kusurlar içerikte: eski bir doğruluk iddiası, etkisiz ayar düğmeleri, sessiz kesmeler.
- **Bulgular:** ARAYUZ-03 ("F1 ~0.45-0.49" notu), ARAYUZ-04/05 (etkisiz "Maks. fonksiyon" ve "Çevrimiçi"), ARAYUZ-06 ("Kaydet" YAML'ın geri kalanını siliyor), ARAYUZ-10 (iptal yok; sonsuz "çalışıyor"), ARAYUZ-11 (kısmi başarısızlık gizleniyor; FUN_ olmayan fonksiyonlar açılamıyor), ARAYUZ-12 (600 satır kesmesi), ARAYUZ-13 ("çözüldü" sayacı doğrulanmamış adları sayıyor), ARAYUZ-14 (ad düzeltme sessizce kaybolabiliyor), ARAYUZ-15, MEK-08 (uydurma kısa etiket `FUN_0052f4`), ARAYUZ-09 (aynı çıktı dizinine ikinci koşu), ARAYUZ-19 (vizyona göre eksikler).
- **Onarım yönü:** `ui/server.py` ve `ui/index.html` tek ajanın elinde, küçük kalemler tek pakette; vizyon kalemleri (sohbet, canlı ajan görünümü, ilişki izleme) KaradulLM paketiyle birlikte ayrı iş.

### T8. KaradulLM
- **Bugün:** `karadul/lm/` hiçbir yere bağlı değil (arayüz, CLI, boru hattı içe aktarmıyor). Üç okuma aracı var (`get_evidence`, `get_decompiled`, `get_xrefs`). K0 kipi gerçek modelde 5/5 çekimser.
- **Kod kusurları:** LM-01 (15 kurallı denetimin kodu yok: `while`, `main`, `malloc` kanıtsız kabul ediliyor), LM-02 (akış kopması görevi ve kuyruğu düşürüyor), LM-03 (istem enjeksiyonuna karşı yalnız istem kuralı), LM-04 (jeton kestirimi adres listelerini düz metin sayıyor), LM-05 (yetim model sunucusu, ~16 GiB), LM-06 (iptal bir kez basılınca kalıcı), LM-07 (test boşlukları).
- **Çekimserliğin nedeni (LM-08):** modelin önüne gelen pakette komşu fonksiyonların ne yaptığına dair hiçbir bilgi yok; bugünkü çıktıda çağrılanların hiçbiri adlı değil (htop 419/419). Bu bilgi eksikliği; model yeteneği sorunu değil.
- **Ayrıntı ve yol haritası:** §7.

### T9. Ağ ve gizlilik
- **Ne:** README "öntanımlı çevrimdışı" diyor. İki yol bu sözü tutmuyor.
- **Bulgular:** MEK-03 (JS hattında `.d.ts` indirmesi ağ bayrağına bakmadan unpkg.com'a gidiyor; `allow_dts_fetch`, `allow_source_match` hiç okunmuyor), MEK-04 = ARAYUZ-16 (uygulama her açılışta GitHub'a güncelleme sorgusu atıyor; kapatma ayarı yok), ARAYUZ-05 (arayüzdeki ağ düğmesi etkisiz).
- **Onarım yönü:** bütün dış istekler tek bir kapıdan (`network.enabled` + alt izin) geçer; kapı kapalıyken `urlopen` çağrılırsa düşen bir test bunu kilitler.

### T10. Ghidra köprüsü, BSim, ayarlar ve CLI
- **Ne:** Ürünün bütün girdisi Ghidra'dan geliyor; köprü veri atıyor ve hatayı gizliyor. Ayar ve komut satırı katmanı yanlış girdiyi sessizce yutuyor.
- **Bulgular (Ghidra):** GHIDRA-09 (Ghidra tamamen düşse de `static` aşaması başarılı; hata nedeni hiçbir çıktıda yok), GHIDRA-10 ("Functions recovered" içe aktarım taslaklarını da sayıyor), GHIDRA-05 (`decompiled.json`'daki 500 fonksiyon iş parçacığı bitiş sırasına göre seçiliyor: belirlenimsiz), GHIDRA-06 (PyGhidra yolunda zaman aşımı fiilen yok), GHIDRA-16 (dizgi kaydında fonksiyon bağı 80 545 dizginin 0'ında), GHIDRA-08 (`analyzeHeadless` yedeği sabitlenen 12.1.2 ile çalışamıyor), B-B4 (gövde 5 000 karakterde kırpılıyor; HEAD'de 11 ikili / 13 664 kayıt), B-C4 (proje siliniyor), MEK-02 (`diff`).
- **Bulgular (BSim):** GHIDRA-01 (ortak H2 veritabanı kilidi: eşzamanlı koşuda geri kalanlar yedeğe düşüyor; HEAD koşusunda 11/14 ikilide günlükte görüldü), GHIDRA-02 (ortak depo sızıyor: sembollü kopyaların gerçek adları stripped ikiliye aday olarak geliyor; ölçüm hijyeni için de önemli), GHIDRA-03 (lite dizini atomik olmayan ortak JSON), GHIDRA-12 (`karadul bsim` komutları analizin kullandığı veritabanını yönetmiyor).
- **Bulgular (çalıştırma güvenliği):** GHIDRA-07 (`security.allow_target_execution` YAML'da `"false"` dizgisini doğru sayıyor: hedef çalıştırma kapısı yanlışlıkla açılabilir), GHIDRA-11 (`--dynamic`: hedef süreç kancasız sürdürülüyor ve analiz bitince öldürülmüyor), GHIDRA-13 (`karadul run` analiz edilen koddan türeyen projeyi yerelde çalıştırıyor, `npm install` yapıyor).
- **Bulgular (ayar/CLI):** GHIDRA-04 (yanlış yazılmış anahtar ve tip sessizce yutuluyor; `config validate` yakalamıyor), GHIDRA-14 (`project_root` hem çıktı kökü hem veri kökü: `--output-dir` verilen her koşuda dış imzalar, FLIRT ve n-gram verisi bulunamıyor; arayüz ve ölçüm koşuları hep böyle çalışıyor), MEK-05 (231 ayarın 83'üne erişim yok), MEK-01, MEK-09, BORU-13, ARAYUZ-04.
- **Onarım yönü:** Ghidra çıktısına "kayıp sayacı" (kaç fonksiyon/gövde/dizgi atıldı, neden) ve hata nedeni; BSim deposu koşuya özel ya da kilitli + kaynağı işaretli; hedef çalıştırma kapısı katı tipli ve her açılışta görünür uyarı; `data_root` ile `output_root` ayrımı; ayar yükleyicide bilinmeyen anahtar = hata.

### T11. Native olmayan hatlar (JS/Electron, Java/APK, .NET, Python)
- **Ne:** Bu hatlar "destekleniyor" diye sunuluyor; ölçülmedi. Tarama iki güvenlik açığı ve birkaç "çalışıyor görünüp çalışmayan" yol buldu.
- **Güvenlik:** BICIM-04 (analiz edilen dosyadaki `Main-Class`, paket adı, AssemblyRef değerleri üretilen `build.gradle` ve `.csproj` içine kaçışsız yazılıyor: projeyi açan/derleyen analistin makinesinde saldırgan kodu çalışır), BICIM-07 (hedef çözücü, bulunamayan noktalı adda çalışma dizinindeki Python modülünü içe aktarıyor: örnek klasöründe yazım hatası kod çalıştırır), BICIM-06 (Electron hedefinde `npx --yes @electron/asar`: sürümü sabitlenmemiş paketi ağdan indirip çalıştırıyor, ağ bayrağına bakmadan), BICIM-14 (PyInstaller açmada toplam boyut bütçesi yok), BICIM-12 (üretilen README analiz edilen koda `npm install && npm start` öneriyor).
- **İşlev:** BICIM-01 (webpack 4 modülleri sözdizimi bozuk yazılıyor; ürünün kendi örnek dosyasında görülüyor, MEK-12), BICIM-02 (yeniden kurma deobfuscation çıktısını değil en büyük `.js` dosyasını, çoğu zaman özgün dosyayı işliyor), BICIM-13 (modül ayırıcı yanlış dizine bakıyor, hiç çalışmıyor), BICIM-11 (npm parmak izi zararlı modülü "Vendored <paket>" diye `vendor/` altına koyabiliyor), BICIM-05 (jadx/ILSpy çökse de `decompiled: True`), BICIM-08 (yerel PE `mscoree.dll` dizgisi yüzünden .NET sayılıyor, Ghidra hiç çalışmıyor), BICIM-09 (.app içinde asıl kod JS/JAR ise hiç yeniden kurulmuyor), BICIM-10 (tek `.pyc`, cx_Freeze, wheel/IPA, FAT64 tanınmıyor ya da yanlış hatta), BICIM-03 (sayaçlar).
- **Onarım yönü:** önce güvenlik (dışarı yazılan her dosyada kaçış; hiçbir yolda içe aktarma/çalıştırma; ağ kapısı), sonra her hat için 3–5 örneklik küçük bir doğrulama seti (bugün yok) ve "araç yok / çöktü / tamam" durumunun dürüst yazılması.

### T12. Mühendislik paketinin ürettiği adlar ve yorumlar
- **Bulgular:** MUH-01 (parametrelere `0xffffffffffffffff`, `long`, `int`, `DAT_001410c0` gibi geçersiz ya da yanıltıcı adlar: 117 ikili, 1 163 imza; HEAD çıktısında görüldü), MUH-02 ("döngü derinliği" aslında süslü parantez derinliği: `if` içindeki parametre `M_matrix` / `v_vector` oluyor; 59 ikili, 308 ad), MUH-11 (bu adlar ürün eşiğinden, ad süzgecinden ve köken kaydından geçmiyor; `naming_map.json`'da izi yok), MUH-03 (bileşim şablonları; ARAYUZ-01'in kökü), MUH-04 (alan sınıflandırıcısı ikilinin bütün dizgilerini her fonksiyona kanıt sayıyor), MUH-10 (sabit katmanı alt dizgiyle eşleşiyor: `"0" in code` → RC4 %90; bugün yalnız bozuk bir kapı sayesinde susuyor), MUH-12 (formül çıkarıcı zayıf tespiti belirli algoritmaya yükseltiyor), MUH-07 ("Row-major matrix access" yorumu; 370 yorum), MUH-06 (C++ sanal çağrı çözücüsü 119 ikilide 0 çağrı yeri buluyor), MUH-05 (güven "kalibrasyonu" hiçbir karara girmiyor), MUH-09 (başvuru karşılaştırmasında sürüm tespiti "requires SQLite 3.8.12 or later" dizgisinden 3.8.12 okuyor), MUH-08 = BORU-10.
- **Onarım yönü:** T1 ve T3 ile aynı: tek ad kapısı, kanıt şartı, masum ikili kapısı. Bu paket vizyondaki "fonksiyonların ilişkisini hesaplamayla bul" işinin doğal yeri; şablonlar libc ithal adından değil, fonksiyon gövdesindeki ölçülebilir olgudan (çağrı sırası, veri akışı, sabitler birlikte) beslenmeli.

### T13. Test, CI ve depo düzeni
- **Sağlam:** tam takım 8 289 geçti / 0 kaldı; CI dışı 153 testin 141'i geçti, 12'si atlandı; testler ağacı kirletmiyor; 7 127 testin yalnız 16'sında doğrulama ifadesi yok.
- **Açık:** uçtan uca analiz CI'da hiç koşmuyor (Ghidra yok); 10 test kalıcı atlanıyor ya da `/private/tmp`'deki girdiye bağlı (MEK-10); testlerin bir bölümü yalnız ölü kodu sınıyor (BORU-12) ya da kırık yolu taklit ettiği için kırığı göremiyor (IMZA-06: capa testleri `_scan_via_api`'yi taklit ediyor); mypy 101 hata, CI'da yok (MEK-06); erişilemeyen 46 modül / 8 149 satır (MEK-07) + Ghidra kulvarında ~7 000 satır (GHIDRA-15); kişisel yollar ve eski iddialı belgeler (MEK-13); sağlamlık denetim betiği bugünkü çıktı biçimini bilmiyor (kulvar_MEK §Sağlamlık).
- **Ders (onarım ajanlarına):** bu depoda yeşil test kanıt değildir. Her onarım (a) kusuru gerçek çıktıda gösteren bir sayımla başlar, (b) onarımdan sonra aynı sayımı yineler, (c) testini mutant koda karşı dener.

## 4. Bulgu sayıları

Tam liste ve doğrulama işaretleri: `DIZIN.md` (üretici `mekanik/dizin.py`).

| Kulvar | KRİTİK | YÜKSEK | ORTA | DÜŞÜK | Toplam |
|---|---|---|---|---|---|
| MEK (ana oturum) | 0 | 2 | 7 | 5 | 14 |
| BORU | 0 | 3 | 9 | 2 | 14 |
| AD | 1 | 4 | 6 | 1 | 12 |
| TIP | 0 | 6 | 4 | 1 | 11 |
| IMZA | 4 | 6 | 5 | 1 | 16 |
| ARAYUZ | 1 | 4 | 12 | 2 | 19 |
| MUH | 2 | 3 | 6 | 1 | 12 |
| BICIM | 2 | 8 | 5 | 0 | 15 |
| GHIDRA | 1 | 7 | 8 | 0 | 16 |
| LM | 0 | 4 | 4 | 0 | 8 |
| **Toplam** | **11** | **47** | **66** | **13** | **137** |

- Aynı kusuru iki kulvar ayrı yönden yazdıysa ikisi de sayıldı (ör. ARAYUZ-01 belirti, MUH-03 kök; BORU-14 ve IMZA-13; BORU-10 ve MUH-08; MEK-04 ve ARAYUZ-16; MEK-03 ve BICIM-06). Ayrık kusur sayısı yaklaşık 130'dur.
- Önem etiketleri kulvar ajanınındır; ana oturum değiştirmedi. KaradulLM bulgularının önemi "arayüze bağlandığında doğacak etki"ye göredir (bugün analiste görünmüyor). GHIDRA-11 yalnız `--dynamic` ile ortaya çıkar.

## 5. Onarım planı

### 5.1 Kurallar (her onarım ajanının istemine girer)
1. **Dosya sahipliği.** Her paket yalnız kendi dosyalarını yazar. Aşağıdaki "tehlikeli" dosyalar tek pakete aittir ve o paket bitmeden başkası dokunmaz: `stages.py`, `config.py`, `c_namer.py`, `ghidra/headless.py`, `core/output_formatter.py`, `core/target.py`. Başka paketin dosyasında değişiklik gerekiyorsa ajan yama dosyası (`.patch`) bırakır, ana oturum uygular.
2. **Aynı anda en çok 4 ajan** (Berke, 2026-11-18). Dalgalar buna göre kuruldu.
3. **Önce göster, sonra onar.** Ajan işe kusuru gerçek çıktıda sayarak başlar (kulvar dosyasındaki "Kanıt" ve "Nasıl sınanır"). Sayı raporda yazanla tutmuyorsa durur ve bildirir.
4. **Katman kalır.** Onarım, katmanı silmek ya da bayrağını kalıcı kapatmak değildir (Berke kararı). İstisna: hiç çalışmayan ölü kopyalar (K-3 onayıyla).
5. **Ad davranışını değiştiren paketler** (aşağıda "ölçüm" işaretli) ön kayıtlı ürün ölçümü olmadan `main`'e "iyileşme" diye yazılmaz: değişiklikten önce beklenti yazılır, sonra `urun_kos.py` + `urun_olc.py`.
6. **Masum ikili kapısı.** Tespit ve iddia katmanları için ortak kabul ölçütü: geliştirme setindeki 119 ikili + macOS sistem ikilileri + birkaç masum PE üstünde yanlış iddia sayısı. Kapı betiği Dalga 0'da kurulur.
7. Sahte veri/gösterge yok; Türkçe metinler Türkçe karakterle; her iş kalemi ayrı commit; push sorulur; sürüm kuralı: yalnız düzeltme → `Z` +1.
8. Ağır ajana takılma bekçisi; ajan bulguyu/işi parça parça dosyaya yazar (bu taramada 9 ajanın 9'u böyle bitti).

### 5.2 Paketler

| Paket | Konu | Sahip olduğu dosyalar | Bulgular | Boy | Not |
|---|---|---|---|---|---|
| P00 | Ölçüm zemini | `docs/arge/2026-11-10_cikti_saglamligi/denetle.py` (yeni sürüm), yeni `scripts/measurement/masum_kapi.py` | kulvar_MEK §Sağlamlık; kural 6 | M | Öbür her paketin önce/sonra kanıtı. İlk iş. |
| P01 | İkili istihbarat | `analyzers/binary_intelligence.py` | IMZA-01 | M | masum kapı |
| P02 | Anti-debug + paketleyici | `analyzers/anti_debug_detector.py`, `analyzers/packer_fingerprint.py` | IMZA-02, 03, 04 | M | masum kapı; x86 gerçek pozitif örneği gerek |
| P03 | YARA + capa | `analyzers/yara_scanner.py`, `analyzers/capa_scanner.py`, capa testleri | IMZA-05, 06 | M | durum yazımının `stages.py` kısmı P-S1'de |
| P04a | Bileşim + alan + blok yorumu | `engineering/composition_analyzer.py`, `domain_classifier.py`, `block_annotator.py` | MUH-03 (=ARAYUZ-01 kök), MUH-04, MUH-07 | M | masum kapı |
| P04b | Formül + sabit + dağıtım + kalibrasyon | `engineering/formula_reconstructor.py`, `analyzer.py`, `constants.py`, `dispatch_resolver.py`, `confidence_calibrator.py`, `confidence_calibration.py`, `reference_differ.py` | MUH-05, 06, 09, 10, 12 | L | masum kapı |
| P05 | Anlamsal adlandırıcı | `engineering/semantic_namer.py`, `pipeline/steps/semantic_naming.py` | MUH-01, 02, 11 | M | **ölçüm**; `name_validity` kullanır |
| P06 | Algoritma ve güvenlik etiketleri | `reconstruction/c_algorithm_id.py`, `c_comment_generator.py` | TIP-08, 09 | M | masum kapı; `ab986da` düzeni örnek |
| P07 | Raporlar | `reporting/*.py`, `core/report_generator.py` | ARAYUZ-01 (alan adları), 02 (okuma), 07, 08, 17, B-B7 | L | P08 ve P-S1'in yazdığı yapıt biçimine bağlı |
| P08 | İmza veritabanı | `analyzers/signature_db.py`, `sigdb_lmdb.py`, `sigdb_builtin/`, `pipeline/steps/ghidra_metadata.py`, LMDB kurma betiği | IMZA-07, 08, 09, 10, 11, 12, MEK-11, ARAYUZ-02 (yazıcı) | L | **ölçüm**; IMZA-07 veritabanının yeniden kurulması (K-5) |
| P09 | Tip kurtarma | `reconstruction/c_type_recoverer.py`, `xtride_typer.py`, `pipeline/steps/_feedback_typing_extras.py` | TIP-06, 07, 11, ARAYUZ-18, AD-10 | L | ölçüm: DWARF tip tabanı |
| P10 | Yapı kurtarma (mühendislik hattı) | `engineering/struct_recovery.py`, `pipeline/steps/struct_recovery.py`, `inline_detection.py` | TIP-04, 05, BORU-02, BORU-04 | M | BORU-01 silinmeden önce MaxSMT aday yolu burada kurulur |
| P11 | Hesaplama kolları | `pipeline/steps/cfg_iso_match.py`, `computation_fusion.py`, `computation_struct_recovery.py`, `karadul/computation/` | TIP-01, 02, 03, BORU-03 | L | CFG-iso için blok başına komut dökümü P16'dan gelir; şablon bankası gerçek koddan yeniden kurulur |
| P12 | Ad çekirdeği | `reconstruction/c_namer.py`, `tarif/alt_kanal.py`, kesinlik tablosu | AD-01, 02, 07, 08 | M | **ölçüm**; K-2 kararı |
| P13a | Ad yan yolları | `pipeline/steps/parallel_algo_eng.py`, `reconstruction/binary_name_extractor.py`, `_feedback_naming_candidates.py`, `_feedback_naming_merger.py`, `_feedback_naming_bindiff.py`, `_feedback_naming_refdiff.py`, `_feedback_naming_parallel.py`, `naming/parallel_runner.py` | AD-04, 05, 06, 09, 11, 12 | M | **ölçüm**; P12'den sonra |
| P13b | Bağlı olmayan ad kanalları | `pipeline/steps/feedback_loop.py`, `type_recovery_consumer.py`, `_deep_tracing_helpers.py`, `analyzers/rust_demangler.py`, `cpp_rtti.py` | BORU-14, IMZA-13, 14, 16, BORU-10 (=MUH-08) | L | **ölçüm**; K-4 kararı; P13a'dan sonra |
| P14 | Çekirdek akış | `core/pipeline.py`, `core/error_recovery.py`, `pipeline/runner.py`, `core/workspace.py`, `karadul/batch.py`, `pipeline/steps/finalize.py` | BORU-06, 07, 09, 11 | M | |
| P15 | CLI ve ayar | `karadul/cli.py`, `cli_common.py`, `hacker_cli.py`, `config.py` | MEK-01, 05, 09, BORU-13, GHIDRA-04, 07, 10 (sayaç), 12, 13, 14, ARAYUZ-04, TIP-10 | L | `config.py` tek elden; `data_root` ayrımını tüketen dosyalar için yama bırakır |
| P16 | Ghidra köprüsü + BSim + dinamik | `ghidra/headless.py`, `ghidra/bsim.py`, `_bsim_shadow.py`, `program_diff.py`, Ghidra betikleri, `analyzers/macho.py`, `frida/session.py` | GHIDRA-01, 02, 03, 05, 06, 08, 09, 10, 11, 16, MEK-02, B-B4, B-C4 | L | ad haritasını etkileyebilir (GHIDRA-05): **ölçüm** |
| P17 | Arayüz | `ui/server.py`, `ui/index.html`, `ui/app_window.py`, `core/overrides.py` | ARAYUZ-03, 05, 06, 10–16, MEK-04, 08 | L | tarayıcıda gözle doğrulama şart |
| P18 | Çıktı ağacı | `core/output_formatter.py`, `reconstruction/c_project_builder.py` | ARAYUZ-09, 07 (JSON), B-B1, B-B8, ARAYUZ küçükler | M | |
| P19 | Native olmayan hatlar: güvenlik ve tanıma | `analyzers/java_binary.py`, `dotnet_binary.py`, `electron.py`, `packed_binary.py`, `app_bundle.py`, `core/target_resolver.py`, `core/target.py` | BICIM-04, 05, 06 (asar), 07, 08, 10 (tanıma), 14 | M | **güvenlik: öne alınır** |
| P20 | JS hattı | `scripts/*.mjs`, `reconstruction/naming/`, `dts_namer.py`, `project_builder.py`, `project_reconstructor.py`, `module_splitter.py`, `context_namer.py`, `deobfuscators/` | BICIM-01, 03, 11, 12, MEK-03 (= BICIM-06 `.d.ts`), MEK-12 | L | |
| P-S | `stages.py` (seri; dört tur) | `karadul/stages.py` + yalnız onu sınayan testler | S1: BORU-05, IMZA-15, IMZA-05/06 ve ARAYUZ-17'nin durum/kayıt kısmı, GHIDRA-07/11'in `stages` kısmı · S2: BORU-01, 12 · S3: AD-03, B-C6 · S4: BICIM-02, 09, 10, 13, BORU-08 | L | tek ajan, turlar arasında ana oturum doğrular; S2 için K-3 onayı |
| P21 | KaradulLM sağlamlaştırma | `karadul/lm/**`, `tests/test_lm_*.py` | LM-01–07, B-E2, B-E5 | L | arayüze bağlamadan ÖNCE |
| P22 | KaradulLM: bilgi, araçlar, arayüz | (yeni dosyalar) + P17 ile eşgüdüm | LM-08, ARAYUZ-19, §7 | L | yeni iş; ayrı tasarım turu |
| P23 | Test, CI, düzen | CI dosyaları, atlanan testler, mypy (dosya sahibi paketler bittikten sonra), depo artıkları | MEK-06, 07, 10, 13, 14, GHIDRA-15, BICIM-15 | M | en sonda |

### 5.3 Sıra (aynı anda en çok 4 ajan; aynı dalgadaki paketlerin dosyaları kesişmez)

| Dalga | Paketler | Neden bu sıra |
|---|---|---|
| 0 | P00 | Ölçüm zemini; taban sayılar alınır |
| 1 | P19, P01, P02, P04a | Güvenlik açıkları + analisti en çok yanıltan dört katman |
| 2 | P03, P06, P08, P-S (S1) | Kalan tespit katmanları, imza veritabanı, durumların dürüst yazılması |
| 3 | P07, P05, P04b, P16 | Raporlar artık doğru veriyi okuyabilir; Ghidra köprüsü |
| 4 | P09, P10, P12, P14 | Tip, yapı, ad çekirdeği, çekirdek akış |
| 5 | P13a, P15, P17, P18 | Ad yan yolları, CLI/ayar, arayüz, çıktı ağacı |
| 6 | P13b, P11, P20, P-S (S2 → S3 → S4) | Bağlanmamış kanallar, hesaplama kolları, JS hattı, `stages.py` temizliği |
| 7 | P21 → P22, P23 | KaradulLM ve kapanış |

- Her dalganın sonunda: tam takım, P00'ın iki kapısı (sağlamlık + masum ikili), dalgada "ölçüm" işaretli paket varsa ön kayıtlı ürün ölçümü; sonra bir sonraki dalga.
- Dalga 1–3 bittiğinde §2'deki tablonun tamamı kapanmış olur; "analisti yanıltmıyor" denebilecek ilk nokta orasıdır.
- Kaba büyüklük (ölçüm değil, tahmin): 27 paket; her biri bir ajan oturumu, L olanlar iki. Dalga başına ana oturumun doğrulaması dahil yarım–bir gün; tamamı 1,5–2,5 hafta.

## 6. Berke'nin kararına kalanlar

| No | Soru | Önerim |
|---|---|---|
| K-1 | Onarımı uzun süren katmanlarda (bileşim, yapı kurtarma, hesaplama kolları) onarım bitene kadar çıktı rapora nasıl yazılsın? | Katman koşsun, ama onarılıp kapıdan geçene kadar iddiası rapora ve koda yazılmasın (silme değil, bekletme). Yoksa ara sürümler bugünkü yanlışları taşır. |
| K-2 | `kebap_ad` (239 yanlış / 0 doğru) ve `api_param_reverse` (rol adı) ad olarak sussun mu? | Evet: ad olarak yazılmasın; fonksiyon kartında ve yorumda "okuduğu seçenek: monitor-silence", "rol: qsort karşılaştırıcısı" diye kanıt satırı olsun. (11 Kasım'dan beri açık soru.) |
| K-3 | Hiç çalışmayan kod ne olacak? (Berke sordu: "bağlanamaz mı?") Ayrıntı aşağıda §6.1. | İkiye ayır: **gerçek kopyalar silinsin** (~7 300 satır; aynı işin eski hâli, yenisi zaten çalışıyor), **bağlanabilir özellikler bağlansın** (~8 000 satır; KaradulLM ayrıca). Silme listesi paket başlamadan önce kalem kalem gelir. **Durum (2026-11-18): Berke sınıflamayı ve yönü kabul etti ("tamamdır"): A silinir, B bağlanır. Her silme kalemi yine de paket başında tek tek onaya sunulur.** |
| K-4 | Bağlı olmayan ad kanalları (PDB, DWARF, Binary Ninja, TRex, Rust/Go demangle, capa adları, RTTI) bağlansın mı? | Evet, bayrak arkasında ve ölçerek. Önce PDB ve DWARF (derleyicinin kendi yazdığı adlar; en güvenilir kaynak). |
| K-5 | İmza veritabanı (9,2 M ad, 2 GB, depo dışı) yeniden kurulacak (IMZA-07). Kullanıcı bunu nasıl edinecek? | Yeniden kurarken yalnız tanımlanan/dışa aktarılan simgeler ve ad başına kitaplık listesi. Dağıtım: ayrı indirilen veri paketi + raporda "hangi veritabanıyla koşuldu" satırı. Ayrıntı senin kararın. |
| K-6 | Uygulama açılışındaki güncelleme sorgusu (GitHub) kalsın mı? | Öntanımlı kapalı ya da ilk açılışta sorulsun; ağ ayarına bağlansın. |
| K-7 | Bu rapor ve kulvar dosyaları commit'lensin mi? Depo herkese açık; içinde onarılmamış güvenlik açıkları var (BICIM-04, BICIM-07, GHIDRA-07, GHIDRA-11, GHIDRA-13). | Yerelde commit'lenebilir; **push, Dalga 1'deki güvenlik onarımları `main`'e girdikten sonra**. İstersen güvenlik bulgularını ayrı dosyaya alıp onu depoya hiç koymayız. |
| K-8 | Native olmayan hatlar için doğrulama seti yok. Kurulsun mu? | Evet, küçük: hat başına 3–5 açık kaynaklı örnek (Electron uygulaması, JAR, APK, .NET, PyInstaller). Onarımın "bitti" demesi için gerekli. |
| K-9 | Bu taramanın koşu dizini `~/karadul_olcum/runs/genel-tarama-2026-11-18` (2,0 GB) | Dalga 0 tabanı alınana kadar kalsın, sonra silinsin (onayınla). |

### 6.1 "Ölü kod" nedir, hangisi bağlanabilir?

"Ölü kod" bugün `karadul analyze` çalışırken hiçbir yoldan çağrılmayan koddur. İki ayrı türü var ve ikisine aynı şey yapılmaz.

**A. Kopyalar: bağlanacak bir şey yok (öneri: sil).** Bunlar bir özelliğin eski sürümüdür; aynı işi yapan yeni sürüm bugün çalışıyor. "Bağlamak" aynı işi iki kez koşturmak demektir; BORU-01 tam olarak bunun kazayla olmuş hâli (yapı kurtarma, CFG-iso ve füzyon her ikilide iki kez koşuyor, ikincisi birincinin yedeğini bozuyor).

| Kalem | Satır | Neyin kopyası | Neden silinmeli |
|---|---|---|---|
| `stages.py:1397-2547`, `3569-4823` (+ küçük parçalar) | ~2 750 | `pipeline/steps/` altındaki adımların eski, tek gövdeli hâli | 2026-11-12'de bile yanlışlıkla düzeltme aldı; okuyan (insan ya da ajan) etkin kod sanıyor |
| Yalnız bu ölü metotları sınayan 4 test dosyası | — | — | Yeşil görünüp ürünü sınamıyor |
| `ghidra/scripts/legacy/*.py` | 2 585 | Ghidra betiklerinin Jython 2.7 sürümü | Jython kurulu değil, Ghidra 12 ile çalışmaz |
| `engineering/confidence_calibration.py` | 806 | `confidence_calibrator.py`'nin ikizi | Hiçbir yerden içe aktarılmıyor |
| Eski deobfuscation zinciri (`deobfuscators/manager.py`, `synchrony_wrapper.py`, `babel_pipeline.py`, `stages.py` `_execute_legacy`) | ~741 | `deep_pipeline.py`'nin öncülü | `use_deep=False` hiçbir yerde kurulmuyor |
| Paralel adlandırma koşucusu (`naming/parallel_runner.py`, `_feedback_naming_parallel.py`) | ~400 | seri adlandırmanın paralel denemesi | Beklediği yöntemler `CVariableNamer`'da yok; açılsa etiket ve süzgeci atlar (AD-12) |

**B. Bağlanmamış özellikler: silinmez, bağlanır (onarım planında yeri var).** Bunlar yazılmış ama akışa hiç takılmamış yeteneklerdir; kapsamlı araç hedefine hizmet ederler.

| Kalem | Satır | Ne işe yarar | Nereye bağlanır | Paket |
|---|---|---|---|---|
| PDB / DWARF / Binary Ninja / TRex ad ve tip kanalları, Rust/Go demangler, `demangler_registry.py` | — | Derleyicinin kendi yazdığı adlar ve tipler: en güvenilir kaynak | Ad birleştiricisine girdi (BORU-14, IMZA-13) | P13b |
| `analyzers/cpp_rtti.py` | 1 553 | C++ sınıf adları ve sanal tablo | Analiz akışı (bugün yalnız `karadul rtti` komutu) | P13b |
| `analyzers/container_classifier.py` | 1 148 | Arşiv/kapsayıcı türünü tanıma | Hedef tanıma: wheel, IPA, nupkg bugün tanınmıyor (BICIM-10) | P19 |
| `ghidra/scripts/*.py` (Jython olmayanlar) | 2 758 | PyGhidra'sız kurulumda `analyzeHeadless` yedek yolu | GHIDRA-08 onarılırsa çalışır | P16 |
| `karadul/decompilers/` | 1 027 | İkinci decompiler arka ucu (angr) | Öntanımlı Ghidra; angr isteğe bağlı kurulum | P16 |
| `ghidra/debugger_bridge.py` (yakalama ve tip doğrulama kısmı) | 969 | Dinamik analizde gerçek değerlerle tip doğrulama | Dinamik aşama (bugün yalnız "hata ayıklayıcı var mı" bakıyor) | P16 |
| capa ve `_capa_comment_inject.py` | — | Yetenek tespiti ("tuş kaydı", "anti-VM") | IMZA-06 onarılınca kendiliğinden çalışır | P03 |
| `computation/struct_recovery/field_namer.py` | 315 | Kurtarılan yapı alanlarına ad | Yapı kurtarma onarımıyla birlikte | P10 / P11 |
| `reconstruction/jsnice_renamer.py`, `ts_declarations_namer.py` | ~180 | JS değişken adı yardımcıları | JS ad hattı | P20 |
| `karadul/lm/` | 4 324 | KaradulLM | Arayüz | P21, P22 |

- Kaba toplam (tablolardaki satırların toplamı): A türü ≈ 7 300 satır (kopya), B türü ≈ 8 000 satır (özellik; KaradulLM'in 4 324 satırı ayrıca). İlk özetteki "`stages.py`'de ~2 750, Ghidra tarafında ~7 000" sayısı iki türü karışık veriyordu: Ghidra tarafındaki ~7 000 satırın yalnız 2 585'i (Jython yedekleri) kopya, kalanı bağlanabilir.
- B türünü bağlamak "yeni özellik eklemek" sayılmaz; yazılmış olanı çalışır hâle getirmektir. Ad üreten kanallar (PDB, DWARF, RTTI) bayrak arkasında bağlanır ve ölçülerek açılır.
- **Karar durumu (2026-11-18):** Berke bu ayrımı kabul etti. B türü onarım planındaki paketlerde bağlanır; A türü P-S (S2), P16, P04b, P20 ve P13a içinde silinir. Silme, dosya silme kuralı gereği kalem kalem onayla yapılır.
- A türünü silmek küçültme değildir: çalışan sürüm yerinde kalır, yalnız eski kopyası gider. Silmeden önce her kalem için "çağıran yok" kanıtı ve silme sonrası "çıktı bayt bayt aynı" denetimi yapılır.

## 7. KaradulLM: bugünkü yer ve yol

### 7.1 Vizyonla karşılaştırma

| Vizyondaki iş | Bugün | Eksik |
|---|---|---|
| Model Karadul'un araçlarını kullanır | 3 okuma aracı (kanıt, kod, tek adım çağrı ilişkisi); araç döngüsü (K1/K2) kapalı, gerçek modelde hiç koşmadı | çok adımlı çağrı grafiği ve yol bulma, ters arama (bu dizgiyi/ithali kim kullanıyor), gövdede arama, fonksiyon olguları, tip sorgusu, benzer fonksiyon, veri akışı sorusu, not defteri |
| Ad önerir | K0: tek atış; gerçek modelde 5/5 çekimser | komşu fonksiyonların özeti (LM-08); denetim katmanı (LM-01); önerinin ayrı köken bölümüne yazılması ve geri alınması (B-E4) |
| Fonksiyonu ve bağlantılılarını anlatır | yok ("ne yapıyor?" görevi yazılmadı) | görev + şema + özet deposu |
| Analistle birlikte çalışır (sohbet + yan panel) | arayüzde hiçbir uç ya da panel yok | `/api/lm/*`, sohbet, kuyruk, kabul/ret |
| Canlı "Karadul simülasyonu" | yok; ajan olayları iş bittikten sonra ve içeriksiz yazıyor | gerçek zamanlı olay akışı: görev başladı, araç başladı/bitti, jeton, denetim hükmü, öneri (LM kulvarı §Vizyon 3). Görünüm yalnız bu olaylardan beslenir; olay yokken hareket yok. |
| Yerel model | Qwen3.8-27B (Q4_K_M, 16,8 GB dosya; bellek tepesi ~17,5 GiB; 36 GiB makine) | boş makinede hız ve 16K bağlam ölçülmedi |

Araçların çoğu için motor verisi diskte hazır (`ghidra_call_graph.json`, `ghidra_xrefs.json`, `decompiled/*.c`, `ghidra_cfg.json`, `ghidra_types.json`, `naming_provenance.json`); LM kulvarının tablosuna göre on aracın sekizi küçük iş. Pahalı olanlar: fonksiyon içi veri akışı sorusu, çok fonksiyonlu alt görev planlama, yeniden hesaplama (Ghidra projesi silindiği için).

### 7.2 Önerilen sıra
1. **Sağlamlaştır (P21).** Denetim katmanı (en az: geçerli ad, var olan adla çakışma, `kesin` adı ezmeme, kanıtsız öneri, enjeksiyon belirtisi), kopmada kuyruğun düşmemesi, yetim sunucu, iptal, jeton kestirimi, anahtarın komut satırından çıkması.
2. **Bilgiyi ver.** "Ne yapıyor?" görevi; alttan yukarı sıra (önce yaprak fonksiyonlar; özetleri çağıranın paketine `[model-özet]` işaretiyle girer). tree 7, htop 15 katman. Bu, 5/5 çekimserliğin doğrudan çaresi; bedeli htop için tahminen 3–6 saatlik kuyruk.
3. **Araçları aç.** Ters arama, çok adımlı grafik, gövdede arama, olgular, tipler; sonra K1/K2 gerçek modelde. Her araç çağrısı içeriğiyle birlikte kayda geçer (bugün yalnız özet değeri yazılıyor).
4. **Arayüze bağla.** Olay akışı → sohbet + yan panel + canlı görünüm. Model önerisi ayrı köken bölümünde durur; analist onaylamadan ad haritasına girmez; ölçüm kipinde tamamen kapalı.
5. **Ölç.** Araç hata oranı (yanlış araç, yanlış argüman, boşa çağrı), çekimser oranı, GT'li sette yanlış ad oranı; kör pilot.

### 7.3 İnce ayar sorusu (32B modele QLoRA yapılır mı, gerekir mi?)
- **Bugün gerekli olduğunu gösteren ölçüm yok.** Şemaya zorlanmış araç çağrısı 10/10 geçerli (sözdizimi hatası dilbilgisiyle zaten sıfır). K0'ın çekimserliği yetenek değil bilgi eksikliği. İnce ayarın düzeltebileceği şey araç **seçimi** ve ad kalitesi; ikisi de hiç ölçülmedi, çünkü araç döngüsü gerçek modelde bir kez bile koşmadı.
- **Eğitecek veri yok.** Çok turlu gerçek araç izi 0; denetim günlükleri içerik taşımıyor. Yukarıdaki 3. adım (araçları aç + içerikli kayıt) aynı zamanda bu veriyi üretir.
- **Bu makinede mümkün mü?** Ölçülmedi; kaba akıl yürütme: bugünkü 27B model yalnız çıkarımda ~17,5 GiB tutuyor. Eğitim, taban ağırlıklara ek olarak geri yayılım için etkinlikleri ve uzun istemleri (bizim paketler 8–10 bin jeton) bellekte tutar; 36 GiB'da 27–32B bir model için sınırda ya da sığmaz. 4090'lı dizüstü (16 GB VRAM) bu boyuta yetmez. Gerçekçi yerel hedef daha küçük bir model (kabaca 14B ve altı) olur; kesin cevap için tek bir deneme koşusuyla bellek ölçülmeli.
- **Öneri:** sıra "araçlar → gerçek modelde ölç → gerekirse ince ayar". Araç hata oranı yüksek çıkarsa, toplanan izlerle küçük bir modelde denenir; düşük çıkarsa ince ayara hiç gerek kalmaz. Bu, 2026-10-17 planındaki kuralla aynı ("ince ayara ancak araç kullanım hataları ölçülürse geçilir").

## 8. Bakılamayan yerler (dürüst sınır)
Her kulvar dosyasının "Bakamadıklarım" bölümünde ayrıntı var. Önemlileri:
- `c_namer.py`'nin strateji gövdelerinin çoğu ve `tarif/kesin.py` ("kesin" etiketinin çıkarım tarafı): okunmadı. "Kesin %97" ölçümle destekli, ama kod denetimi yapılmadı.
- `reconstruction/recovery_layers/` (≈9 600 satır; öntanımlı kapalı, arayüzden açılabiliyor): okunmadı.
- `flirt_parser.py`, `byte_pattern_matcher.py`, `bindiff.py`, `pdb_parser.py`, `dwarf_extractor.py`, `cpp_rtti.py`: kötü niyetli girdi denetimi yapılmadı.
- Go / Swift / Rust / Delphi analizcilerinin gövdeleri; gerçek `.app`, APK, .NET, PyInstaller örnekleriyle uçtan uca koşu.
- Paketleme betiklerinin çoğu (`build_dmg.sh`, koruma betikleri); notarization; GitHub sürüm durumu (ağa çıkılmadı).
- Arayüz gerçek WKWebView içinde ve 10 000+ fonksiyonlu ikiliyle denenmedi (tarayıcıda Mac htop ile açıldı).
- KaradulLM gerçek modelle koşturulmadı (enjeksiyona dayanıklılık, K1/K2 şemasının derlenmesi yalnız koddan).
- Yanlış tip ve yanlış `@security` etiketlerinin **oranı** ölçülmedi; yalnız sayıldı ve örneklendi.
- Bu tarama yeni ad doğruluğu ölçümü yapmadı; yanlış ad oranı (%29,7) 2026-11-12 ölçümünden alındı.
