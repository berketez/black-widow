# ARGE kararları (2026-11-19)

Berke'nin bu oturumda verdiği kararlar ve ana oturumun onun yetkisiyle verdiği hükümler. Planlar bu belgeye göre okunur; çelişkide bu belge geçerlidir.

## Berke'nin sözleri

- "En çok 3 Mythos ajanı; bunlar gerçekten ARGE için. Öbür işler için Opus."
- "ARGE yapılırken kodları siz yazmayın; detaylı planı adım adım çıkarın. Plan çıkınca bu oturumda yapılacak iş kalmayacak; sonraki oturumda bütün işleri Opus'lar halledecek."
- "Zaman yeter; bir şeyler atlamasınlar."
- "Uygulamayı toparlayalım, yayına almak istiyorum, biraz erkenden. KaradulLM kullanmak istiyorum. 50 MB'lık bir uygulamayı tersine mühendislikle görmek istiyorum."
- "Kendi decompiler dışında bizim de ekosistemimiz olacak." "MCP sunucusu da yapalım: analistlerin model izinleri vardır; Karadul'u MCP ile Claude / GPT ile kullanabilsin."
- ÖLÇÜ hattının dört sorusuna (iki insan değerlendirici; maliyet oranı; küçük harf farkı; indirme): **"indir; ayrıca kimse artık kod okumuyor, o yüzden sen onaylayacaksın; devam edelim."**

## Kararlar

| No | Karar | Kimin | Sonucu |
|---|---|---|---|
| A-1 | **İnsan değerlendirici aranmıyor.** "Amacı doğru ad" hükmünü model verir, ana oturum onaylar. | Berke | ÖLÇÜ planındaki insan etiket paketleri (P-Ö3, P-Ö4, P-Ö9) **model hakem paketi** olarak uygulanır: aynı 302 öğe, aynı kör düzen ve rubrik; iki bağımsız hakem (ayrı bağlam; mümkünse ayrı model ailesi), uyum (kappa) raporlanır, ayrışanları ana oturum karara bağlar. **Bu hükümler her belgede "model hükmü" diye etiketlenir; "insan doğrulaması" diye yazılmaz.** Yayımlanan ana sayı tam eşitlik ve tam + biçim kalır; "yakın ad" sayısı model hükmü etiketiyle ikincil satırdır. |
| A-2 | **Maliyet oranı L = 10:** yanlış ad, eksik adın 10 katı kötü sayılır ("yanlış ≤ %10" hedefiyle aynı anlam). | ana oturum (Berke'nin yetkisiyle) | Karar kuralı (ÖLÇÜ `BULGULAR.md` §5) L = 10 ile uygulanır: ölçülmüş kesinliğinin Wilson alt sınırı ≥ 0,909 olan kanal ad yazar; altındaki kanıt satırı yazar. |
| A-3 | **Biçim farkı doğru sayılır:** büyük / küçük harf, çakışma eki (`_2`) ve derleyici eki dışında GT ile aynı olan ad "tam + biçim" düzeyinde doğrudur. Tam eşitlik ayrıca raporlanmaya devam eder. | ana oturum (Berke'nin yetkisiyle) | P-Ö1 (`urun_olc` biçim satırı) uygulanır. Ürün tarafında asıl onarım ÖK-1'dir (adı küçük harfe çevirmemek); biçim satırı onarımın yerine geçmez. |
| A-4 | **İndirme onaylandı.** | Berke | Kapsam (ana oturumun okuması; Berke'ye bildirildi): P-Ö7 tabaka A / B paketleri ve hata ayıklama paketleri; ÖK-V'nin 24 paketi (78,0 MiB); P-Ö8'in kurayla seçilecek 10 programı (kura ve ön kayıt commit'lendikten sonra); P-Ö9 kaynak paketleri. Kaynak yalnız dağıtımların resmî arşivleri; her dosyanın sha256'sı dizinle doğrulanır; hiçbir indirilen dosya çalıştırılmaz. Toplam 2 GiB'ı aşacaksa durulur ve Berke'ye sorulur. |
| A-5 | Onuncu Adam (karşı görüş) ertelendi: Astra kotası bitti. | Berke bildirdi | Yön kararına itiraz açık kalem; kota açılınca ya da başka model ailesiyle. |
| A-6 | MCP sunucusu yapılacak (P24); bu oturumda yazılmaz. | Berke | Paket metni `docs/arge/2026-11-18_onarim/gonderim/P24.md`. |

## Sonradan eklenenler (aynı gün)

| No | Karar | Kimin | Sonucu |
|---|---|---|---|
| A-7 | **Erken yayın yok; bitiş çizgisi "her şey tam ve Berke'nin makinesine kurulu".** Berke (13:0x): "Yayın çıkmasına çok zaman var; her şey tam olduğunda yayına çıkacak. Çok dağıtılmayacak bir uygulama bu; her şeyin tam olarak hazırlanıp bana kurulması lazım." (Sabahki "biraz erkenden yayına almak istiyorum" sözünün yerine geçer.) | Berke | Paketler "yayından önce / sonra" diye ayrılmaz; sıra bağımlılık, risk ve doğrulanabilirliğe göre kurulur. `YAYIN_KAPISI.md` §2'deki "yayına bilerek girmeyecekler" listesi geçersiz: bekletilen katmanlar (P10b, P08b, P03b, K-1 / K-4 bayrakları) da tamamlanacak iştir. Son adım: uygulamanın derlenip Berke'nin makinesine kurulması ve gerçek büyük bir uygulamada uçtan uca çalışması. |
| A-8 | **Birkaç GB'lık yazılımda çalışmalı.** Berke: "Sadece 50 MB'de de olmayacak; birkaç GB'lık yazılımlarda da çalışabilmesi lazım." | Berke | ÖLÇEK planı (`olcek/`) bitiş çizgisinin parçası. |
| A-9 | **Ayarlar tek işlemciye göre yazılmaz.** Berke: "Sadece M4 Max için değil; M5 Max, M6 Max alırım; genel." | Berke | HIZ planında her değer çalışma anında algılanan donanımdan türetilir; kabul ölçütleri oranla yazılır. |
| A-10 | **Üst veri (Go, Objective-C, Swift, C++ RTTI, Mach-O `main`) okunacak.** Berke: "Bence bunları da okumalıyız." | Berke | ÜST VERİ planının bütün paketleri uygulanır; adlar `üst veriden` etiketiyle yazılır, tutarlılık denetiminin yakaladığı ad yazılmaz. |
| A-11 | Analistin kendisinin verdiği hata ayıklama dosyasından ad almak öntanımda açık; ağdan kendiliğinden indirme kapalı. Başvuru başka sürümdense ad yazılır ve "başvurunun sürümündeki ad" diye işaretlenir. | ana oturum (Berke'nin yetkisiyle) | KİMLİK planı PK-4, PK-5. |
| A-12 | **İzin bekleyen (Berke cevaplamadı):** indirilen kodu çalıştırmak gerektiren iki iş — Go derleyicisi (go.dev, 133 MB; ÜST VERİ P-ÜV9) ve kaynak paketlerinden derleme (KİMLİK V1). A-4 "indirilen dosya çalıştırılmaz" koşuluyla verildi. | — | İzin gelene kadar o ölçümler "izin bekliyor" durumunda kalır; öbür paketler etkilenmez. |

## KARŞI hattının itirazlarına verilen hükümler (ana oturum, 13:3x)

Kaynak: `karsi/KARSI.md` (İ-1 … İ-13), `karsi/CAKISMA.md`. Hat belgeleri değiştirilmedi; bu hükümler plan metinlerinin önüne geçer. Uygulayan ajan çelişki görürse bu bölüm geçerlidir.

| No | Hüküm | İtiraz | Hangi paketi değiştirir |
|---|---|---|---|
| A-13 | **Ad eşiği tek sayı: 0,909** (= L / (L + 1), L = 10). `1 − e / L` (0,900) kullanılmaz; kanıt satırının değeri (e) ölçülmediği için formüle girmez. Sabit tek yerde: `karadul/core/naming_labels.py` (bayrak ön paketi tanımlar; PK-1, P-ÜV6, ÖK-4b içe aktarır, kendi sabitini tanımlamaz). | İ-3 | bayrak ön paketi; PK-1 (`AD_ESIGI`), P-ÜV6, ÖK-4b; ÖLÇÜ karar kuralı |
| A-14 | **Sayım birimi:** her kanal iki düzeyde raporlanır (örnek ve tekil kaynak fonksiyonu). Yeni bir kanalın öntanımda ad yazması için: Wilson alt sınırı ≥ 0,909 (örnek düzeyi, yön başına) **ve** en az 3 bağımsız programda ölçülmüş olmak. Şartı sağlamayan kanal bayrak arkasında kalır ya da kanıt satırı yazar. Var olan ön ad kanalları (gnulib, ELF önyükü, `main`) set dışı ölçümler (P-Ö7, ÖK-5, hedef seti) gelene kadar ad yazmayı sürdürür; o ölçümlerle yeniden hükme bağlanır. Geriye dönük susturma yok. | İ-3, İ-12 | PK-3 / PK-4, P-ÜV6, ÖK-4b kabul ölçütleri |
| A-15 | **KİMLİK sayımı yön başına** (hedef → başvuru). `basvuru:dizgi` satırı (362, 388; Wilson alt 0,904) eşiğin altında → o alt kanal ad değil kanıt satırı yazar; yayılım aşaması (0,928) ve `derleyici` çifti (0,986–0,995) ad yazar. | İ-4 | PK-3 raporu, PK-4 adım 4 |
| A-16 | **ÖLÇÜ P-Ö3 / P-Ö4 / P-Ö9 bu hâliyle gönderilmez.** Üçü tek küçük pakete iner (P-Ö3′): yalnız T3 (ikiz: tanım gereği yanlış) ve T4 (biçim: tanım gereği doğru) tabakaları hakemin denetim öğesi; T1 / T2'de model hükmü ikincil satır, "model hükmü" etiketiyle. "İnsan–vekil kappa" hipotezi silinir (ölçülemez). `olcu/PLAN.md`'deki "İnsan etiketini model üretmez" kuralı A-1 ile kalkmıştır. | İ-5 | P-Ö3, P-Ö4, P-Ö9 |
| A-17 | **Hedef seti birinci ölçüm zemini olur.** Geliştirme setinin (119 küçük C ikilisi; toplam kod 10,4 MiB) yanına gerçek uygulamalardan kurulu hedef seti (Go / Swift / Objective-C / C++; GT sembollü ikiliden: P-ÜV8 kalem 1–3) eklenir. Her ad kanalı paketi iki sette ölçülür; 119'da beklenti "yeni yanlış 0", hedef setinde kapsam. Öncelik sırası: ÜST VERİ, ÖLÇEK, HIZ; KİMLİK ve ÖZ KOD'un ürün paketleri erken risk ölçümlerinin (PK-6, PK-11, ÖK-5) hükmüne bağlıdır. | İ-1, İ-6, İ-7, İ-8 | dalga sırası; PK-2 / 3 / 4 / 7 / 8 / 9 / 10, ÖK-3 / 4b / 6 koşullu |
| A-18 | **ÖL-10 (tembel derinlik) Opus paketi olarak bu hâliyle gönderilmez;** önce tasarım turu (seçim kuralı, kısmi analizde ad kanallarının sözleşmesi, "decompile edilmedi" sayacı, isteğe bağlı decompile komutu). ÖLÇ-1'in T100 / T300 / PAKET duvarları 8 saatten 2 saate iner; ÖLÇ-1 ile HZ-0 tek koşuda birleşir. | İ-2, İ-10 | ÖL-10, ÖLÇ-1, HZ-0 |
| A-19 | **Ortak altyapı bir kez yazılır.** (a) Bayrak ön paketi: bütün planların `karadul/config.py` alanları tek pakette, öntanımı kapalı (`CAKISMA.md` §2.1); sonraki paketler `config.py`'ye yazmaz. (b) Ortak ikili okuyucu P-ÜV0; ÖK-4a ve PK-2 onun arayüzünü kullanır. (c) Ghidra kuyruğu tek listede, ana oturum tutar. | İ-9, İ-10 | bayrak ön paketi (yeni), P-ÜV0, ÖK-4a, PK-2 |
| A-20 | P12d (dalda; 17 doğru ad geri, 4 yeni yanlış) tek başına main'e alınmaz; ÖK-1 (harf koruma) ile aynı ajanda, sırayla alınır ve birlikte ölçülür. D2'nin gerektirdiği işçi süreç düzeltmesi (D1 commit'inde) mutlaka alınır. | — | P12d, ÖK-1, ÖK-2 |

## 2026-11-20 (uygulama oturumu, Dalga 0)

| No | Karar | Kimin | Sonucu |
|---|---|---|---|
| A-21 | **Push onaylandı.** | Berke (08:1x) | Tam takım (b6aceb9: 10 289 / 0) ve son doğrulama mutasyonlarından sonra (6 / 7 tanım temiz; p20'deki tek hayatta mutant bilinen bayat tanım → MUTBAKIM), gizli anahtar / büyük dosya taraması temiz: `a62f15e..e996200` (114 commit) push edildi. |
| A-22 | **V5 indirme onaylandı** (KİMLİK PK-11). | Berke | `libzstd1_1.5.7+dfsg-1_arm64.deb` (266 052 B) + `libzstd1-dbgsym_…` (1 834 508 B), deb.debian.org; InRelease gpgv + sha256 doğrulandı; `~/karadul_olcum/n2_tabaka/kitaplik/` (künye `kitaplik_veri.json`). |
| A-23 | **A-12'nin cevabı: iki işe de izin** — Go derleyicisi (go1.26.11 + go1.27.4, go.dev) ve Debian kaynak paketlerinden yerel derleme. | Berke | Koşullar A-4'teki gibi: yalnız resmî kaynak, sha256 dizinle, ağ kapalı derleme; derleme çıktıları çalıştırılmaz, yalnız analiz edilir. V1 kaynakları indirildi (tree, libzstd, sqlite3, redis; 31,2 MB; `~/karadul_olcum/kimlik_v1/`, künye `v1_veri.json`). Go derleyicisi, onu kullanan paket (P-ÜV9 kalem 3–4) sıraya girince indirilir. redis'in `deps/lua` kodu V1 ölçümünde dışarıda kalır (lua kilitli setin stres alt kümesinde; `kimlik/PLAN.md` PK-11). |
| A-24 | **ÖL-10 tasarım turu Mythos oturumuna bırakıldı.** | Berke | Dalga 0 sekiz ajana indi (OL10 çıktı). ÖL-10 Dalga 4'ün önkoşulu olarak açık; gönderim metni `docs/arge/2026-11-20_dalga0/gonderim/OL10.md` Mythos oturumu için hazır. |
| A-25 | `AD_ESIGI = MALIYET_ORANI_L / (MALIYET_ORANI_L + 1)` (= 0,90909…); A-13'teki "0,909" bu kesrin yuvarlanmış yazımıdır. | ana oturum (Berke'nin yetkisiyle) | Bayrak ön paketi sabiti kesirle tanımlar; Wilson alt sınırı bu değerle karşılaştırılır. |
| A-26 | **Gece koşusu (ÖLÇ-1 + HZ-0) 2026-11-20 gecesi yapılmayacak; ertelendi.** | Berke (10:4x) | Ölçülecek ürün sabit: commit `be9550e` (Dalga 0'ın ürün kodu: BAYRAK + HZ1), ağaç `~/karadul_olcum/urun-be9550e` ve Avast kökü `~/karadul_olcum/runs/hiz-avast-dislama/be9550e` silinmeden durur; koşu Berke'nin izin verdiği bir gece aynı komutla (`gece_kosusu.py --commit be9550e --gece 1 / 2`) yapılır. Dalga 1'in ölçek / hız paketleri kodlarını yazabilir; "önce" sayıları bu sabit ağaçtan gelir, "sonra" ölçümleri o koşudan sonra. |

| No | Karar | Kimin | Sonucu |
|---|---|---|---|
| A-27 | **Ürün ikilide ne varsa her şeyi okur.** Berke (2026-11-20 10:5x, hedef setinde bugünkü ürünün terminal-notifier'da 40 adın 0'ını verdiği görülünce): "her şeyi okuyacak, yazılımda ne varsa her şeyi okumak zorunda." Ad, tip ya da ilişki taşıyan her kaynak (Mach-O / ELF / PE tabloları; ObjC, Swift, Go, C++ RTTI, .NET, Rust kalıntıları; ayrık hata ayıklama dosyası; …) okunur. | Berke | Okumak güvenmek değildir: üst veri adı `üst veriden` etiketiyle yazılır, tutarlılık denetiminin yakaladığı ad yazılmaz (A-10), ikili çalıştırılmaz. Yeni paket **OKUMA-ENVANTERİ**: biçim × kaynak tablosu (ürün bugün okuyor mu, hedef setinde ve 119'da kaynak başına kaç ad), öncelikli açık listesi; ÜST VERİ planı bu listeyle genişler. Öncelik: üst veri hızlı hattı (P-ÜV0 → P-ÜV1 ║ P-ÜV2 ║ P-ÜV5 → P-ÜV6); kabul ölçütü baştan gerçek uygulamada (terminal-notifier, Ollama dilimi) + 119'da yeni yanlış 0. |
| A-28 | **ObjC tam adı Ghidra'nın seçici adının yerine yazılabilir** (P13b'nin "aday yalnız Ghidra'nın adsız bıraktığı fonksiyona" kuralına üst veri istisnası): Ghidra'nın adı üst verideki seçiciyle birebir aynıysa tam ad (`-[Sınıf seçici]` / `+[…]`) yazılır, `üst veriden` etiketiyle. | ana oturum (Berke'nin yetkisiyle; A-27) | Bugünkü kuralla ObjC kanalı terminal-notifier'da 1, Ollama'da 2 ad yazabiliyordu (HEDEF, 148 / 151 yöntem Ghidra'da yalnız seçiciyle adlı). P-ÜV6 uygular ve ölçer. |
| A-29 | **ÖK-5 (kör nüfus) hükmü: ÖZ KOD'un ad kuralları bağımsız nüfusta tutmadı → ÖK-3, ÖK-4b, ÖK-6 yazılmaz.** K1-a %81,7 (Wilson %80,0–%83,4; eşik %85), G1-b %69,2 (eşik %90), modül öneki %48,4 (geliştirme setinde %83,4), R1 %79,8 (ÖK-2'nin %90 şartı tutmadı); yalnız K1-b (erişim) tuttu. | ana oturum (Berke'nin yetkisiyle; ön kayıtlı hükümler, `ozkod/OK5.md`) | K1 kesinliği ad eşiğinin (A-13, 0,909) çok altında → ÖK-4b için yeniden ön kayıt yapılmaz; kayıt çifti ÖK-4a ile yalnız kanıt satırı olarak kalabilir. ÖK-2'nin tasarımı R1 sonucuyla yeniden ele alınır (oz_ad bağımsız nüfusta %79,8 — ad mı kanıt satırı mı). ÖK-1 (harf koruma; ölçülmüş kusur onarımı) planındaki gibi kalır. Erken risk ölçümü amacına ulaştı: üç ürün paketi yazılmadan elendi. |
| A-30 | **KİMLİK erken risk ölçümleri tuttu → KİMLİK ürün paketleri (PK-2 → PK-3 → PK-4 …) açık.** PK-6 (e): aynı sürüm GCC ↔ clang 4 / 4 program Wilson alt ≥ 0,909 (gcc → clang alt 0,959); mimari (kısmi 17 / 19) alt 0,998; derleyici sürümü (kısmi 5 / 38) alt 0,944. PK-11: gömülü kitaplık 242 / 1 (alt 0,977), başvuruda olmayan koda 0 / 199 ad; kapsam %33,6 (< %40). | ana oturum (Berke'nin yetkisiyle; ön kayıtlı hükümler, `kimlik/PK-6.md`, `PK-11.md`) | Aynı çiftte bugünkü ürün yolları BinaryDiffer 34 doğru / 93 yanlış, ReferenceDiffer 175 / 116 → **PK-1 (yöntem kapısı) önceliklidir**. PK-6 (d) tree'de tutmadı → PK-4 öntanımı `TUTUCU` (ön kaydın dediği gibi; PK-4 ölçümüyle yeniden bakılır). PK-6'nın kalan 35 çifti (derleyici_surumu, tabA openssl / zstd) sonraki oturumda aynı sürücüyle. |

## A-1'in dürüst sınırı (kayıt için)

ÖLÇÜ hattı ölçtü: iki model hakemin birbirini öngörmesi 0,96–0,99. Yani iki model hakemin uyumu yüksek çıkacaktır, ama bu uyum hükmün doğru olduğunu göstermez; aynı yanılgıyı paylaşıyor olabilirler. Bu yüzden:
- model hükmüne dayanan hiçbir sayı ürünün ana başarı ölçüsü yapılmaz;
- karar kuralı (ad mı, kanıt satırı mı) yalnız tam eşitlik ve tam + biçim sayılarından beslenir;
- bir gün dış bir tersine mühendislik uzmanı bulunursa aynı 302 öğelik paket ona verilebilir (paket kalıcıdır).
