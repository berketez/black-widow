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

## A-1'in dürüst sınırı (kayıt için)

ÖLÇÜ hattı ölçtü: iki model hakemin birbirini öngörmesi 0,96–0,99. Yani iki model hakemin uyumu yüksek çıkacaktır, ama bu uyum hükmün doğru olduğunu göstermez; aynı yanılgıyı paylaşıyor olabilirler. Bu yüzden:
- model hükmüne dayanan hiçbir sayı ürünün ana başarı ölçüsü yapılmaz;
- karar kuralı (ad mı, kanıt satırı mı) yalnız tam eşitlik ve tam + biçim sayılarından beslenir;
- bir gün dış bir tersine mühendislik uzmanı bulunursa aynı 302 öğelik paket ona verilebilir (paket kalıcıdır).
