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

## A-1'in dürüst sınırı (kayıt için)

ÖLÇÜ hattı ölçtü: iki model hakemin birbirini öngörmesi 0,96–0,99. Yani iki model hakemin uyumu yüksek çıkacaktır, ama bu uyum hükmün doğru olduğunu göstermez; aynı yanılgıyı paylaşıyor olabilirler. Bu yüzden:
- model hükmüne dayanan hiçbir sayı ürünün ana başarı ölçüsü yapılmaz;
- karar kuralı (ad mı, kanıt satırı mı) yalnız tam eşitlik ve tam + biçim sayılarından beslenir;
- bir gün dış bir tersine mühendislik uzmanı bulunursa aynı 302 öğelik paket ona verilebilir (paket kalıcıdır).
