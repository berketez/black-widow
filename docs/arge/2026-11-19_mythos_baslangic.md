# Mythos oturumu: başlangıç metni (2026-11-19)

Mythos oturumunu `~/Black_Widow` içinde açınca aşağıdaki metni ilk mesaj olarak yapıştır. Oturum Claude Code dışındaysa (dosya okuyamıyorsa) şu üç dosyayı ekle: `docs/arge/2026-11-18_arge_soru_listesi.md`, `docs/arge/2026-11-19_birlesik_olcum/sonuc.md`, `docs/arge/2026-11-18_onarim/DURUM.md`.

---

Sen Karadul (Black Widow) projesinin ARGE oturumundasın. Depo: `~/Black_Widow`.

**Görev:** `docs/arge/2026-11-18_arge_soru_listesi.md` dosyasındaki sorulardan araştırma hatları seç. Seçtiğin her hat için ölçülebilir bir plan yaz. Kod yazmıyorsun. Planları Opus ekibi uygulayacak, ana oturum doğrulayacak.

**Okuma sırası** (listenin başında da var):
1. §1 ve §1.1: zemin. Birleşik 119 ölçümünün sonucu:
   - yanlış ad oranı %29,7 → %6,6;
   - program düzeyi makro yanlış %31,0;
   - doğru ad kapsamı %5,2 → %5,7.
2. `docs/arge/2026-11-19_birlesik_olcum/sonuc.md`
3. §2: bağlayıcı kurallar.
   - Motor LLM'siz.
   - Önce kesinlik.
   - K-2: ad kanalı susturulmaz; ölçülmüş kural yoksa ad yerine kanıt satırı yazar.
   - Kapsam küçültülmez.
   - Test seti dokunulmaz.
   - Değişiklikten önce ön kayıt.
   - Yaratıcılık protokolü.
4. §3 sorular ve §3.I (onarımdan doğan sorular).
5. §4 öncelik önerisi. İtiraz edebilirsin.
6. §5 plan biçimi.

**Çıktı:** `docs/arge/2026-11-19_mythos/PLANLAR.md`
- Başa iki kısa bölüm koy: "Seçilen hatlar ve neden", "Seçilmeyenler ve neden".
- Her hat §5 biçiminde olsun:
  - hipotez;
  - literatürün beklediği cevap ve aykırı öncül;
  - ölçüt, doğrulayıcı ve önceden yazılmış "tuttu / tutmadı" eşiği;
  - ön kayıt taslağı;
  - Opus ekibi için iş paketleri: paket başına dosya sahipliği, 5–8 kalem, ayrık dosya kümeleri;
  - gerekli veri ve araç (indirme gerekiyorsa liste: ad, kaynak, boyut);
  - durma ölçütü;
  - riskler.

**Berke hakkında:**
- Tersine mühendislikte uzman değil. Teknik yol ayrımlarını ona sorma. Öneri ve ölçüm yaz, karar noktalarını sade dille özetle.
- Berke'nin kendi hipotezi listede I1 (ayrıca A2 / A5): kütüphane bilgisinden rol, programın dizgisinden öğe. Ciddiye al ama ölçütle sına.

**Dikkat:**
- **Taban a62f15e.** Sonradan main'e giren paketler DURUM.md'de: P02b, P16d, P-S4, P12c, P05c, P22c ve bugün bitenler. Her planda hangi tabana göre yazdığını belirt.
- **Onarımın kalan paketleri** `docs/arge/2026-11-18_onarim/gonderim/OKU.md`'de: P10b, P08b, P03b, P23 ve yeni oz_ad onarımı. Planın bunlarla çakışıyorsa söyle.

Türkçe yaz; Türkçe karakterleri doğru kullan.
