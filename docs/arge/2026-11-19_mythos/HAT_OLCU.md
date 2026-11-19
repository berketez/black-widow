# Hat: ÖLÇÜ (B3, B4, B2, B5, G1, G2) — tur 1

Hat dizinin: `docs/arge/2026-11-19_mythos/olcu/`, betikler `scripts/arge/olcu/`, veri `~/karadul_olcum/runs/arge-2026-11-19/olcu/`. Önce `ORTAK_BRIF.md`.

## Soru

1. "Amacı doğru ad" hangi **mekanik** ölçüyle sayılır ve bu ölçü insan yargısıyla ne kadar uyuşur (B3)?
2. Bir fonksiyon için ad / ad ailesi / kanıt satırı / boş kararını hangi belirlenimci kural verir (B4, B5)?
3. Sayıların geliştirme setinin dışına ne kadar taşındığı, kilitli setlere dokunmadan nasıl ölçülür (G1, G2)?

Berke benzerliği kabul ediyor ("seramik duvar" yerine "fayans duvar" başarıdır, "pencere" başarısızlıktır). Ama ölçü tanımlanıp insan yargısıyla doğrulanmadan hiçbir "yakın ad" iddiası kabul edilmiyor; ÖZ KOD ve KİMLİK hatları bu ölçüyü bekliyor.

## Bilinenler (üstüne kur)

- Bugünkü hüküm tam eşitlik (`scripts/measurement/urun_olc.py`).
- Etiket düzeni: `docs/arge/etiket_protokolu_v2.md`, `etiket_rehberi.md`, `scripts/measurement/etiket_paketi.py`, `etiket_puan.py`.
- Var olan etiketler (hepsi tek etiketçi, bir kısmı ajan ön etiketi): P15c rubrik v2 (236 kayıt), P12b N0b kör etiketleri, `workspaces/2026-10-19_g4_etiketleme/`. Hangi sete ait olduklarını önce doğrula (ortak brif §2.3).
- İki insan değerlendirici ve kappa hâlâ yok.
- Güven tablosu: `karadul/core/naming_labels.py` `MEASURED_PRE_NAME_PRECISION` (kanalın ölçülmüş kesinliğinin Wilson alt sınırı).

## Yasak cevap (literatürün beklediği)

- "Gömme benzerliği ya da dil modeli hakem kullan."
- "Belirteç F1'i al, eşiği 0,5 koy."

## Aykırı öncüller (sına)

1. **Simetrik ölçü analisti yanıltan adı ödüllendirir.** Analistin zararını yalnız belirteç **kesinliği** ölçer (üretilen adın her belirteci doğru mu); duyarlılık ayrı bir kapsam ölçüsüdür. İnsan "amaç doğru" hükmüyle hangisi daha iyi uyuşuyor: simetrik F1 mi, asimetrik kesinlik mi?
2. **Tam eşitlik "yanlış" dediklerinin bir kısmı zaten amaçça doğrudur**, bir kısmı da (ikiz adlar) tam eşitliğe yakın görünüp amaçça yanlıştır. Taban koşusunun 119 yanlışını ve KİMLİK hattının ikizlerini bu gözle say.

## Bu turun kalemleri (sırayla)

1. **Etiket envanteri.** Kaç (üretilen ad, GT adı, insan hükmü) üçlüsü var; hangi set; kaç etiketçi; kör mü. Kullanılabilir olanları tek tabloda topla.
2. **Aday ölçüler.** Normalleştirme (büyük / küçük harf, alt çizgi, deve yazımı, sayı ekleri, derleyici ekleri) + belirteç kesinliği / duyarlılığı / F1; kısaltma ve eşanlam sözlüğü (kaynağını yaz); düzenleme uzaklığı; asimetrik belirteç kesinliği. Her ölçü için insan hükmüyle ROC / AUC. Bir etiket kümesinde ayar, öbüründe sınama; bölmeyi önce deftere yaz.
3. **Literatürle karşılaştırılabilir ölçü** (G2): fonksiyon adı kurtarma makalelerinin kullandığı belirteç ölçülerinin tam tanımı (kaynak ve tarihle; `docs/arge/2026-10-21_literatur/yontem_taramasi.md` §2.3, §3.1'den başla, web'den doğrula). Bizim nüfus tanımımızla farkı.
4. **Taban koşusunu yeniden puanla.** a62f15e'nin 1 800 adını seçilen ölçülerle (tam eşitliğin yanına) puanla; kanal başına. 119 yanlışın kaçı hangi ölçüde "yakın"?
5. **Karar kuralı taslağı** (B4, B5): dört düzeyli çıktı (ad / ad ailesi / kanıt satırı / boş) için maliyet modeli; kanalların ölçülmüş kesinliklerinden belirlenimci seçim. Yanlış adın maliyeti eksik adın kaç katı sayılırsa bugünkü kanallar hangi düzeye düşer?
6. **Set dışı ölçüm tasarımı** (G1): kilitli setlere dokunmadan tabakalı bir keşif dışı set önerisi (derleyici × mimari × iyileştirme düzeyi; ayrıca çerçeve türü). İndirme listesi: ad, kaynak, boyut. İki insan değerlendiricili etiketleme için gereken örnek sayısı (G3; aralık genişliği hedefinden hesapla).

## Çakışma notları

- Ölçüm betiklerini (`scripts/measurement/`) değiştirme; yeni ölçüyü `scripts/arge/olcu/` altında yaz. Ürüne ya da ortak ölçüm betiğine girecek her şey `PLAN.md`'de Opus paketi olarak yazılır.
- İnsan etiketi üretme ve kendi yargını "insan hükmü" diye sayma. Yeni etiket gerekiyorsa paket tasarımını yaz (kaç örnek, hangi tabaka, kör düzen); etiketlemeyi Berke'nin bulacağı değerlendiriciler yapar.
