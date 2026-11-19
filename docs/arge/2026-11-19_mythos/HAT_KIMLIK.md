# Hat: KİMLİK (A2, A4, H3, C5, E5) — tur 1

Hat dizinin: `docs/arge/2026-11-19_mythos/kimlik/`, betikler `scripts/arge/kimlik/`, veri `~/karadul_olcum/runs/arge-2026-11-19/kimlik/`. Önce `ORTAK_BRIF.md`.

## Soru

Kaynağı başka bir yerde bulunan kodun fonksiyonları (kitaplık kopyası ya da aynı programın başka bir derlemesi), **farklı** derleyici / platform / sürümle yapılmış bir başvuru derlemesinden hangi kesinlikle ve hangi kapsamda tanınır? Hedef: kesinliğin Wilson alt sınırı ≥ 0,95; bu kesinlikte kapsam ne?

Berke'nin hipotezinin birinci kolu budur: "elimizde imzalı kütüphaneler var; adı bilinmeyen fonksiyonu onlardan tanı." Bugün yalnız gnulib'de ve bu setin GT'sine bakılarak kurulmuş kurallarla çalışıyor (733 / 733, set içi).

## Bilinenler (üstüne kur)

- CFG-iso gerçek kod bankası (cat → ls / sort / expr; aynı derleyici): ham kesinlik 0,882, klon düzeltmesiyle 0,912; kalan yanlışların hepsi `quotearg_*` ↔ `*_mem` ikizleri (`docs/arge/2026-11-18_onarim/P11.md`).
- BSim: toplu sorgu öntanım (P16c); ortak depodan ad sızıntısı kapandı (P16b). BSim kanalının derlemeler arası ad kesinliği ölçülmedi.
- İmza veritabanı (şema 2, 9 092 473 ad): adsız fonksiyona verdiği adlar tam eşitlikte 0 / 208 (P11); uygulanan ad farkı 0 (P15b). Kitaplık iddiası kesinliği 0,975 ama bu içe aktarım tablosuna karşı (P08).
- FLIRT bayt imzaları bekletiliyor (P08b sırada).

## Yasak cevap (literatürün beklediği)

- "Derleyiciler arası eşleme öğrenilmiş gömme ister" (jTrans türü yöntemler) → bunu sonuç diye getirme; motor LLM'siz ve öğrenmesiz.
- "BSim'i aç, benzerlik eşiğini ayarla."

## Aykırı öncüller (sına)

1. **Çapalı yayılım yeter.** Ad vermek, milyonlarca aday içinde sıralama yapmak değildir; bilinen bir başvuru derlemesine karşı doğrulamadır. Önce tekil çapalar eşlenir (yalnız o fonksiyonda geçen dizgi, sabit, içe aktarım çağrı kümesi), sonra çağrı grafiği komşuluğunda yayılır (BinDiff türü). Öğrenme olmadan, derleyici farkına rağmen ≥ 0,95 kesinlik verir mi; hangi kapsamda?
2. **İkizler ad ailesiyle çözülür.** Ayrılamayan ikizlerde yanlış ad ya da hiç ad yerine ad ailesi (ortak önek ya da ad kümesi) yazmak kesinliği korur mu? Bu dördüncü bir çekimserlik düzeyidir (ad / ad ailesi / kanıt satırı / boş).
3. **Sürüm farkı derleyici farkından ucuzdur** (ya da tersi). Hangisi eşlemeyi daha çok bozuyor, say.

## Elde hazır doğrulayıcı (yeni indirme gerekmeden)

Aynı kaynağın iki derlemesi, iki tarafta da GT:
- `debian/tmux` ↔ `mac/tmux`, `debian/htop` ↔ `mac/htop` (Debian GCC 14 / AArch64 ELF ↔ Homebrew clang / arm64 Mach-O). İkisi de taban koşusunda analiz edilmiş.
- Debian coreutils ↔ Homebrew coreutils (P-S3b'nin Mach-O kabul seti; yerini `docs/arge/2026-11-18_onarim/PS3b.md` ve `~/karadul_olcum/runs/onarim-2026-11-18/` altından bul).
- 106 Debian coreutils ikilisi arasındaki gnulib kopyaları (aynı derleyici; kolay uç).
- `~/karadul_olcum/corpus/` (`debian-9.4-3`, `ubuntu-9.4-3ubuntu6`; mimari ve GT durumunu `manifest.json`'dan doğrula).

Bölme: yöntemin parametrelerini bir çiftte ayarla (öneri: htop), öbür çiftlerde dondurulmuş hâliyle say (tmux, coreutils). Bölmeyi sayılara bakmadan deftere yaz.

## Bu turun kalemleri (sırayla)

1. **Envanter.** Hangi çiftler var; sürüm farkı; iki tarafta da adı geçen fonksiyon sayısı (eşlemenin tavanı); ad bekleyen nüfusun ne kadarı bu tavanın içinde.
2. **Var olan yöntemlerin çıplak ölçümü** çiftlerde: BSim, CFG-iso bankası, tekil dizgi çapası. Var olan koşu çıktılarından hesaplanabiliyorsa yeni Ghidra koşusu yapma.
3. **Çapalı yayılım prototipi** (araştırma betiği; ürün kodu değil): kesinlik ↔ kapsam eğrisi, çift başına. Belirsizlik kapısı: aday tekil değilse ad verme.
4. **İkiz analizi:** ayrılamayan çiftlerin sayısı ve türü; ad ailesi düzeyinde kesinlik.
5. **Gerçek kullanım sorusu:** tanınmayan bir ikilide başvuru derlemesi nereden gelir? Seçenekleri (dağıtım dbgsym'i, kaynaktan derleme, hazır imza kümesi) maliyet ve kapsamıyla yaz. İndirme gerekiyorsa liste (ad, kaynak, boyut).
6. **A1'e katkı:** geliştirme setinin ad bekleyen nüfusunda "başka yerde kaynağı bulunan kod" payı için sayabildiğin her şey.

## Çakışma notları

- P08b (FLIRT seçici VT) onarımda sırada: planın FLIRT'e değiyorsa söyle.
- Ürün kodunu değiştirme; ürüne girecek her şey `PLAN.md`'de Opus paketi olarak yazılır.
