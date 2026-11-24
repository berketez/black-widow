# GK0 — GK-0: geri kurma hattının tasarım turu ("kodu açığa çıkar, eksikleri hesapla doldur, eski hâline döndür")

Bu bir TASARIM + İLK ÖLÇÜM turudur: ürün kodu yazılmaz. Çıktın bir tasarım belgesi ve bugünkü çıktının ne kadar "geri kurulabilir" olduğunu sayan bir ölçüm betiğidir (biçim örneği: `docs/arge/2026-11-19_mythos/olcek/OL10_TASARIM.md`).

Önce oku (sırayla, baştan sona): `docs/arge/2026-11-19_mythos/KARARLAR.md` ("Berke'nin sözleri", A-1 … A-41; özellikle A-7, A-10, A-13, A-14, A-17, A-27, A-33 K-6, A-41), `docs/arge/2026-11-23_dalga1/ORTAK_D1.md` (§5, §6), `docs/arge/2026-11-20_dalga0/ORTAK_D0.md`, `docs/arge/2026-11-23_dalga1/DURUM.md` (dünkü Ollama koşusu; 24 Kasım bölümü), `docs/arge/2026-11-19_mythos/SONRAKI_OTURUM.md` (kalan plan), KaradulLM belgeleri (`grep -rl "KaradulLM" docs/ | head` ile bul: ürün tarifi, 1b kaydı, Y7 duman listesi, P22 paketleri), `karadul/lm/` (araçlar, bekçi `guard.py`, bağlam), yeniden kurma aşamasının proje kurma adımı (`project_build`; `karadul/pipeline/steps/` ve `karadul/reconstruction/` içinde bul), `docs/arge/2026-11-18_onarim/P18.md` varsa (alt sistem başlıklarındaki 36 078 çelişkili bildirim).

## Berke'nin kararı (A-41, 2026-11-24)

> "KaradulLM'e öyle bir analiz yeteneği de vermeliyiz ki, RE yaptığımız programı anlayıp eksik kısımları kendi isimlendirmeleri ile yazsa bile eski hâline dönebilsin. […] Tersine mühendislikle kodları açığa çıkarmaya çalışıp hesapla o eksikleri yerlerine koymak. İşte buydu. İstersen direkt projenin ana amacı olarak da bu şekilde düzeltebilirsin."

Projenin ana amacı budur: ikiliden **yeniden derlenebilen ve özgün programla aynı davranan** kaynak kodu çıkarmak. Motor belirlenimci hesapla kurtarabildiğini kurtarır; kalan boşlukları KaradulLM doldurur; **her dolgu bir denetleyiciden geçer** (hesap doğrular). Model adı uydurabilir — ad özgün olmayabilir — ama kod geri kurulabilir olmalı.

## Ana oturumun çerçeve hükümleri (tasarımın sabitleri)

1. **Ölçüt makinenin verdiği cevaptır:** "kodu çıkardık" demek = (a) derlenir, (b) derlenen işlev özgün ikilideki işlevle eşdeğerdir. İnsan okuması, "makul görünüyor", model özgüveni ölçüt değildir. Her düzey (dosya, işlev, program) için oran ölçülür ve raporlanır.
2. **Model önerir, hesap karar verir.** KaradulLM'in yazdığı her parça (ad, tip, bildirim, gövde düzeltmesi) ancak denetleyiciden geçerse çıktıya girer ve etiketini taşır (`model önerisi` + hangi denetimden geçtiği). Denetimden geçmeyen öneri çıktıya GİRMEZ; kanıt satırı olur. Model çıktısı hiçbir yerde "kurtarıldı" diye gösterilmez (sahte veri yasağı; A-10).
3. **Motor LLM'siz kalır.** Belirlenimci hat tek başına koşar ve tek başına ölçülür; KaradulLM katmanı isteğe bağlıdır, üstüne gelir, kendi sütununda raporlanır (2026-10-15 kararının devamı).
4. **Hedef ikili çalıştırılmaz.** Eşdeğerlik denetimi özgün ikiliyi yerel olarak ÇALIŞTIRMADAN yapılır. Adaylar (her birini değerlendir, ölçülebilirliğini ve maliyetini yaz): yeniden derlenen işlev ↔ özgün işlev için yapısal / anlamsal karşılaştırma (BSim benzerliği, CFG eşbiçimliliği, P-code düzeyinde karşılaştırma; KİMLİK hattının derleyiciler arası ölçümleri `kimlik/PK-6.md` burada taban verir), Ghidra'nın P-code öykünücüsünde yalıtılmış işlev öykünmesi (ikili çalıştırılmıyor, komutlar yorumlanıyor: bunun "çalıştırma yasağı"na girip girmediğini ayrı bir karar maddesi olarak yaz), simgesel eşdeğerlik (SMT; yalnız küçük işlevlerde). Kaynak kodu elde olan geliştirme ikililerinde (Debian paketleri; A-23) ek denetim: kendi derlediğimiz iki ikilinin karşılaştırılması.
5. **Bayt eşitliği hedef değil, üst basamaktır.** Özgün derleyici ve bayrakları bilinmeden bayt eşit yeniden derleme genelde ulaşılamaz. Basamakları tanımla (öneri: B0 sözdizimi geçerli → B1 tek başına derlenir → B2 projeyle birlikte bağlanır → B3 işlev düzeyinde eşdeğer (ölçülmüş eşikle) → B4 bayt eşit) ve her basamak için "ne zaman tuttu sayılır"ı ölçülebilir yaz.
6. **Donanımdan bağımsız, yerel:** her şey Berke'nin Mac'inde (M serisi) yerel modelle çalışır; model boyutu ve süre bütçesi tasarımın parçasıdır (A-9; KaradulLM ürün tarifi).
7. **Kapsam eklenir, var olan plan düşmez:** bu hat SONRAKI_OTURUM'daki dalgaların yanına eklenir; hangi var olan paketlerin bu hattın önkoşulu olduğunu (P18 çelişkili bildirimler, tip kurtarma, ÇA çıktı ağacı, P22 KaradulLM altyapısı, P24 MCP) açıkça bağla.

## Cevaplanacak sorular (belgenin bölümleri)

1. **Bugünkü durumun ölçümü (bu turun sayıları):** bugünkü `out/src` ne kadar derleniyor? `scripts/arge/gerikurma/derlenebilirlik.py` (yeni): var olan çıktılar üstünde (S8 tabanı `~/karadul_olcum/runs/dalga1-2026-11-23/ANA/s8_taban_534e252b` 8 ikili; dünkü Ollama çıktısı `ANA/ollama_ba_kapali/out`; salt okur) her `.c` dosyasını `clang -fsyntax-only` ile (derle, ÇALIŞTIRMA; çıktı yalnız kendi koşu kökünde) dene; say: dosya ve işlev düzeyinde geçen oran, hata sınıflarının dağılımı (ilk 20 sınıf: eksik bildirim, tip çelişkisi, `undefinedN`, Ghidra'ya özgü yapılar …), kurulan projenin (derleme dosyaları varsa) uçtan uca derlenip derlenmediği. Ollama'nın 13 159 dosyası için süre sınırı koy; gerekirse belirlenimci 1 000'lik örneklem (tohum yazılı). Bu sayılar belgenin 1. bölümüdür; ölçülemeyeni "ölçülmedi" yaz.
2. **Boşluk sınıflaması:** derlenmeyi ve eşdeğerliği engelleyen şeyler sınıf sınıf; her sınıf için "belirlenimci onarılabilir mi, model mi gerekir, hiç kurtarılamaz mı (bilgi ikilide yok)". Dil başına (C, C++, Go, ObjC, Swift) ayrı: Go / Swift / ObjC'de C sözdizimine decompile edilmiş çıktının "eski hâline dönmesi" ne demek (aynı dilde mi, C olarak mı)?
3. **Denetleyicinin tasarımı (hattın kalbi):** hüküm 4'teki adaylardan hangisi, hangi basamak için; ölçülmüş yanlış kabul / yanlış ret oranı nasıl elde edilir (kaynak kodu elde olan ikililerde: doğru kaynaktan derlenen işlev "eşdeğer", bilerek bozulmuş işlev "eşdeğer değil" diye etiketlenir → denetleyicinin kesinliği ölçülür); eşik A-13 / A-14 düzeniyle.
4. **Belirlenimci katman:** modelden önce hesapla kapatılacak boşluklar (bildirim üretimi, tip birleştirme, Ghidra artıklarının çevrilmesi …); var olan hangi adımların üstüne kurulur.
5. **KaradulLM katmanı:** modelin görevi (hangi boşluk sınıfları), girdi bağlamı (işlev, çağıranlar, kanıt satırları, derleyici hatası), döngü (öner → derle → denetle → hata iletisiyle yeniden öner; deneme sınırı ve süre bütçesi), yerel model seçimi ve bellek / süre (ölçülmüşse sayıyla, değilse "ölçülmedi"), etiket ve köken kaydı şeması, analistin onayı (K-6 ile ilişki), sahte veri bekçisi (`karadul/lm/guard.py`).
6. **Ölçüm düzeni ve ön kayıt:** geliştirme / kör / sınama bölmesi (var olan setler; kilitli setler açılmaz), basamak başına oran, model katmanının katkısı ayrı sütun, "yeni yanlış" tanımı bu hatta ne (denetleyiciden geçip aslında eşdeğer olmayan işlev).
7. **Önceki çalışmalarla ilişki:** bu fikrin bilinen akrabaları (eşleşen yeniden derleme toplulukları, yeniden çalıştırılabilirlik ölçütlü decompile modelleri, sinirsel ad kurtarma). Ağa çıkamazsın: depodaki literatür notlarından (`docs/` altında `grep -ril "DIRTY\|SymGen\|LLM4Decompile\|recompil"`) ne varsa onu yaz, kalanını "ana oturum kaynak taraması yapacak" diye işaretle. Yenilik iddiası YAZMA; yalnız konumlandır.
8. **Uygulama planı:** alt paketler (GK-A …), sıra, zincirler ve dosya sahipliği, her birinin kabul ölçütü ve ön kayıt metni, hangi paketin Opus'a (yazma) hangisinin Mythos'a (ağır mühendislik) gideceği önerisi, Ghidra / model / derleyici gereksinimi. İlk üç paket bugün yazılabilir olmalı.
9. **Riskler, dürüst sınırlar, karar listesi:** neyin ulaşılamaz olduğu (bilgi ikilide yok), en büyük üç risk, Berke / ana oturum için numaralı karar listesi (öneriyle). Proje belgelerindeki ana amaç cümlesi için metin önerisi (README'de iddia değil HEDEF olarak; ölçülen sayılarla).

## Yazabileceğin dosyalar

`docs/arge/2026-11-19_mythos/gerikurma/GERI_KURMA_TASARIM.md` (yeni dizin), `scripts/arge/gerikurma/derlenebilirlik.py`. Başka hiçbir dosyaya yazma. Koşu çıktıların `~/karadul_olcum/runs/dalga1-2026-11-23/GK0/` altında (özet `ozet/`).

## Kısıtlar

- Hiçbir hedef ikili çalıştırılmaz; derleme çıktısı (nesne dosyası) üretilse bile çalıştırılmaz. Derleyici: makinedeki `/usr/bin/clang` (sürümünü yaz); paket kurma, ağa çıkma, model indirme, başka model CLI'ı, alt ajan YOK. Yerel model çağırma (bu tur model ölçmez; yalnız tasarlar).
- Sahte veri yok: ölçmediğin her sayı "ölçülmedi" ya da "TAHMİN" (aralıklı).
- Depo herkese açık: çıktı kodundan uzun alıntı, üçüncü taraf ad listesi commit'lenmez (yalnız sayı, sınıf, kısa örnek satır).

## Sert son

Gönderim iletisinde yazılı. Belgenin son satırı tam olarak `## PAKET BİTTİ`.

## Dönüş mesajı

İlk satır bugünkü durumun sayısı: S8'in 8 ikilisinde ve Ollama'da `.c` dosyalarının yüzde kaçı tek başına derleniyor (dosya ve işlev düzeyi), en büyük üç hata sınıfı ve payları. Sonra: önerilen basamaklar ve denetleyici, alt paket listesi (ilk üçü), en büyük üç risk, karar listesi, atıf doğrulaman.
