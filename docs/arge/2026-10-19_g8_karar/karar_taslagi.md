# G8 karar günü: taslak (G6 pilotu bekleniyor)

- **Tarih:** 2026-10-19 (taslak). G6 LLM pilotu bitince tamamlanacak.
- **Dayanak:** plan v2 §5 "G8 karar kuralları (ön kayıt)". Kurallar deneylerden önce yazılmıştı; eşikler düşürülmez (§7).
- **Karar sahibi:** Berke. Bu belge kuralların mekanik okumasını ve plan v2.1 için önerileri verir.

## 1. Kuralların okunması

| # | Kural (ön kayıt) | Ölçülen | Okuma |
|---|---|---|---|
| 1 | LLM pilotunda (b)−(a) ≥ 15 puan ve fark görülmemiş dilimde de sürüyor → ana sonuç "gevşek isim oranı" olmaz | G6 pilotu sürüyor | **BEKLİYOR.** Berke kararıyla G8'de geçici, G34'te kesin. Yerel model (Qwen3.8-27B); sonuç öncü modellere genellenmez |
| 2 | Geri yazma, ölçütlerin en az ikisinde anlamlı kazanç veriyor → Faz 1'in kritik yolu geri yazma hattı (G14-G15 öne alınabilir) | Üst sınır C3: 3/5 (undefined −%52, ham işaretçi aritmetiği −%50, `->` 0→11). Karadul bugün K1: 1/5 (yalnız undefined, tip adı değişiminden). K1y (Karadul yapıları yeniden bağlanınca): 2/5. Ürün kuralı K4': 2/5 (6dc79bd, d6c4bcf, be8f7eb) | **Kural tetiklendi (üst sınırda).** Ancak kazanç bugünkü Karadul bilgisiyle erişilebilir değil; "öne alınabilir" kullanılmıyor, önce yapı kurtarma |
| 3 | Alıcı tip kümeleri saf (≥ %90) ve kapsamlı → Faz 1'de tarifin nesne kaynağı bu kümeler (G16-G17) | İsim öneki saflığı tmux %77,4, htop %55,9; negatif kontrol geçti (ea498a4) | **Tutmadı.** G16-G17'nin "tarifin nesne kaynağı" kalemi bu biçimiyle düşer |
| 4 | Kör protokolde cömertlik farkı > 10 puan → v1 tabanındaki yakın oranlar geçersiz | +1,0 puan [−1,0; +3,0] (e9b9322) | **Tetiklenmedi.** Yine de v1 ve v2 sayıları birleştirilmez (rubrik değişti) |

Ek ölçüm (G8 satırı): MaxSMT ofset hatası doğrulandı (c9f3e29). tmux'ta 30 839 LOAD/STORE'un hepsinde ofset yerine adres uzayı kimliği (433) alınıyor.

## 2. Ölçülenlerden çıkan tablo

- **İsim:** Karadul bugün tmux'ta verdiği isimlerin %45,5'inde, htop'ta %81,4'ünde yanlış (hedef ≤ %10). Yakın isim tmux'ta %19,7, htop'ta %4,1.
- **Temsil:**
  - Ghidra'ya doğru yerleşimle yazılan tek yapı ham işaretçi aritmetiğini yarıya indiriyor.
  - Karadul'un bugün kurtardığı 1398 yapının hiçbiri bir fonksiyona bağlı değil. Her yapı tek fonksiyonun 2-3 alanlık parçası; c_namer'ın sayı ekleri birleştirmeyi engelliyor.
  - MaxSMT ofsetleri bütünüyle yanlış.
- **Alıcı tip kümeleri:** isim öneki için saf değil, ama kaynak tipine göre tmux'ta %99,1, htop'ta %87,1 saf (ön kayıt dışı yorum). Kümeler tipi doğru buluyor; adlar modülü izliyor.
- **Çapa kesinliği:** yayılımın kesinliği çapanın kesinliğini izliyor (bugün %39, doğru çapalarla %68, oracle ile %84). KS-1 (kendi adını yazma tespiti) yayılımdan önce gelmeli.

## 3. Plan v2.1 önerileri (Berke'nin onayına)

1. **Faz 1 sırası:** yapı kurtarma → geri yazma.
   - (a) Alıcı tip kümelerini tip ve yapı taşıyıcısı olarak kullanmak: aynı kümedeki fonksiyonların ilk parametre erişimleri tek bir yapı yerleşiminde birleştirilir. Ön koşul: DWARF'a karşı ön kayıtlı tip saflığı deneyi (Debian'daki geliştirme seti derlemeleri; tmux/htop'ta %99 görüldüğü için orada karar ölçüsü olamaz).
   - (b) MaxSMT ofset düzeltmesi G19'dan bu bloğa alınır.
   - (c) Geri yazma hattı (G14-G15) ancak doğrulanmış yerleşimler geldikten sonra; ürün kuralı: yerleşim bilinmiyorsa yalnız ad yazılır, doğrulanmış yerleşimde tip de yazılır.
2. **İsim tarafı:** G11-G12'deki KS-1 (kendi adını yazma, assert, `__func__`) yayılımdan önce kalır. Hedef çapa kesinliği ≥ %90.
3. **Ölçüm:**
   - Okunurluk ölçütlerinde havuz oranının yanında fonksiyon başına ortalama değişim de raporlanır.
   - `undefined` yoğunluğu tek başına kanıt sayılmaz (3d2365d).
4. **G13'ten önce yazılacaklar:**
   - **Program sınıfı tanımı** (§3 madde 4 ve §7 sınıf başına ölçüyor, mekanik tanım yok). Öneri: GT'siz, ikiliden hesaplanan "dizgi zenginliği", yani snake_case tanımlayıcı biçimli dizgi sayısının fonksiyon sayısına oranı. Eşik geliştirme setinden (8 program) ön kayıtla seçilir. htop ve tmux bu ölçüde iki ayrı sınıfa düşmeli (doğrulanacak). Boyut tabakası ikincil sınıf olarak raporlanır.
   - **"Kapsamlı" eşiği** (alıcı tip kümeleri için).
5. **Bekleyen:** G6 pilot sonucu (kural 1), G7 kanıt tavanı, ÖL-3 (sürüyor), ÖL-7 (pilot sonrası), nagios derlemesi (gd onayı).
