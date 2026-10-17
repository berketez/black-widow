# Karadul isimlendirme planı: gevşek mod, 8 hafta

> **Not (2026-10-17):** Bu plan v2 ile değişti: `2026-10-17_plan_v2.md`. G1 ve G2 tamamlandı; v1'in htop taban sayıları geçersiz (htop Go programı sanılıyordu, v2 §2).

- **Tarih:** 2026-10-15
- **Durum:** Plan v1. Derleyici sentez belgesi (`2026-10-15_makale/derleyici_sentez.md`) gelince v2'ye güncellenecek.
- **Karar sahibi:** Berke. Plandaki her eşik ölçümle sınanır. Tutmayan eşikte zorlamak yerine plan yeniden kurulur.

## 0. Hedef ve ölçüt

**Hedef.** Kilitli test setinde, isim bekleyen fonksiyonlar üzerinden ortalama:

| Ölçü | Hedef |
|---|---|
| Yakın isim (amacı doğru anlatan) | Model katmanı dahil **≥ %70**; LLM'siz hedef **%50**, alt sınır (kapı) **%35** |
| Tam isim (özgün adın kendisi) | **≥ %15** |
| Yanlış isim (gevşek ölçütle de yanlış) | Verilen isimlerin **≤ %10**'u |

**Ölçüt.** Her isim dört gruptan birine girer. Rehber: `scratchpad/tarif/etiket_rehberi.md`; depoya taşınacak (Hafta 1, Gün 1).

| Etiket | Anlamı | Başarı mı? |
|---|---|---|
| `tam` | Özgün ad; çakışma eki ve biçim farkı yok sayılır. | Evet (tam ve yakın) |
| `dogru_tarif` | Fiil ve nesne ana işi anlatıyor ("seramik duvar → fayans duvar"). | Evet (yakın) |
| `yalniz_alan` | Alan doğru, ana iş yok. | Hayır; isim değil yorum olarak gösterilir |
| `yanlis` | İlgisiz ya da yanıltıcı ("pencere"). | Hayır; çıkmaz |

**Payda.** İsim bekleyen fonksiyonlar, yani Ghidra'nın kendisi adlandıramadıkları. Thunk ve stub'lar hariçtir. `.cold` ve `OUTLINED_FUNCTION` parçaları ayrı bir sınıfta raporlanır. Mac kopyaları her zaman `/usr/bin/strip` ile çıkarılır; conda strip export tablosunu bıraktığı için kullanılmaz.

**Ölçüm araçları:**
- Tam isim: `score_macho.py` (Mac) ve `measure.py` (Linux).
- Yakın isim: kör etiketleme. Geliştirmede ajan etiketliyor; ajanla Claude'un uyumu 30 örnekte 29/30. Test setinde iki insan değerlendirici kullanılacak.
- Kanıt erişimi: `reach.py`.

## 1. Başlangıç (2026-10-15 ölçümleri, Mac, Apple strip)

| | İsim bekleyen | Verilen isim | Yakın | Yanlış | Tam |
|---|---|---|---|---|---|
| htop, mevcut Karadul | 597 | 101 | 4 | 65 | 0 |
| htop, tarif v0 | 597 | 43 | 21 | 2 | 0 |
| tmux, mevcut Karadul | 2561 | 871 | ≈253 (örneklem %29) | ≈357 (%41) | 105 |
| tmux, tarif v0 | 2561 | 300 (129 kesin + 171 tarif) | ≈192+ | ≈30 | 96 |

Ek bulgular:
- **Kanıt erişimi:** Doğrudan kütüphane çağrısı %41-43. Çağrı zinciriyle %75-80. Çağıranlar da eklenince %90-94.
- **Modül çıkarımı:** İki güvenilir komşu arasında kalan fonksiyonlarda modül tahmini %96-99 doğru. tmux'ta isimsiz fonksiyonların %22-25'ini kapsıyor.
- **Log mesajından isim:** tmux örnekleminde %56 yakın; diğer string kaynaklarında %26.
- **htop'un açığı:** Fonksiyonların çoğu veri tablolarındaki işaretçilerle çağrılıyor ve bu çağrılar çağrı grafiğinde görünmüyor.

## 2. Çalışma kuralları

1. **Deney döngüsü:** Her kalem hipotez → uygulama → geliştirme setinde ölçüm → karar sırasıyla ilerler. Ölçülmeyen kural ürüne girmez.
2. **Geliştirme seti:** htop, tmux; Linux tarafı için coreutils (Debian ve Ubuntu). **Test seti** kurayla kilitlenir ve Hafta 7'ye kadar açılmaz.
3. **Prototipten ürüne geçiş:** Önce `scratchpad/tarif/v0/` içinde doğrulanır, sonra yeni `karadul/reconstruction/tarif/` paketine testleriyle taşınır.
4. **Tehlikeli dosyalar:** `c_namer.py`, `stages.py` ve `config.py`'ye yalnız sıralı ve tek elden dokunulur.
5. **Commit ve ajanlar:** Her iş kalemi ayrı commit; push her seferinde sorulur. Aynı anda en fazla 4 ajan çalışır; uzun süren ajana bekçi kurulur.
6. **Takvim varsayımı:** Haftada 5 çalışma günü (G1…G40). Daha az gün varsa takvim uzar, sıra değişmez.

## 3. Haftalık plan

### Hafta 1: zemin, veri tabloları, kesin kaynaklar

| Gün | İş | Çıktı / ölçüm |
|---|---|---|
| G1 | **Test seti kurası.** 25 adaylık havuzdan alan × boyut tabakalı kurayla 15 program seçilir. Tohum, sürümler (+bN), sha256 ve BuildID yazılır, ölçüt tanımları eklenir. Belge commit edilir. **Etiket rehberi** depoya taşınır. | `docs/arge/test_seti_kilidi.md` |
| G2 | **Prototipi depoya taşı:** `karadul/reconstruction/tarif/` (`evidence`, `rules`, `propagate`, `module`) ve birim testleri. Mevcut hatta henüz bağlanmaz. | Testler yeşil; prototiple aynı sayılar |
| G3 | **M4, veri tablosu rolleri:** Mach-O `__const`/`__data` içindeki fonksiyon işaretçisi dizileri bulunur. Aynı biçimdeki tablolarda aynı sıranın aynı rolü taşıdığı varsayılır (htop sınıf tablolarında `display`, `delete`, `compare`). Rol adı + sınıf bağlamı. | htop yakın isim sayısı |
| G4 | **Kesin kaynak genişletme:** (a) Kendi adını yazma tespiti: log formatı + tanımlayıcı string + tek referans; kesinliği %74'ten %90'a çıkarmak. (b) `__assert_rtn` ilk argümanı. (c) C++ RTTI ve vtable typeinfo adları. (d) ObjC/Swift meta verisi; küçük örnek uygulamayla denenir. | Tam isim sayısı ve kesinliği |
| G5 | **Ölçüm turu:** Kör etiketleme ve rapor. | Hafta 1 sayıları |

### Hafta 2: yayılım, modül, isim biçimi

| Gün | İş | Çıktı / ölçüm |
|---|---|---|
| G6 | **Yayılım v2:** Kafes (bilinmiyor / isim / çelişki). Önce aşağıdan yukarı fiil-nesne özetleri, sonra yukarıdan aşağı bağlam. Sabit noktaya kadar sürer, sırasından bağımsızdır. Bu, mevcut çift döngü sorununa da yapısal bir çözüm olur. | Yayılımla eklenen yakın isim |
| G7 | **Modül çıkarımı v2:** Tek taraflı komşu, modül sözlüğü, Linux'ta LTO'suz GCC'nin "önce çağrılan" sıralaması için ayrı kural. Debian dbgsym ile doğrulanır. | Modül kapsamı ve doğruluğu |
| G8 | **İsim biçimi:** tek şablon (`modül_fiil_nesne`); `_2` yerine ayırt edici nesne; uzunluk sınırı; alan ipuçları yorum olarak. | Çakışma sayısı, okunabilirlik örnekleri |
| G9 | **Tutarlılık testi:** Aynı kaynak -O0 ve -O2 ile derlenir; aynı fonksiyon aynı adı alıyor mu? | Tutarlılık oranı |
| G10 | **Kapı 1:** LLM'siz **≥ %25 yakın**, yanlış **< %10**. | Karar: devam ya da yeniden plan |

### Hafta 3: Linux tarafı ve tam isim

| Gün | İş | Çıktı / ölçüm |
|---|---|---|
| G11-12 | **ARGE D1-D9:** LTO'suz gnulib yerleşimi ("önce çağrılan" sıralaması, klonlar). `measure.py compare` ile ölçülür. | Debian F1 (bugün 0,12) |
| G13 | **FLIRT/imza DB'si:** relocation'lı `.o` tabanlı seçici imzalar (Levine). Ölçerek açılır. | Kesinlik ve kapsam |
| G14 | **Bağlayıcı simülasyonu:** Statik kütüphane üye sırasından komşu fonksiyon beklentisi çıkarılır. Debian'da denenir; LTO'lu binary'lerde kapalı tutulur. | Tam isim artışı |
| G15 | **Ölçüm:** coreutils Debian ve Ubuntu ile Mac seti; tam isim oranı. | Tam isim % |

### Hafta 4: değişkenler, entegrasyon, bilinen hatalar

| Gün | İş | Çıktı / ölçüm |
|---|---|---|
| G16 | **Değişken rol isimleri:** döngü sayacı ve sonu (`i`, `len`, `end`), indirgeme (`sum`, `product`), API argüman rolleri (`buf`, `len`, `fd`, `fp`). Ölçümde DWARF konum hizalaması kullanılır; yapısal tavan ayrı raporlanır. | Değişken yakın % |
| G17 | **Tip ipuçları:** FORTIFY boyutundan `char[N]`. Zaman kalırsa ters güç azaltmayla `T a[N]`. | Örnekler |
| G18 | **Entegrasyon:** `c_namer`'a sıralı bağlama. İsim türü etiketi (kesin / tarif / ipucu / model) çıktıya ve arayüze taşınır; güven değeri ölçülmüş kesinlikten gelir. `output_formatter`'ın her isme 1.0 güven yazma hatası düzeltilir. | Uçtan uca koşu |
| G19 | **Bilinen hatalar:** kripto sahte pozitifi (değer kümesi + veri bölümü), boş çıktıda sahte başarı, elle verilen isimlerin uygulanmaması (MAJOR-1), ölü değişken adı koruması. | Hata başına test |
| G20 | **Kapı 2:** LLM'siz **≥ %35 yakın** (hedef %50), **≥ %10 tam**. | Karar |

### Hafta 5: model katmanı (çekirdek)

| Gün | İş | Çıktı / ölçüm |
|---|---|---|
| G21 | **Model seçimi:** 3 yerel aday (20-30B, MoE öncelikli). M4 Max 36 GB'ta hız ve bellek ölçülür; htop ve tmux için toplam süre çıkarılır. | Model tablosu |
| G22 | **Kanıt paketi biçimi, kör tarif istemi, bölümleme:** Bölümler çağrı ilişkisine göre kesilir. | İstem ve paket tanımı |
| G23 | **Kanıtla çapraz kontrol ve güven kalibrasyonu:** Örnek: ağ API'si çağırmayan bir fonksiyona `send_packet` önerilirse elenir. | Kalibrasyon eğrisi |
| G24 | **Ölçüm:** geliştirme setinde model dahil yakın ve yanlış oranı. | Sayılar |
| G25 | **Karar:** ürün etiketi ve gösterimi. | Karar notu |

### Hafta 6: uygulama ve arayüz

| Gün | İş | Çıktı / ölçüm |
|---|---|---|
| G26-27 | **Arayüz:** model indirme ve seçme; "kontrolü başlat" tuşu; örümcek animasyonu (yalnız gerçek duruma bağlı). | Çalışan arayüz |
| G28 | **Paketleme:** uygulama paketi (pycdc ve imzalar dahil). | `.app` |
| G29 | **Uçtan uca deneme:** htop, tmux, coreutils. | Deneme raporu |
| G30 | **Kapı 3:** model dahil **%60-70 yakın**. | Karar |

### Hafta 7: kilitli test seti ve kıyaslar

| Gün | İş | Çıktı / ölçüm |
|---|---|---|
| G31 | **Test setini aç:** 15 program, Mac + Debian. | Koşular |
| G32 | **Etiketleme:** ajanla ön etiket, iki insan değerlendiriciyle örneklem ve uyum ölçümü. | Uyum (kappa) |
| G33 | **Kıyaslar:** IDA (Free) ve Ghidra. SymGen alt örneklemi (coreutils hariç ~40 binary, 7-17 saat): isim imza DB'si açık ve kapalı iki koşu. | Kıyas tablosu |
| G34-35 | **Sonuçlar:** tablolar, hata analizi; ünlü ve az bilinen programlar ayrı raporlanır (ezber riski). | Sonuç bölümü |

### Hafta 8: makale

| Gün | İş | Çıktı / ölçüm |
|---|---|---|
| G36-38 | **Makale taslağı:** yöntem, deney, sonuç, sınırlar, şekiller. | Taslak |
| G39 | **Hoca görüşmesi paketi:** iki sayfalık özet ve tablolar. | Paket |
| G40 | **Sonraki adımlar ve hedef yer:** BAR veya benzeri. | Yol haritası |

## 4. Kapılar ve karar kuralları

| Kapı | Ölçüt | Tutmazsa |
|---|---|---|
| G10 | LLM'siz ≥ %25 yakın, < %10 yanlış | En çok kaybettiren kural sınıfı bulunur; Hafta 3 bir hafta kayar |
| G20 | LLM'siz ≥ %35 yakın, ≥ %10 tam (hedef %50) | %35 altıysa LLM'siz hedef makalede ölçülen değere çekilir ve model katmanına ağırlık verilir. %35-50 arasıysa §4.1'deki iki kaldıraçta bir hafta daha çalışılır |
| G30 | Model dahil %60-70 yakın | Model, istem ya da kanıt paketi gözden geçirilir; hedef yeniden konuşulur |

### 4.1 LLM'siz %50 için ne gerekiyor (Berke'nin hedefi, 2026-10-15)

| Kaldıraç | Bugün | Gereken |
|---|---|---|
| Alan → doğru tarif dönüşümü (nesne kaynakları: sabit argüman, modül öneki, veri tablosundaki sınıf, çağıranın nesnesi) | Tarif isimlerinin ~%40'ı yalnız alan | Yarıya inmesi: doğru tarif oranı ~%55'ten ~%75'e |
| Kapsam (yayılım v2, M4 veri tabloları, log kuralı) | İsim bekleyenlerin %10-20'si isimli | %65-70 |
| Program türü | tmux türü: log'unda kendi adı var; htop türü: fonksiyonlar tablolardan çağrılıyor | htop türünde M4 tutmazsa %50 zor |

Bu iki kaldıraç birlikte tutarsa %50'ye ulaşılır. Hangisinin ne kadar katkı verdiği her ölçüm turunda ayrı raporlanır.

## 5. Riskler

- **LLM'siz tavan düşük kalabilir.** Özgün ad bilgisi binary'de yok; tarif davranıştan gelir ve davranışın bir kısmı çağrı grafiğinde görünmez.
- **Etiketlemeyi şimdilik LLM yapıyor.** Makale için insan değerlendirmesi şart (G32).
- **Test seti sızıntısı.** Geliştirme sırasında test programlarına bakılmaz.
- **Platform farkları.** Mac, Linux ve LTO'nun etkileri farklı; ayrı raporlanır.
- **IDA erişimi.** Hesap ve lisans gerekebilir; IDA Free arm64'te sınırlı olabilir.
- **Takvim.** Haftada 5 gün varsayıldı.

## 6. Berke'nin vereceği kararlar

1. Test seti kurası: yöntem onayı (G1'den önce).
2. Haftada kaç gün çalışılacağı.
3. IDA Free hesabı (G33'ten önce).
4. Hoca seçimi (G39'dan önce).

## 7. Takip

- Her gün sonunda bu belgeye bir durum satırı eklenir ve günlük kayda yazılır.
- Kapı sonuçları hafıza kaydına işlenir: `karadul-kullanilabilirlik-2026-10-14`, `karadul-makale-hedefi`.

| Gün | Durum | Not |
|---|---|---|
| — | Plan v1 yazıldı; LLM'siz hedef %50 (kapı %35) | 2026-10-15 |
| G1 | Test seti kurası çekildi ve kilitlendi (337c4d5 → 1bc05ec); etiket rehberi depoda. İkili sabitleme ajanı çalışıyor | 2026-10-15 |
| G2 | Tarif paketi depoda (ff8abc6), 10 test, 4 mutant yakalandı; hatta bağlı değil. tmux: 386 isim + 487 ipucu; htop: 47 isim | 2026-10-15 |
