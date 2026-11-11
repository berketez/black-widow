# N4 v2 (TASLAK): ad yerine ölçülebilir davranış satırı

- **Tarih:** 2026-11-11. **Depo:** `main`, HEAD `93a2956`. Ürün kodu yok; commit yok.
- **Durum:** Taslak. Yalnız tasarım ve GT'siz ateşleme sayımı. **Kesinlik ölçülmedi.** GT dosyaları, kilitli setler ve `macho_score.json` açılmadı; Karadul ve Ghidra koşulmadı; başka model ya da alt ajan çağrılmadı.
- **Yön (Berke, 2026-11-11):** adı verilemeyen fonksiyon için arayüzde bir fonksiyon kartı olacak; araştırmacı işi kanıttan anlayacak. Ad zorunlu değil.
- **Dayanak (dünkü belgeler; değiştirilmedi):** `2026-11-10_n4/fiil_onkayit_taslak.md` (v1), `onuncu_adam.md`, `fiil_tavani.md`, `on_olcum_gt_siz.md`, `tablo_yuvasi_sayim.md`; `2026-11-10_n1_adim3/urun_olcumu_taban.md`; `2026-10-21_plan_v2_2.md`.
- **İşaretler:** **[hesap]** çıktı sayılarından aritmetik. **[okuma]** decompile metninin elle okunmasıyla verilen yargı; GT değildir. **[tahmin]** ölçülmemiş varsayım. **[seçim]** karara bağlanacak madde; öneri değildir, gerekçesiyle seçenektir.
- Bu belgede program fonksiyonu adı ve adres yoktur. Kütüphane (import) adları ve sözlük v0'ın sınıf adları geçer.

**Dosyalar** (hepsi `docs/arge/2026-11-11_n4_v2/`):

| Dosya | İçerik | sha256 (ilk 16) |
|---|---|---|
| `taslak.md` | bu belge | — |
| `on_sayim_v2.py` | GT'siz ateşleme sayımı; dünkü `on_sayim.py` ve `tablo_yuvasi_sayim.py`'yi içe aktarır | `2b2ccfed273261c9` |
| `on_sayim_v2.json` | bütün sayılar; tanımlar künyede | `571c5d7a50140103` |
| `on_sayim_v2.md` | betiğin ürettiği tablolar (birim başına; iki nüfus) | `d9256b631c32fb04` |

**Yeniden üretim** (depo kökünden; makine yüküne göre 2-4 dk, 2 süreç):

```
python3 -I -B docs/arge/2026-11-11_n4_v2/on_sayim_v2.py --oz-sinama
python3 -I -B docs/arge/2026-11-11_n4_v2/on_sayim_v2.py \
    --mac-kosu workspaces/olcum_mac/runs/ol7-c-b7faeac --debian-kosu ~/karadul_olcum/n1_debian13 \
    --yeni-kosu ~/karadul_olcum/runs/urun-yeni-93a2956 \
    --cikti docs/arge/2026-11-11_n4_v2/on_sayim_v2.json --md docs/arge/2026-11-11_n4_v2/on_sayim_v2.md
```

- Dünkü sayaçları aynen yeniden üretmek için aynı komuta `--giris-duzeltmesi-kapali` eklenir (§5.4).
- **`adsiz` nüfusu koşu anına bağlıdır:** yeni ürün koşusu bu sayım yapılırken 119 ikilinin 16'sında bitmişti (iki Mac ikilisi dahil). Koşu bitince aynı komut yeniden çalıştırılmalıdır; `jenerik` nüfusun sayıları değişmez.

**Çalışma kuralları: uygulandı mı?**

| Kural | Uygulandı mı |
|---|---|
| 1. Denetlenebilirlik | Evet. Altı ailenin her biri bir önermeye ve bir mekanik sınama yoluna bağlı (§4). Mekanik sınaması olmayan altı satır "yön gösterici" listesinde, ana öneride değil (§4.8). Bir sınama yolu bugün çalıştırıldı (A5'in p-code çapraz denetimi) ve dünkü betikte iki hata buldu (§5.4) |
| 2. Uzlaşıyı bilerek kır | Evet. Model ya da öğrenilmiş tahmin ve yeni dizgi sezgiseli yok; hiçbir aile dizgi içeriği okumuyor. Üç aykırı öncülün tuttuğu ve bozulduğu yerler sayılarla §3'te. Farklı model ailesi ve Onuncu Adam kullanılmadı (bu görevde yasaktı); yön kararından önce yapılması gerekir |
| 3. Tek hatta kal, olumsuzları taşı | Evet. Dünkü yirmi bulgu "v1'de ne denendi, neden olmadı, v2'de ne değişti" tablosunda (§2). Yeni konu açılmadı; tablo yuvası yalnız örtüşme için sayıldı |
| 4. Seçimi model yapmaz | Evet. Aileler kapsam üst sınırı ve sınama maliyetiyle sıralandı, seçilmedi (§9.1). Hedef için altı seçenek, öneri değil (§8). Dış uzmana üç soru §9.2'de; Berke'nin kararları §9.3'te |

## 0. Kısa sonuç

1. **Altı aile, adsız fonksiyonların %74,4'üne (havuz) ve %82,5'ine (iki Mac ikilisi) en az bir satır yazabiliyor.** Bu, tanımların ateşleme payıdır; doğru satır payı değildir.
   - Birleşimin büyük kısmı iki "kısmi" aileden gelir: A3 (parametre üstünden alan erişimi) ve A4 (global değişken). A3 ve A5 çıkarılınca pay %44,0 / %35,3'e iner.
   - Fiil sınıfı taşıyan satırlar (A1 ∪ A2) küçüktür: havuzda %5,1, Mac'te %11,6 **[hesap]**. Dünkü fiil tavanıyla aynı büyüklükte; "%75 doğru fiil" bu çerçevede de erişilemez.
2. **Öncül 1 (nesne fiilden çok şey söyler) kapsamda tuttu, bilgide yarım kaldı.** Nesne satırları fiilin ulaşamadığı I sınıfının (yalnız iç çağrı yapan) Mac'te %62,8'ine ulaşıyor. Ama satır nesneyi adlandıramıyor; yalnız ofset ve adres veriyor.
3. **Öncül 2 (`get`/`set`/`is`/`init` davranıştan en kolay tanınır) bozuldu.** Dar tanımla Mac tmux'ta 102, Mac htop'ta 16 fonksiyon ateşliyor. Dün yayımlanan sayıya göre bu dört sınıfı taşıyan gerçek ad 369 ve 145'tir; dar biçim bunların en çok %27,6'sı ve %11,0'ı olabilir **[hesap]**.
4. **Öncül 3 (ad yerine sözleşme) koddan doğrulanabiliyor ama dar.** Evrensel iddia (yan etkisiz; yalnız parametreye yazar; hiç dönmez) adsızların %13,7'sinde (Mac %18,3) kanıtlanabiliyor. İkinci, bağımsız türetimle (Ghidra p-code'u) çapraz denetim bugün çalıştırıldı: üç iddiada 0 / 2 773 uyuşmazlık, "hiç dönmez"de 51 / 434.
5. **Aynı denetim dünkü `on_sayim.py`'de iki hata buldu** (§5.4). Dünkü "hiç dönmeyen 1 095 fonksiyon" sayısı düzeltmelerle 434'e iniyor (düzeltmeden önce 1 095'in 702'sinde p-code gerçek bir dönüş gösteriyordu); dünkü Debian FK3 ve dönmez sayıları şişkindir. Mac sayıları birinci hatadan etkilenmedi; ikincisi Mac tmux'ta 22 fonksiyonu etkiliyor.
6. **Karar gerekenler:** hedefin ne olacağı (§8), hangi ailelerin ön kayda gireceği (§9.1), eşikler ve Mac'te DWARF olmaması (§9.3).

## 1. Çerçeve

### 1.1 Davranış satırı

- **Satır** bir ad değildir; fonksiyon `FUN_` kalır. Satır şunları taşır: kural kimliği ve sürümü, sınıf, somut değerler (parametre sırası, ofset, adres, kütüphane adı, sayı), kanıt adresleri, doğrulama etiketi (§7.5).
- Satır metni şablondan üretilir. Şablona serbest metin, dizgi içeriği ve tahmin edilmiş ad girmez.

### 1.2 İki tür satır

| Tür | Önermenin biçimi | Aileler | Gerçek adın fiiliyle karşılaştırılır mı |
|---|---|---|---|
| **Bütüncül** | Fonksiyonun bütün yolları ve bütün etkileri üstüne evrensel önerme ("başka etkisi yok") | A1, A5, A6; A2'nin "söküm" satırı | Evet: "asıl iş" iddiası taşır |
| **Kısmi** | Varlık önermesi ("şuna dokunur", "şunu bırakır") | A3, A4; A2'nin "bırakır" ve "taze nesne" satırları | Hayır: fonksiyonun asıl işi olmayabilir. Koda ya da DWARF'a karşı sınanır |

- Bu ayrım dünkü iki hatanın ortak nedenidir: v1 kısmi kanıttan (dönüş 0/1; iki alana sabit yazılıyor) bütüncül sonuç (`is`, `init`) çıkarıyordu.
- "Doğru ama işe yaramaz" tehlikesi iki türde ayrı ölçülür: bütüncül satırda gerçek fiille uyum, kısmi satırda ayırt edicilik (§7.2).

### 1.3 Üç ölçü

1. **Doğruluk:** satır, mekanik bir doğrulayıcıya karşı doğru mu (§4, §7).
2. **Kapsam:** adsız fonksiyonların kaçında satır çıkıyor. GT gerektirmez; bu belgede sayıldı (§5).
3. **Ayırt edicilik:** satır fonksiyonu öbürlerinden ayırıyor mu; kartı okuyana yeni bilgi veriyor mu (§7.2).

### 1.4 Taban satır (aile değil)

Ana yolda çağrılan kütüphane fonksiyonlarının listesi her araçta vardır ve kartın tabanıdır. N4 v2 onu aile saymaz. Kart envanteri ayrı bir çalışmadadır (`docs/arge/2026-11-11_fonksiyon_karti/envanter.md`; bu taslak yazılırken yalnız başlıkları görüldü).

### 1.5 Satırın ikinci okuru: KaradulLM

Bugünkü kullanıcı kararı (ana oturumun iletisi): adı kurtarılamayan fonksiyonlarda asıl dayanak KaradulLM (araç kullanan yerel model ajanı) olacak. Bu belgedeki satır aileleri hem fonksiyon kartının satırıdır hem de modelin okuyacağı araç çıktısıdır. Tasarım bundan iki şey alır, kapsam genişlemez: satır yapılı kayıt olarak üretilir (§1.1; serbest metin değil) ve doğrulama etiketini taşır; yanlış bir evrensel iddia ("yan etkisiz") modeli de araştırmacıyı da aynı yöne yanıltacağı için §7'deki doğruluk eşikleri kapsam hedefinden önce gelir. Motor LLM'siz kalır: satırlar belirlenimci kurallardan çıkar; modelin satırları nasıl kullanacağı bu taslağın konusu değildir.

## 2. v1'de ne denendi, neden olmadı, v2'de ne değişti

| # | Dünkü bulgu (kaynak) | v1'de ne denendi | Neden olmadı | v2'de ne değişti |
|---|---|---|---|---|
| 1 | Fiil tavanı: ilk sürümün üç ailesi kusursuz çalışsa doğru fiil sınıfı Mac tmux %6,8-11,1, Mac htop %17,6-20,6 (`fiil_tavani.md:117-118`) | Ad = fiil + nesne; hedef %75 doğru fiil | Tavan hedefin çok altında | Hedef satır başına doğruluk ve kapsam; fiil yalnız bütüncül satırların (A1, A2) ikincil sınaması. A1 ∪ A2 ateşlemesi Mac'te %11,6, havuzda %5,1: aynı büyüklük |
| 2 | Gerçek adların tek sözlük sınıfı taşıyan payı %62,3 / %70,9 (`:129`) | Başvuru = addaki sözlük fiili | Sözlüğün tamamı bile %75'in altında | Kısmi satırlar (A3, A4) ve A5, A6 fiil başvurusu kullanmaz |
| 3 | Gerçek fiillerin çoğu `get`, `set`, `is`, `init`; ilk sürüm bunları vermiyor (`:132-134`, `:435-440`) | "Ölçüm adayı" olarak ertelendi (v1 `:295`, `:315`) | İki günlük süre; adları genel nesneli (B4) olacaktı ve rubrik kararı açıktı (v1 `:239-240`); `is` için iç çelişki (`:399` ↔ `:295`) | A1 dar tanımla sayıldı: havuzda 589 (%2,6). Öncül 2 bozuldu (§3.2) |
| 4 | Elle denetimde fiil çıkarımı %25,7 yanlış sınıflıyor (`:187`) | M1: fiil uyumu öldürme ölçütü | Başvuru gürültülü | Fiil uyumu tek başına aile öldürmez; yalnız "karşıt sınıf" oranı öldürür (§7.4). Dört aile fiilsiz sınanır |
| 5 | `is` kuralının 1 082 ateşlemesinin %72'si "başarıda 1 dön" deyimi; okunan 19'un 13'ü yanlış (`on_olcum_gt_siz.md:37`, `:138`) | Dönüş 0/1 ve doğrudan saklama yok → `is` | İş çağrının içinde; dönüş durum kodu | A1 yüklem: çağrı yok ve dönüş sabit değil → 268 (dünkü 1 082'nin %24,8'i **[hesap]**). "Durum kodu döner" satırı yön gösterici (§4.8) |
| 6 | `create` dar tanımla 119 ELF'te 0; geniş FK1 ile 314 (`:38`, `:102`) | FK1 "tek hedefe inen" sarmalayıcı | Ayırıcı sarmalayıcısı iki hedef çağırır (ayırıcı + hata bildirimi) | A6 kütüphane sarmalayıcısı hata ailesini çekirdek dışı sayar ve her kütüphane fonksiyonu için geçerlidir: 1 524 (982'si ayırıcı). A2 "taze nesne" dünkü geniş tanımdır |
| 7 | `create` geniş: okunan 10'un 3'ü "okuyup yeni dizgi dönen" (`:237`) | — | Dönen nesneyi kimin kurduğu işi söylemez | Değişmedi; A2 "taze nesne" kısmi satır sayılır, gerçek fiille uyumu ön kayıtta ayrı okunur. Risk sürüyor |
| 8 | `destroy`: okunan 18'in 16'sı gerçek yıkıcı; kalıp 3'ün geniş tanımı yıkıcının kendisini tarif ediyor (`:241`, `:240`) | Kalıp 3 koruma adayı | Koruma olarak kullanılsa kuralın hemen hepsini eler | A2 "bırakır" dünkü kural, aynen. "Her yolda" alt sayacı eklendi (215 / 288). Argümanını tüketen geri çağrı için dar koruma **yazılmadı** |
| 9 | `init`: kalıp 2 ∩ `init` okunan 10'un 10'unda yanlış; büyük gövdelerde yoğun (`:230`, `:182`) | Parametrenin iki ofsetine sabit → `init` | Büyük gövdede her işin yan ürünü | `init` aile satırı değil. Yaprak biçimi A1 "çok alan yazar" (63). "Alanı bırakıp sıfırlar" ayrı: geniş 77, okunan 4'ün 4'ü büyük fonksiyon; dar "söküm" 6 |
| 10 | FK3 dar; `return -1` yolunda bırakma hiç yok (`:39`, `:233`) | Hata yolu = dönmeyen çağrıya ulaşan blok | Mac'te az fonksiyonda çalışıyor | A6'da hata ailesi çekirdek dışı; A5'te "hiç dönmez" ayrı satır. Dünkü Debian FK3 ve dönmez sayıları bir hata yüzünden şişkin (§5.4) |
| 11 | B4 adları ikilide tekil değil: Mac htop'ta 0 / 72 (`:33`, `:206`) | `free_object`, `get_field` | Yüz fonksiyon aynı adı taşır | Satır ad değil; nesne somut değerdir (ofset, adres). Ayırt edicilik ayrı ölçü (§7.2) |
| 12 | M1 temsil: export nüfusu ad bekleyenleri temsil etmiyor; tmux türünde öldürme dayanağı olamaz (`:34`, `:302-309`) | Export adlarıyla fiil uyumu | Nüfus, derleyici ve kolay vaka yoğunluğu farklı | Sınama export'a değil: koda (ikinci türetim), DWARF'a ve ad bekleyen nüfusun kendi gerçek adına (ayrı oturum) |
| 13 | Onuncu Adam İ1: fiil K ∪ Y'ye sıkışık; I sınıfı (%47,2 / %44,4) kapalı (`onuncu_adam.md:13-16`) | Üç aile çağrı ve yan etkiden | I sınıfında kütüphane çağrısı yok | A3, A4 ve A6 I sınıfına ulaşıyor: Mac'te I sınıfının %81,6'sı en az bir satır alıyor (A3 %62,8, A6 %18,9, A4 %13,8) |
| 14 | Onuncu Adam İ2: korumalar C deyimlerini görmüyor; M1 "farklı" sonucu saymıyor (`:17-20`, `:107-114`) | Dokuz koruma | Kalıp 1, 2, 4 karşıt çift değil | Bütüncül satırlar evrensel koşulla tanımlı (çağrı yok; bütün çağrılar şu kümede). Ön kayıtta sınıf × gerçek fiil çapraz tablosunun tamamı raporlanır (§7.3) |
| 15 | Onuncu Adam İ3: htop türünde tablo yuvası dışarıda (`:21-23`); dünkü sayım: üst sınır Mac tmux %10,6, Debian tmux %13,4, Mac htop %3,0 (`tablo_yuvasi_sayim.md:18`) | Tablo yuvası N4 dışı | — | Aile yapılmadı; örtüşmesi sayıldı (§6). Tablo kanıtlı adsızların Mac'te %26,4'ü, havuzda %42,5'i hiçbir aileden satır almıyor **[hesap]** |
| 16 | Tablo tanımı: adım 8 baytlık "tablolar" yöntem yuvası; elle okunan 19'un 19'u (`:31`) | — | — | Değişmedi; dünkü tanım aynen kullanıldı |
| 17 | Dizgi kanalları: ürün taban ölçümünde susan grubun %99,7'si yanlış (`urun_olcumu_taban.md:74`) | Dizgi fiil kaynağı değil | — | Hiçbir aile dizgi içeriği okumaz. A4 dizgi adreslerini dışlar |
| 18 | Tip kümesinden nesne adı %1,6 doğru (`plan_v2_2.md:38`) | Nesne tip kümesinden alınmaz | — | A3 nesneyi adlandırmaz; parametre sırası ve ofset verir. Aynı yapıyı paylaşan fonksiyonları gruplamak tip birleştirme (T3) ister: yön gösterici |
| 19 | Ürün taban ölçümü: verilen adların %81,5'i yanlış (`urun_olcumu_taban.md:13`) | — | — | Kart yönünün gerekçesi; satırda ad yok |
| 20 | Onuncu Adam §8.4: taslakta dört iç çelişki (`:165-169`) | — | — | Aile ↔ alt satır ↔ sayaç tek tabloda (`on_sayim_v2.json` → `kunye.aileler`, `kunye.tanimlar`); aile bayrağı alt satırların birleşimidir |

## 3. Üç aykırı öncül: nerede tuttu, nerede bozuldu

Sayılar `adsiz` nüfustandır (havuz 23 088; iki Mac ikilisi 2 789). Dünkü GT'li sayılarla karşılaştırmalar `jenerik` nüfusla yapılır (o sayılar bütün `FUN_` nüfusundandı); yeri belirtilir.

### 3.1 Ö1: "Fiil adın en az bilgi taşıyan parçasıdır; nesne daha çok şey söyler"

**Yürüyüş:** A3 (parametre üstünden hangi ofsetler okunuyor, yazılıyor) ve A4 (hangi global adrese dokunuluyor, başka kim dokunuyor).

**Tuttuğu yer:**
- A3 ∪ A4 adsızların %53,3'ünde (havuz), %70,1'inde (Mac) ateşliyor **[hesap]**. Fiil sınıfı taşıyan A1 ∪ A2: %5,1 ve %11,6.
- Fiilin giremediği I sınıfı: Mac'te A3 %62,8, A4 %13,8; havuzda %35,1 ve %23,7.
- Globalde paylaşım kesin hesaplanıyor: A4 ateşleyen fonksiyonların %92,0'ında (havuz 5 189 / 5 643) aynı adrese başka bir fonksiyon da başvuruyor **[hesap]**.

**Bozulduğu yer:**
1. **Satır nesneyi adlandıramıyor.** "param_1 + 0x18" bir ad değildir. Nesne adının tip kümesinden gelmediği ölçülmüştü (%1,6). Alan satırı ancak "aynı yapıya dokunan öbür fonksiyonlar" ile birlikte bilgi taşır; o gruplama tip birleştirme ister ve bugün yok.
2. **Düşük bilgili ateşlemeler.** Herhangi bir alan erişimi %46,1 (havuz); yalnız ofset 0 olanlar çıkarılınca %31,5; aynı parametreden en az iki ofset %23,5. Mac'te %73,4 / %61,8 / %38,7. Aile bayrağı ortadaki düzeydir **[seçim]**.
3. **Kütüphane istemcisi programlarda zayıf.** openssl'de A3 %10,1: nesneler kütüphanenin opak tutamaçlarıdır, program alanlarına dokunmaz.
4. **Kısmi satır asıl işi söylemez.** Büyük bir fonksiyon onlarca alana ve birkaç globale dokunur. Bu yüzden A3 ve A4 gerçek fiille karşılaştırılamaz.
5. **Globalde paylaşım tam adres eşitliğiyle.** Aynı değişkenin iki ayrı alanına dokunan iki fonksiyon "paylaşmıyor" görünür; değişken sınırları DWARF'sız bilinmiyor. Paylaşım sayısı alt kestirimdir; "aynı değişken" iddiası sınanmadı.
6. **coreutils ağırlığı.** A4'ün havuz payının büyük kısmı coreutils'tendir (%33,0; 106 ELF'te yinelenen yardımcı kütüphane globalleri). Mac'te A4 %14,4.

### 3.2 Ö2: "`get`, `set`, `is`, `init` davranıştan en kolay tanınan sınıflar olmalı"

**Yürüyüş:** A1, yalnız çağrısız fonksiyonlarda, dört dar biçim: tek alan döndürür; tek alana yazar; birden çok alana sabit ya da parametre yazar; yan etkisiz ve sabit olmayan 0/1 döndürür.

**İlk taslak onları neden dışarıda bıraktı** (v1 belgesinden):
- süre: iki gün, üç aile (v1 `:315`, `:607`);
- üretecekleri adlar genel nesneli (B4) olacaktı ve rubriğin bu biçimi nasıl sayacağı karara bağlanmamıştı (`:239-240`);
- `is` bir yerde "ilk sürümde", başka yerde "ölçüm adayı" yazıyordu (`:399` ↔ `:295`).

**`is` neden %72 yanlış deyime ateşledi:** kural yalnız dönüş değerinin kümesine ({0, 1}) ve fonksiyonun kendi saklama komutuna bakıyordu. C'de "işi çağrıda yap, durum kodu dön" deyimi aynı kümeyi verir.

**Daraltılmış tanım neyi kurtarıyor:**

| (üç sütun da `jenerik` nüfus) | Havuz | Mac tmux | Mac htop | Kaynak |
|---|---:|---:|---:|---|
| v1 `is` ateşlemesi (dünkü betikle) | 1 082 | 124 | 20 | `on_olcum_gt_siz.md:102` |
| … çağrısız kısmı (dün okunmadı) | 303 | 42 | 11 | `:162` |
| A1 yüklem (çağrısız, sabit olmayan dönüş) | 268 | 38 | 4 | bu sayım |
| gevşetme: yalnız salt okur kütüphane çağrılı yüklem | 59 | 7 | 1 | bu sayım |
| A1 tek alan döndürür / tek alana yazar / çok alana yazar | 196 / 62 / 63 | 45 / 10 / 9 | 2 / 4 / 6 | bu sayım |
| **A1 toplam** | 589 (%2,5) | 102 (%3,9) | 16 (%2,7) | bu sayım |
| Gerçek adı `get`, `set`, `is` ya da `init` sınıfında olan (dün yayımlandı) | — | 369 (%14,3) | 145 (%24,3) | `fiil_tavani.md:435-440` **[hesap]** |

- Okunan 22 A1 örneğinin hepsinde satırın koddan söylediği doğru **[okuma]**. Sınıf adı ikisinde uymuyor: "çok alana yazar" örneklerinden ikisi (aynı gövde, iki ELF) bir arabelleğe karakter yazan biçimleyici; işi `set` ya da `init` değil.

**Bozulduğu yer:**
1. **Kapsam.** A1'in her ateşlemesi doğru sınıfta olsa bile, bu dört sınıfı taşıyan gerçek adların en çok %27,6'sına (Mac tmux) ve %11,0'ına (Mac htop) ulaşır **[hesap: 102 / 369, 16 / 145]**. Üst sınırdır; ateşleyenlerin o adlardan olduğu ölçülmedi.
2. **Neden:** adı `get` ya da `set` olan fonksiyonların çoğu yalın erişimci değildir. A1 tanım gereği yalnız çağrısız fonksiyonlardadır. Dün yayımlanan dağılımda tek sınıflı adların Mac tmux'ta %47,9'u, Mac htop'ta %46,8'i I sınıfındadır (`fiil_tavani.md:136`). Yalın erişimcilerin derleyici tarafından çağıranına gömüldüğü ve ayrı fonksiyon olarak kalmadığı **[tahmin]**; ölçülmedi.
3. **Örneklem.** Mac htop'ta A1 16 fonksiyon; hiçbir alt satır tek başına "yanlış ≤ %10" için gereken 35'e ulaşmıyor (`plan_v2_2.md:69`).

**Sonuç:** öncülün "en sık" kısmı doğru, "en kolay tanınan" kısmı yanlış. Dar tanım yanlış deyimi kurtarıyor ama ortaya küçük bir aile çıkıyor.

### 3.3 Ö3: "Ad yerine sözleşme: girdi, çıktı ve yan etki özeti koddan doğrulanabilir"

**Yürüyüş:** A5 (evrensel iddialar) ve A6 (tek hedefi saran ya da tek hedefe ileten fonksiyon).

**Mekanik doğrulayıcı ne olur:**
1. **İkinci, bağımsız türetim.** Aynı önerme Ghidra decompiler'ının yüksek p-code'undan yeniden türetilir; iki türetimin ayrıştığı her fonksiyon uyuşmazlıktır. Bugün A5 için çalıştırıldı (§5.3).
2. **DWARF** (Debian): "parametre i üstünden yazar" iddiası `const T *` parametreyle çelişemez; "hiç dönmez" `DW_AT_noreturn` ile karşılaştırılır. **Yazılmadı.**
3. **Öykünme:** rastgele girdiyle koşturulan fonksiyonda yığın dışı yazma gözlenirse "yan etkisiz" iddiası çürür. **Yazılmadı.**

**Tuttuğu yer:**
- A5 adsızların %13,7'sinde (havuz), %18,3'ünde (Mac) evrensel bir iddia kanıtlıyor: yan etkisiz, yerel kanıt %7,4 / %9,4; yan etkisiz, çağrı grafından geçişli kanıt %2,3 / %3,7; yalnız parametreye yazar %2,2 / %4,4; hiç dönmez %1,8 / %0,8.
- A6 adsızların %22,9'unda (havuz), %11,0'ında (Mac). İnce iç iletici I sınıfına ulaşıyor: Mac'te I sınıfının %18,9'u.
- Çapraz denetim: yan etkisiz (yerel) 0 / 1 722, yan etkisiz (geçişli) 0 / 536, yalnız parametreye yazar 0 / 515 uyuşmazlık (`jenerik`).

**Bozulduğu yer:**
1. **Evrensel iddia çoğu fonksiyonda kanıtlanamıyor.** Kütüphane çağıran fonksiyonda çağrının etkisi bilinmeli; bilinen "salt okur" listesi 22 addır. K sınıfında A5 %5,7 (havuz 701 / 12 215) **[hesap]**.
2. **Kanıtlanamayan yerde özet varlık bildirimine iner** ve ayırt etmez. (Dönüş türü, yazma türü, çağrı türü) üçlüsünün en sık değeri bir ikilideki fonksiyonların ortalama %17,3'ünü (Mac %14,5) kaplıyor; dağılımın entropisi 5,1 bit (133 farklı üçlü).
3. **"Doğru ama işe yaramaz" somut örnekleri:** yan etkisiz (yerel) içinde sabit dönen ya da boş 113 fonksiyon; okunan geçişli örneklerden biri derleyicinin kayan nokta yardımcısı **[okuma]**.
4. **"Hiç dönmez" iki türetimde ayrışıyor:** 51 / 434 (coreutils 25, redis-tools 26; Mac 0 / 23). Okunan 5 örneğin 5'inde fonksiyon, bu sayımın dönmez saydığı bir iç fonksiyonu çağırıp bitiyor; Ghidra o çağrıdan sonra dönüş gösteriyor **[okuma]**. Hangi türetimin yanlış olduğu kanıtlanmadı.
5. **A6 coreutils'e bağlı.** Havuzdaki 5 277 ateşlemenin 4 428'i coreutils'ten (aynı yardımcı sarmalayıcılar 106 ELF'te). Program makrosu %10,7.

**"Doğru ama işe yaramaz" olmaktan nasıl kurtulur** (ön kayda girecek ölçüler, §7.2):
- bütüncül satır gerçek adın fiiliyle çelişmemeli: "yan etkisiz" iddiası alan fonksiyonun gerçek fiili değiştiren bir sınıftaysa çelişkidir (liste: `onuncu_adam.md:162`);
- A6'da sarılan kütüphane adı gerçek adın içinde geçiyor mu (mekanik alt dizgi sınaması);
- değeri ikilide çok yaygın olan satır kartın başlığına değil ayrıntı bölümüne yazılır; eşiği **[seçim]**.

## 4. Önerilen satır aileleri

Kesin tanımlar `on_sayim_v2.json` → `kunye.tanimlar` içindedir. Zemin dünkü veri akışıdır (gömülü AArch64 disassembly; değerler: parametre, sabit, 0/1, çağrı dönüşü, parametre alanı, yığın adresi, bilinmez) ve bugünkü iki düzeltme (§5.4).

### 4.1 Özet

Kapsam üst sınırı = ateşleyen / adsız. Önermedeki X eşikleri **[seçim]**'dir (§7.4); doğru satır kapsamı en çok X × üst sınır olur.

| Aile | Tür | Denetlenebilir önerme | Kapsam üst sınırı: havuz / Mac ikilisi / program makrosu | Mekanik sınama | Başlıca risk |
|---|---|---|---|---|---|
| **A1 erişimci** | bütüncül | A1 kuralları, ateşlediği fonksiyonlarda {tek alan döndürür, tek alana yazar, çok alana yazar, yan etkisiz yüklem} sınıfını ≥ %90 kesinlikle verir | 589 (%2,6) / 118 (%4,2) / %2,3 | Gerçek adın fiil sınıfı (aynı / karşıt / farklı); `al` için DWARF'ta o ofsette üye | Küçük örneklem; çok alana yazan biçimleyici; başvuru gürültüsü %25,7 |
| **A2 yaşam** | kısmi (söküm bütüncül) | A2 kuralları {parametreyi bırakır, taze nesne döndürür, yeniden ayırır, söküm} sınıfını ≥ %90 kesinlikle verir | 577 (%2,5) / 205 (%7,4) / %3,7 | Gerçek adın fiil sınıfı; dünkü okuma | Argümanını tüketen geri çağrı; okuyup yeni dizgi dönen; söküm 6 fonksiyon |
| **A3 alan** | kısmi | (fonksiyon, parametre i, ofset o, yön) dörtlüsü ≥ %95 kesinlikle doğrudur: DWARF'ta parametre i bir yapı, birlik ya da dizi göstericisidir ve o ofsetinde bir yaprak başlar | 7 272 (%31,5) / 1 724 (%61,8) / %41,9 | DWARF yerleşimi (Debian); şans tabanı yanında | Ofset tek başına anlam taşımaz; Mac'te DWARF yok; klonlarda parametre sırası |
| **A4 global** | kısmi | (fonksiyon, adres, yön) üçlüsü ≥ %95 kesinlikle bir program değişkenine düşer; "paylaşan" fonksiyonlar aynı değişkene dokunur | 5 643 (%24,4) / 401 (%14,4) / %20,8 | DWARF değişken aralıkları; Mac'te simge tablosu | Doğrusal izleme (kontrol akışı yok); "bir globale dokunur" düşük bilgi; coreutils ağırlığı |
| **A5 sözleşme** | bütüncül | A5, {yan etkisiz, yalnız parametreye yazar, hiç dönmez} iddiasını ikinci türetime karşı ≥ %95 uyumla verir | 3 165 (%13,7) / 511 (%18,3) / %12,7 | p-code çapraz denetimi (bugün: 51 / 3 207 uyuşmazlık, hepsi "hiç dönmez"); DWARF `const` ve `noreturn`; öykünme | Yanlış evrensel iddia okuru fonksiyondan uzaklaştırır; kütüphane etkileri 22 adlık liste |
| **A6 sarma** | bütüncül | A6 ateşleyen fonksiyonun hata yolu dışındaki tek dış etkisi adı verilen kütüphane çağrısıdır (ya da tek iç hedefe ince iletimdir), ≥ %95 kesinlikle | 5 277 (%22,9) / 307 (%11,0) / %10,7 | Koddan ikinci türetim; sarılan adın gerçek adda geçmesi | coreutils yinelenmesi; "ince iletici" yerel yapı kurup iletebilir |
| *tablo yuvası* (dünkü kanıt; aile değil) | kısmi | dün yazıldı | 1 100 (%4,8) / 406 (%14,6) / %7,3 | dün: ölçülmedi | `tablo_yuvasi_sayim.md` §7 |

Her ailenin tanımı, satır şablonu, sınaması ve riski aşağıdadır. Şablonlardaki `<…>` yer tutucudur.

### 4.2 A1 erişimci

- **Kod örüntüsü:** fonksiyon "yalın" (çağrı yok, dolaylı dallanma yok, dönen çıkış var) ve
  - `al`: yığın dışı saklama yok; dönüşlerin birleşiminde tam bir parametre alanı var, geri kalanı sabit;
  - `yaz_tek` / `yaz_cok`: bütün yığın dışı saklamalar aynı parametrenin sabit ofsetlerine, saklanan değerler sabit ya da parametre; dönüş yok ya da bir parametre;
  - `yuklem`: yığın dışı saklama yok; dönüşler ⊆ {0, 1, karşılaştırma sonucu} ve sabit değil.
- **Şablon:**
  - "Yalnız `param_<i>` + `<ofset>` alanını döndürür; belleğe yazmaz, çağrı yapmaz."
  - "`param_<j>` değerini (ya da sabit `<c>`) `param_<i>` + `<ofset>` alanına yazar; başka etkisi yok."
  - "`param_<i>`'nin `<n>` alanına sabit ya da parametre yazar (`<ofsetler>`); başka etkisi yok."
  - "Yan etkisiz yüklem: 0 ya da 1 döndürür; belleğe yazmaz, çağrı yapmaz."
- **Önerme ve sınıf eşlemesi [seçim; GT'ye bakılmadan dondurulur]:** `al` → `get`; `yaz_tek` → `set`; `yaz_cok` → `set`, `init`, `reset`; `yuklem` → `is`, `compare`.
- **Mekanik sınama:**
  1. gerçek adın fiil sınıfı (sözlük v0; tek sınıflı adlar; ad bekleyen nüfusta, geliştirme setinde, ayrı oturumda): aynı sınıf, karşıt sınıf, farklı; çapraz tablonun tamamı;
  2. `al` için DWARF: parametre i'nin gösterdiği yapıda o ofsette üye var mı;
  3. koddan: A1 ⊂ A5 olduğu için A5'in çapraz denetimi A1'i de kapsar (bugün 0 uyuşmazlık).
- **Risk:** küçük nüfus (Mac htop 16); "çok alana yazar" içinde arabellek biçimleyici **[okuma: 6'da 2, aynı gövde]**; varsayılan değerli `al` bir koşul taşır; nüfus vekilinde derleyici çalışma zamanı fonksiyonları var.

### 4.3 A2 yaşam

- **Kod örüntüsü** (ilk üçü dünkü kurallar, aynen):
  - `birakir`: ana yolda bir bırakıcı çağrısının argümanı tam olarak bir parametre;
  - `taze`: bütün dönüşler ayırıcı sonucu ya da 0, ayrılan nesneye yazılıyor (ayırıcı: kütüphane ayırıcıları ve "ayırıcı + hata bildirimi" sarmalayıcıları);
  - `buyutur`: döndürülen ayırıcı `realloc` ya da `reallocarray`;
  - `sokum`: bir parametrenin alanları bırakılıyor ve en az iki alanına sabit yazılıyor, parametrenin kendisi bırakılmıyor, fonksiyonun bütün çağrıları bırakıcı.
- **Şablon:**
  - "`param_<i>`'yi serbest bırakır (`<n>` çağrı yerinde; bırakmadan dönen yol `<var/yok>`)."
  - "Yeni ayrılmış bir nesne döndürür (ayırıcı: `<ad>`); alanlarını doldurur."
  - "`param_<i>`'nin alanlarını serbest bırakıp sıfırlar; `param_<i>`'yi bırakmaz; başka çağrısı yok."
- **Sınıf eşlemesi [seçim]:** `birakir` → `destroy`, `fini`; `taze` → `create`; `buyutur` → `resize`, `create`; `sokum` → `reset`, `fini`, `destroy`.
- **Mekanik sınama:** gerçek adın fiil sınıfı. Dünkü okuma: `birakir` 16 / 18 gerçek yıkıcı, `taze` 10'da 6-7 gerçek kurucu (`on_olcum_gt_siz.md:241`, `:237`) **[okuma]**.
- **Risk:** argümanını kullanıp bırakan geri çağrı (dünkü 2 / 18); okuyup yeni dizgi dönen fonksiyon `taze` sayılır (dünkü 3 / 10); `sokum` havuzda 6 fonksiyon, ölçülemez; kendi ayırıcısını kullanan programlarda (openssl, sqlite3, redis-tools) aile neredeyse hiç ateşlemiyor.

### 4.4 A3 alan

- **Kod örüntüsü:** taban değeri tam olarak bir parametre ve ofseti sabit olan, yığın dışı yükleme ya da saklama; ofsetlerden en az biri 0 değil.
- **Şablon:** "`param_<i>` üstünden okur: `<ofsetler>`; yazar: `<ofsetler>`."
- **Önerme:** §4.1. Ayrı raporlanır: "yalnız ofset 0" ve rastgele hizalı ofsetin tutma olasılığı (şans tabanı; K2'deki denetimle aynı, `plan_v2_2.md:111-113`).
- **Mekanik sınama:** `scripts/measurement/dwarf_tip.py` (yerleşim imzası: ofset, genişlik, gösterici/skaler) ve `scripts/measurement/parametre_hizala.py` (Ghidra `param_N` ↔ DWARF parametresi). İkisi depoda; ikisini satırla birleştiren betik **yazılmadı**. Debian'da çalışır. Mac geliştirme ikililerinde (tmux, htop) DWARF'ın varlığı bu çalışmada doğrulanmadı; plan Mac tip okumasını başka iki programın dSYM'ine bağlıyor (`plan_v2_2.md:82`).
- **Ayırt edicilik sınaması:** aynı ofset kümesini paylaşan fonksiyon çiftlerinin DWARF'ta aynı tipe işaret etme oranı (K1'in çift kesinliği ölçüsü, `plan_v2_2.md:99-104`).
- **Risk:** veri akışı gösterici aritmetiğini (`parametre + sabit` bir yazmaca alınıp oradan erişim) ve iç içe alanı izlemiyor; sayı alt kestirimdir. Girişteki x0-x7'nin hepsi parametre sayılıyor. Derleyici klonlarında parametre sırası değişir.

### 4.5 A4 global

- **Kod örüntüsü:** `adrp` (+ `add`) ya da `adr` ile kurulan, ya da `adrp` + bellek işleneniyle erişilen mutlak adres, yazılabilir veri bloğunda (`.data`, `.bss`, `__data`, `__bss`, `__common` …). GOT, metin ve dizgi adresleri sayılmaz.
- **Şablon:** "Global `<adres>`'i `<okur/yazar/adresini alır>`; aynı adrese `<n>` fonksiyon daha başvuruyor."
- **Mekanik sınama:** DWARF'ta `DW_OP_addr` konumlu değişkenin aralığı (adres bir değişkenin içinde mi; paylaşanlar aynı değişkende mi). `dwarf_tip.py`'nin değişken DIE'lerini okuyup okumadığı doğrulanmadı. Mac'te soyulmamış ikilinin simge tablosundaki veri simgeleri aynı işi görebilir; denenmedi.
- **Ayırt edicilik sınaması:** aynı değişkene dokunan fonksiyon çiftlerinin aynı derleme biriminden gelme oranı ile rastgele çiftlerin oranı arasındaki fark; %95 alt sınırı 0'ın üstünde olmalı.
- **Ek sayaç (aileye girmez):** salt okunur veri bloğunda, dizgi olmayan adres: %13,9 (havuz). Atlama tabloları buraya düşebilir.
- **Risk:** adres izleme doğrusal (kontrol akışına bakmaz; yazmaç yeniden yazılınca ya da çağrıda bilgi silinir); yanlış adres oranı ölçülmedi.

### 4.6 A5 sözleşme

- **Kod örüntüsü:**
  - `ye_yerel`: yalın ve yığın dışı saklama yok;
  - `ye_gecisli`: en az bir çağrı var; saklama, dolaylı çağrı ve dolaylı dallanma yok; her çağrı hedefi çözülüyor; kütüphane hedefleri salt okur listesinde; iç hedeflerin hepsi yan etkisiz (çağrı grafında en büyük sabit nokta);
  - `param_yazar`: bütün yığın dışı saklamalar bir parametrenin sabit ofsetine; çağrı yok ya da bütün hedefler yan etkisiz;
  - `donmez`: girişten dönen bir çıkışa ulaşılamıyor.
- **Şablon:**
  - "Yan etkisiz: belleğe yazmaz; `<çağrı yapmaz / çağırdığı her şey yan etkisiz>`."
  - "Yalnız `param_<i>` üstünden yazar (`<ofsetler>`); başka yan etkisi yok."
  - "Hiç dönmez (bütün yollar `<hedef>` çağrısında bitiyor)."
- **Mekanik sınama:** §3.3. Çapraz denetim sonucu §5.3'te.
- **Risk:** "yan etkisiz", "aynı girdiye aynı çıktı" demek değildir (global okuyabilir); şablon bunu söylemeli. Salt okur listesi elle yazılmış 22 addır. "Hiç dönmez"de 51 uyuşmazlık açık.

### 4.7 A6 sarma

- **Kod örüntüsü:** yığın dışı saklama, dolaylı çağrı ve dolaylı dallanma yok; hata ailesi (dönmeyen, ileti, errno, dönmeyen iç fonksiyon) dışındaki çağrı yerlerinin hepsi aynı tek hedefe iniyor; o çağrıda bir parametre iletiliyor; dönüş yok ya da o çağrının sonucu ve sabitler.
  - `lib`: hedef tek bir kütüphane adı;
  - `ic` (ince iletici): hedef tek bir iç fonksiyon, tam bir çağrı yeri, kontrol akışında döngü yok, dönüş o çağrının sonucu.
- **Şablon:**
  - "`<kütüphane adı>` çağrısını sarar; `<başarısızlıkta dönmez / hata bildirir>`; başka dış etkisi yok."
  - "Tek işi `FUN_<hedef>`'e iletmek (`<argümanları değiştirmeden / sabit argüman ekleyerek>`)."
- **`lib` ile `ic` neden ayrı tanımlı:** kütüphane hedefinin işi belgelidir; fonksiyonun bütün dış etkisinin o çağrı olması döngü içinde de bilgi taşır. İç hedef kendisi adsızdır; satır ancak iletici inceyse ("bunun kartı hedefin kartıdır") bilgi taşır.
- **Mekanik sınama:** koddan ikinci türetim (**yazılmadı**); `lib` için sarılan adın gerçek adın belirteçlerinde geçmesi (alt dizgi); `ic` için iletici ile hedefin gerçek adlarının ortak belirteci.
- **Risk:** okunan 10 ince ileticinin 3'ü yerel bir yapı kurup iletiyor **[okuma]**; coreutils'te aynı sarmalayıcılar 106 ELF'te; Ghidra'nın `void` saydığı sarmalayıcılar.
- **Türev satır (aileye girmez):** "`FUN_<x>` üstünden `<kütüphane adı>` kullanır": bir A6 kütüphane sarmalayıcısını çağıran fonksiyonlar, havuzda 1 662 (%7,2), Mac'te 546 (%19,6). Kütüphane kanıtını I sınıfına taşır.

### 4.8 Yön gösterici satırlar (mekanik sınaması yok; ana öneriye girmez)

| # | Satır | Neden yön gösterici |
|---|---|---|
| YG1 | "İşini çağrılarda yapar, durum kodu döndürür ({0, 1})" (dünkü kalıp 1 ∩ `is`; 752 adsız fonksiyon) | Koddan doğru; ama yararını sınayacak etiket yok (gerçek adlarda karşılığı olan bir fiil sınıfı yok) |
| YG2 | Aynı alan düzenine dokunan fonksiyon grupları (A3'ün gruplaması) | Tip birleştirme (T3) ister; bugün yok |
| YG3 | Geri çağrı rolü (v1 F-ROL) | Dün: erişilen 242 fonksiyonun 197'sinde rol genel sınıfta; isabet 22 (`fiil_tavani.md:143`) |
| YG4 | Çağıranların dönüş değerini kullanışından rol (v1 AD4) | Ön sayımı yok |
| YG5 | "Sarmalayıcı üstünden kütüphane kullanır" (A6 türevi) | Çağrı listesinin zenginleştirilmesi; ayrı bir doğruluk iddiası yok |
| YG6 | Salt okunur veri tablosuna başvuru | Atlama tablosu ve sabit havuzu ayrımı yapılmadı |

## 5. GT'siz ateşleme sayımı

### 5.1 Yöntem ve nüfus

- **Girdi:** saklı taban koşularının `static/` çıktıları: Debian `~/karadul_olcum/n1_debian13` (117 ELF), Mac `workspaces/olcum_mac/runs/ol7-c-b7faeac` (2 Mach-O). Alt küme alınmadı; 119 ikilinin hepsi sayıldı.
- **`jenerik`:** dünkü `isim_bekleyen` (thunk ve dış olmayan, adı `FUN_<onaltılık>`): 23 963; Mac 3 184.
- **`adsiz`:** yeni ürün koşusu (`~/karadul_olcum/runs/urun-yeni-93a2956`) ikilide bittiyse `jenerik` eksi ürünün ad verdikleri; bitmediyse `jenerik`'in tamamı.
  - Sayım anında biten: 16 / 119 (Mac tmux, Mac htop, Debian tmux, htop, openssl, sqlite3, tree, zstd ve pzstd, dört redis-tools ikilisi, coreutils'ten `dir`, `ls`, `vdir`). **Kalan 103 coreutils ikilisinde `adsiz` = `jenerik`.**
  - `adsiz`: 23 088; Mac 2 789 (tmux 2 192, htop 597). Biten ikililerde ürün 875 `FUN_` fonksiyona ad verdi **[hesap: 23 963 − 23 088]**; ad haritasındaki 29 `FUN_` anahtarı nüfusta değil (nedeni incelenmedi).
- **Ağırlık:** `adsiz` havuzunun %58,3'ü coreutils'tir (13 449). Programlar arası okuma için program makrosu ve Mac ikilisi kullanılmalı.
- **Sınırlar:** nüfus vekildir (derleyici çalışma zamanı fonksiyonları ve C++ ikili `pzstd` içinde); ayrıntı §10.

### 5.2 Sonuç (nüfus `adsiz`)

| Birim | `jenerik` | `adsiz` | A1 | A2 | A3 | A4 | A5 | A6 | tablo yuvası | en az bir (6 aile) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `debian/coreutils` | 13 485 | 13 449 | 260 (%1,9) | 166 (%1,2) | 1 930 (%14,4) | 4 441 (%33,0) | 1 606 (%11,9) | 4 428 (%32,9) | 0 (%0,0) | 9 765 (%72,6) |
| `debian/htop` | 239 | 234 | 1 (%0,4) | 14 (%6,0) | 158 (%67,5) | 26 (%11,1) | 18 (%7,7) | 14 (%6,0) | 32 (%13,7) | 194 (%82,9) |
| `debian/openssl` | 588 | 555 | 3 (%0,5) | 0 (%0,0) | 56 (%10,1) | 177 (%31,9) | 35 (%6,3) | 40 (%7,2) | 56 (%10,1) | 271 (%48,8) |
| `debian/redis-tools` | 2 103 | 2 078 | 43 (%2,1) | 2 (%0,1) | 1 108 (%53,3) | 227 (%10,9) | 303 (%14,6) | 113 (%5,4) | 275 (%13,2) | 1 453 (%69,9) |
| `debian/sqlite3` | 425 | 407 | 7 (%1,7) | 1 (%0,2) | 214 (%52,6) | 70 (%17,2) | 45 (%11,1) | 30 (%7,4) | 14 (%3,4) | 311 (%76,4) |
| `debian/tmux` | 1 916 | 1 623 | 60 (%3,7) | 110 (%6,8) | 1 012 (%62,4) | 135 (%8,3) | 277 (%17,1) | 149 (%9,2) | 312 (%19,2) | 1 279 (%78,8) |
| `debian/tree` | 115 | 112 | 1 (%0,9) | 10 (%8,9) | 24 (%21,4) | 47 (%42,0) | 10 (%8,9) | 5 (%4,5) | 5 (%4,5) | 81 (%72,3) |
| `debian/zstd` | 1 908 | 1 841 | 96 (%5,2) | 69 (%3,7) | 1 046 (%56,8) | 119 (%6,5) | 360 (%19,6) | 191 (%10,4) | 0 (%0,0) | 1 525 (%82,8) |
| `mac/htop` | 597 | 597 | 16 (%2,7) | 72 (%12,1) | 364 (%61,0) | 100 (%16,8) | 79 (%13,2) | 49 (%8,2) | 24 (%4,0) | 510 (%85,4) |
| `mac/tmux` | 2 587 | 2 192 | 102 (%4,7) | 133 (%6,1) | 1 360 (%62,0) | 301 (%13,7) | 432 (%19,7) | 258 (%11,8) | 382 (%17,4) | 1 790 (%81,7) |
| **Mac ikilisi** | 3 184 | 2 789 | 118 (%4,2) | 205 (%7,4) | 1 724 (%61,8) | 401 (%14,4) | 511 (%18,3) | 307 (%11,0) | 406 (%14,6) | 2 300 (%82,5) |
| **havuz** | 23 963 | 23 088 | 589 (%2,6) | 577 (%2,5) | 7 272 (%31,5) | 5 643 (%24,4) | 3 165 (%13,7) | 5 277 (%22,9) | 1 100 (%4,8) | 17 179 (%74,4) |
| **program makrosu** | — | — | %2,3 | %3,7 | %41,9 | %20,8 | %12,7 | %10,7 | %7,3 | %73,4 |

- Program makrosu: aynı programın platform birimleri önce ortalanır, sonra 8 program eşit ağırlıkla (dünkü kural).
- `jenerik` nüfusta havuz: A1 589, A2 619, A3 7 839, A4 5 832, A5 3 207, A6 5 299, en az bir 17 899 (%74,7). Alt satırlar, K/I/Y kırılımı ve iki nüfusun bütün tabloları `on_sayim_v2.md`'dedir.

**Alt satırlar** (`adsiz`; havuz / Mac ikilisi):

| Aile | Alt satır | Havuz | Mac ikilisi |
|---|---|---:|---:|
| A1 | tek alan döndürür / tek alana yazar / çok alana yazar / yüklem | 196 / 62 / 63 / 268 | 47 / 14 / 15 / 42 |
| A2 | bırakır (… her yolda) / taze nesne / yeniden ayırır / söküm | 288 (215) / 267 / 18 / 6 | 114 (79) / 86 / 1 / 4 |
| A3 | herhangi bir alan / sıfır dışı ofset (aile) / ≥ 2 ofset / yazar | 10 638 / 7 272 / 5 425 / 4 520 | 2 048 / 1 724 / 1 078 / 730 |
| A4 | değişken (aile) / doğrudan yazar / paylaşımlı adres | 5 643 / 1 440 / 5 189 | 401 / 125 / 349 |
| A5 | yan etkisiz yerel (… sabit ya da boş) / geçişli / yalnız parametreye yazar / hiç dönmez | 1 713 (113) / 523 / 513 / 416 | 263 (26) / 103 / 123 / 22 |
| A6 | kütüphane sarmalayıcısı (… ayırıcı) / ince iç iletici | 1 524 (982) / 3 753 | 39 (11) / 268 |

### 5.3 A5'in p-code ile çapraz denetimi (nüfus `jenerik`; GT'siz, kesinlik değildir)

İkinci türetim: `static/ghidra_output/pcode.jsonl` (Ghidra decompiler'ının yüksek p-code'u; seçici listede `STORE`, `CALL`, `CALLIND`, `RETURN` var, `karadul/config.py:525-531`). Uyuşmazlık tanımları betikte (`pcode_capraz`).

| İddia | Düzeltmelerden önce (dünkü veri akışı) | Düzeltmelerden sonra |
|---|---:|---:|
| yan etkisiz (yerel): p-code'da `STORE`, `CALLIND` ya da derleyici dışı `CALL` | 11 / 1 618 (hepsi Mac) | **0 / 1 722** |
| yan etkisiz (geçişli): p-code'da `STORE` ya da `CALLIND` | 0 / 535 | **0 / 536** |
| yalnız parametreye yazar: p-code'da hiç `STORE` yok | 0 / 519 | **0 / 515** |
| hiç dönmez: p-code'da gerçek `RETURN` | 702 / 1 095 (hepsi Debian) | **51 / 434** (coreutils 25 / 292, redis-tools 26 / 51; Mac 0 / 23) |

- Düzeltmelerden sonraki sıfırlar, düzeltmelerin bulunduğu veriyle aynı veride ölçüldü; bağımsız bir doğrulama değildir.
- İki türetim aynı komut çözümlemesine dayanır; ortak hataları görmez. `STORE` ölçütü yığın göstericisi üstünden yazmayı ayırmaz.

### 5.4 Dünkü `on_sayim.py`'de bulunan iki hata

Çapraz denetim iki hata buldu. Dünkü dosyalar değiştirilmedi; düzeltme `on_sayim_v2.py` içindeki alt sınıftadır (`_KayitliFonksiyon`, `yastiklari_ayikla`). `--giris-duzeltmesi-kapali` ile dünkü `on_sayim.json`'ın nüfus, K/I/Y ve kural sayaçları 10 birimin 10'unda aynen çıkıyor.

1. **Giriş bloğu (yalnız Debian).** Debian arm64 ELF'lerinde PLT girişi `bti c` ile başlıyor; Ghidra thunk fonksiyonunu o komuttan sonra kuruyor ve `bti c`'yi, o girişe kuyruk çağrısı yapan fonksiyonun gövdesine katıyor. Gömülü disassembly adrese göre sıralı olduğu için bu komut listenin başına düşüyor; `on_sayim.Fonksiyon` listedeki ilk komutu giriş sayıyor. Sonuç: fonksiyon "hiç dönmez" görünüyor ve kuyruk çağrısı çağrı sayılmıyor.
   - Etkilenen iç fonksiyon: coreutils 498, openssl 14, redis-tools 13, sqlite3 6, zstd 6, htop 2, tmux 2; Mac 0.
   - Dünkü "hiç dönmeyen" 1 095 fonksiyon iki düzeltmeyle 434'e iniyor: 661 fonksiyon çıktı **[hesap]**. Sayı yastığı atılan 541 iç fonksiyondan büyük; dönmezlik çağıranlara yayıldığı için bu beklenir (sonu yalnız "dönmeyen" bir iç fonksiyon çağrısı olan fonksiyon da dönmez sayılır), ama iki düzeltmenin payı ayrıştırılmadı. Düzeltmeden önce 1 095'in 702'sinde p-code gerçek bir dönüş gösteriyordu (§5.3).
   - Dünkü `on_olcum_gt_siz.md` §2.7'deki Debian "dönmeyen iç", "hiç dönmeyen" ve FK3 geniş sayıları şişkindir; o belgenin "nedeni incelenmedi" dediği fark (`:218`) büyük olasılıkla budur **[tahmin]**. Mac sütunları bu hatadan etkilenmedi.
2. **Gövde dışına düşme (iki platform).** Bir komuttan sonraki adres fonksiyonun listesinde yoksa ama başka bir fonksiyonun girişi ya da gövdesindeyse akış o koda düşer (paylaşılan kuyruk). `on_sayim` bu yolu yok sayıyordu; fonksiyon olduğundan kısa ve çağrısız görünüyordu.
   - Etkilenen `jenerik` fonksiyon: coreutils 97, redis-tools 64, Mac tmux 22, zstd 15, openssl 3, Debian tmux 2.
   - Düzeltme: düşme, hedefi o adres olan bir kuyruk çağrısı gibi kaydediliyor.
3. **Dünkü kural sayaçlarına etkisi** (havuz, `jenerik`; dünkü → düzeltmeli): `is` 1 082 → 1 077 (Mac tmux 124 → 121), `init` 700 → 702, `destroy` 301 → 302, `create` geniş 314 → 313. Dünkü belgenin hükümleri değişmiyor.
4. **Bugünkü ailelere etkisi** (havuz, `jenerik`; düzeltmesiz → düzeltmeli): A5 3 767 → 3 207 (hiç dönmez 1 095 → 434), A6 5 172 → 5 299 (kütüphane sarmalayıcısı 1 410 → 1 533), A3 7 704 → 7 839; A1, A2, A4 aynı.

### 5.5 Elle okuma [okuma]

Örnekler satır başına sha1 sırasıyla 10'ar seçildi (depo dışı: `~/karadul_olcum/runs/n4-v2-2026-11-11/ornekler_son.json`). Yalnız decompile metni okundu; gerçek ad aranmadı. Yaklaşık 85 fonksiyon.

| Satır | Okunan | Bulgu |
|---|---:|---|
| A1 tek alan döndürür | 6 | 6'sı tanıma uygun; 2'si koşullu (varsayılan değer dönen) |
| A1 tek alana yazar | 3 | 3'ü tanıma uygun |
| A1 çok alana yazar | 6 | 4 sıfırlama ya da ilkleme; 2 (aynı gövde, iki ELF) arabelleğe karakter yazan biçimleyici |
| A1 yüklem | 7 | 7'si yan etkisiz karşılaştırma ya da bit sınaması |
| A2 "alanı bırakıp sıfırlar", geniş tanım | 4 | 4'ü büyük, çok işli fonksiyon (dünkü okumayla aynı yön) → dar "söküm" tanımı yazıldı |
| A2 söküm (dar) | 3 | 3'ü "alanları bırak, sıfırla" |
| A5 yan etkisiz (geçişli) | 4 | 3 arama ya da karşılaştırma; 1 derleyici kayan nokta yardımcısı |
| A5 yalnız parametreye yazar | 4 | 4'ü tanıma uygun |
| A6 kütüphane sarmalayıcısı | 4 | 3 ayırıcı ya da saat sarmalayıcısı; 1 tek kütüphane çağrısı çevresinde on beş satırlık çözme yardımcısı |
| A6 iç iletici, ilk tanım | 8 | 4'ü döngülü ya da çok işli → tanım sıkılaştırıldı |
| A6 ince iç iletici (son tanım) | 10 | 10'u tek hedefe iletiyor; 3'ü önce yerel bir yapı kuruyor |
| hiç satır almayan | 10 | dolaylı çağrı yapan; iç içe alana yazan; birden çok kütüphane çağıran; döngüde iç fonksiyon çağıran |
| p-code uyuşmazlıkları | 15 | §5.3, §5.4 |

A3 ve A4 örnekleri okunmadı.

### 5.6 Sayım sırasında değişen tanımlar

Hepsi ilk tam koşudan sonra, sayılar ve örnekler görüldükten sonra yapıldı. Hiçbiri bir ateşleme sayısını hedeflemedi; ikisi sayıyı düşürdü.

1. **A6 iç iletici sıkılaştırıldı.** İlk tanım "tek iç hedefli, kendi saklaması yok" idi (4 460). Okunan 8 örneğin 4'ü döngülü ya da çok işliydi. Son tanım: tek çağrı yeri, döngü yok, dönüş o çağrının sonucu. Geniş hâli ek sayaç olarak duruyor.
2. **A2 "alanı bırakıp sıfırlar" daraltıldı.** İlk tanım dünkü kalıp 2 idi (83). Okunan 4'ün 4'ü büyük fonksiyondu. Son tanım "söküm": bütün çağrılar bırakıcı (6). Geniş hâli ek sayaç.
3. **`a3_yazar` sayaç hatası** düzeltildi (ilk iki koşuda "herhangi bir alan" ile aynı çıkıyordu).
4. **p-code "hiç dönmez" ölçütü** düzeltildi: Ghidra dönmeyen bitişi ilk girdisi sabit 1 olan `RETURN` ile işaretliyor; ilk ölçüt her fonksiyonda tetikliyordu.
5. **İki veri akışı düzeltmesi** eklendi (§5.4).

### 5.7 Denetimler

- **Dünkü çıktılarla:** nüfus ve K/I/Y `on_sayim.json` ile 10 / 10 birimde aynı; tablo yuvası sayıları (`tablo_kaydinda`, `gevsek_ad_kanitli`) `tablo_yuvasi_sayim.json` ile 10 / 10 aynı. Dünkü kural sayaçları düzeltmeler kapalıyken 10 / 10, açıkken 5 / 10 aynı (fark §5.4 madde 3).
- **Belirlenimcilik:** `PYTHONHASHSEED` 0 ve 4242 ile beş Debian biriminde JSON, tablolar ve örnek dosyası bayt bayt aynı. Ayrıca iki tam koşunun `jenerik` bölümleri ve p-code sayıları aynı (rastgele tohumla).
- **Öz sınama:** `--oz-sinama`, sentetik disassembly ile 18 denetim (alt satırlar, global adres izleme, iki düzeltme ve düzeltmesiz davranış). **Mutant kanıtı yok; `tests/` altına test yazılmadı** (görevde yalnız bu dizine yazma izni vardı).

## 6. Örtüşme

Nüfus `adsiz`. Altı aile; tablo yuvası ayrı.

**Kaç aile ateşliyor:**

| | n | 0 | 1 | 2 | 3 | 4 |
|---|---:|---:|---:|---:|---:|---:|
| havuz | 23 088 | 5 909 (%25,6) | 12 364 (%53,6) | 4 289 (%18,6) | 523 (%2,3) | 3 (%0,0) |
| Mac ikilisi | 2 789 | 489 (%17,5) | 1 484 (%53,2) | 669 (%24,0) | 144 (%5,2) | 3 (%0,1) |

**En az bir satır alan adsız fonksiyon** (birleşimin duyarlılığı):

| Birleşim | Havuz | Mac ikilisi | Program makrosu |
|---|---:|---:|---:|
| Altı aile | 17 179 (%74,4) | 2 300 (%82,5) | %73,4 |
| Altı aile ya da tablo yuvası kanıtı | 17 646 (%76,4) | 2 407 (%86,3) | %76,3 |
| A5 hariç beş aile | 15 758 (%68,3) | 2 156 (%77,3) | %68,1 |
| A3 ve A5 hariç dört aile | 10 158 (%44,0) | 984 (%35,3) | %34,5 |
| Yalnız A1 ∪ A2 ∪ A6 | 6 410 (%27,8) | 623 (%22,3) | %16,5 |
| Yalnız bütüncül (A5 ∪ A6) **[hesap]** | 8 328 (%36,1) | 788 (%28,3) | — |
| Yalnız fiil sınıfı taşıyan (A1 ∪ A2) **[hesap]** | 1 166 (%5,1) | 323 (%11,6) | — |

**Hiç satır almayanlar:** havuz 5 909 (K 3 844 / I 1 632 / Y 433); Mac 489 (K 228 / I 237 / Y 24). K sınıfındakilerin kartında kütüphane çağrı listesi (taban satır) vardır. Taban satırı da olmayan (I ∪ Y) satırsız: havuz 2 065 (%8,9), Mac 261 (%9,4) **[hesap]**.

**Aileler arası** (ayrıntı `on_sayim_v2.md`):
- A1 tümüyle A5'in içindedir (tanım gereği); A1 ∩ A2 = A1 ∩ A6 = A2 ∩ A5 = 0.
- Tek ailenin ateşlediği fonksiyonlar: havuzda A3 4 904, A6 2 955, A4 2 846, A5 1 421, A2 238; Mac'te A3 996, A4 177, A5 144, A6 94, A2 73. Yani birleşimi A3 taşıyor: A3 çıkarılırsa Mac'te 996 fonksiyon satırsız kalır.
- En büyük kesişimler: havuzda A4 ∩ A6 1 826 (coreutils sarmalayıcıları), A3 ∩ A5 1 167; Mac'te A3 ∩ A5 298, A3 ∩ A6 177, A3 ∩ A4 170.

**Tablo yuvası kanıtıyla** (dünkü tanım: tablo kaydında ve kayıt dizgisi tanımlayıcı ya da kısa ad biçiminde):

| | Tablo kanıtlı adsız | … A3 de var | … A6 da var | … A4 de var | … A5 de var | … hiçbir aile yok |
|---|---:|---:|---:|---:|---:|---:|
| havuz | 1 100 | 461 | 218 | 112 | 49 | 467 (%42,5) |
| Mac ikilisi | 406 | 233 | 135 | 51 | 16 | 107 (%26,4) |

- Mac'te tablo kanıtlı fonksiyonların üçte biri (135 / 406) ince iletici ya da sarmalayıcı: tabloya giren fonksiyon çoğu kez asıl işi yapan fonksiyona iletiyor **[hesap]**.
- Tablo kanıtı birleşime Mac'te 107, havuzda 467 fonksiyon ekliyor.

## 7. Ön kayıt iskeleti

Kesin ön kayıt ana oturumda yazılır; bu bölüm iskelettir. Eşiklerin hepsi **[seçim]**'dir.

### 7.1 Birim, nüfus, dondurma

- **Birim:** (platform, program); karar program düzeyinde (aynı programın iki platformu iki bağımsız kanıt değildir; dünkü kural).
- **Nüfus:** yeni ürün koşusunda ad almayan fonksiyonlar. GT'li ölçümde N2'nin tanımıyla eşlenir (`fiil_onkayit_taslak.md:431`); `FUN_` vekili yalnız ön sayım içindir.
- **Dondurma:** aile tanımları, sınıf eşlemeleri (§4.2, §4.3), karşıt ve "değiştiren" sınıf listeleri, salt okur listesi ve blok kümeleri GT oturumundan önce sha256 ile dondurulur.
- **GT oturumu ayrıdır.** Kural yazan oturum gerçek adlara bakmaz; GT oturumu yalnız toplu sayı üretir.

### 7.2 Ölçüler

| Ölçü | Tanım | Aileler | Araç durumu |
|---|---|---|---|
| Ö-K kapsam | ateşleyen / adsız | hepsi | var (bu belge) |
| Ö-D1 koddan doğruluk | ikinci türetimle uyuşmazlık oranı | A5 (var); A1, A2, A6 (**yazılmadı**) | kısmen |
| Ö-D2 DWARF doğruluğu | A3: dörtlü kesinliği; A4: adres bir değişkende; A5: `const` ve `noreturn` ile çelişki; A1 `al`: üye var | A3, A4, A5, A1 | okuyucu ve hizalayıcı depoda; birleştirici **yazılmadı**; yalnız Debian |
| Ö-D3 fiil uyumu | gerçek adın fiil sınıfı: aynı / karşıt / farklı; çapraz tablonun tamamı | A1, A2 | `fiil_tavani.py`'nin çatısı uyarlanabilir; **yazılmadı** |
| Ö-A1 çelişki | "yan etkisiz" iddiası ∧ gerçek fiil değiştiren sınıf (`onuncu_adam.md:162` listesi) | A5 | **yazılmadı** |
| Ö-A2 ad içerme | sarılan kütüphane adı gerçek adın belirteçlerinde | A6 `lib` | **yazılmadı** |
| Ö-A3 birlikte dokunma | aynı değişkene (A4) ya da aynı ofset kümesine (A3) dokunan çiftlerin aynı birimden ya da aynı tipten gelme oranı − rastgele çiftlerin oranı | A3, A4 | **yazılmadı** |
| Ö-A4 yaygınlık | satır değerinin ikilideki payı; üçlü entropisi | A5 özeti | var (bu belge) |

### 7.3 Raporlama kuralları

- Her ölçü birim başına, Mac ikilisi, havuz ve program makrosu olarak; coreutils'li ve coreutils'siz.
- Fiil uyumunda başvurusu olmayan adlar (tek sınıflı olmayanlar) ayrı sayılır; payda yalnız başvurusu olanlardır.
- Küçük nüfuslu alt satırlar birleştirilmez; "ölçülemedi" yazılır.

### 7.4 Eşik önerileri [seçim]

| # | Eşik | Dayanak (var olan sabit) | Seçenek |
|---|---|---|---|
| E1 | Koddan ya da DWARF'tan sınanan satırda kesinlik ≥ %95 (Wilson alt sınırı) | K1, K2 ve KS-1 çapa eşiği (`plan_v2_2.md:70`, `:104`, `:110`) | Evrensel iddialar (A5) için daha sıkı: uyuşmazlık 0 |
| E2 | Fiil uyumunda yanlış oranı: N0b'nin `karar()` kuralı, eşik %10 | Kapı 1'in sınırı (`:72`); v1 S20 | Yalnız "karşıt" sayılır / "farklı" da sayılır |
| E3 | Karşıt sınıf oranının Wilson alt sınırı > %5 ise alt satır kapanır | v1 S17 (`fiil_onkayit_taslak.md:461`) | — |
| E4 | En az örneklem: "yanlış ≤ %10" için 35, "kesinlik ≥ %95" için 73 | `plan_v2_2.md:69` | Altında "ölçülemedi" |
| E5 | A3'ün aile düzeyi: sıfır dışı ofset | bu belge §3.1 | herhangi bir alan / ≥ 2 ofset |
| E6 | Ö-A3'te fark için eşik: %95 alt sınırı > 0 | yeni sayı içermez | — |

### 7.5 Öldürme ölçütleri ve doğrulama etiketi

| Sonuç | Ne olur |
|---|---|
| Ö-D1 ya da Ö-D2'de kesinlik E1'in altında | Aile karta ve araç çıktısına girmez. Kural düzeltilmez; düzeltme yeni ön kayıt ister |
| A5'te uyuşmazlık > 0 ve nedeni açıklanmamış | O alt satır "doğrulanmadı" etiketiyle bile gösterilmez (bugün: "hiç dönmez") |
| A1 ya da A2 alt satırında karşıt oranı E3'ü aşıyor | Alt satırın sınıf adı (ör. "erişimci") şablondan çıkar; yalnız koddan kanıtlanan cümle kalır |
| Örneklem E4'ün altında | "Ölçülemedi". Satırın "doğrulanmadı" etiketiyle gösterilip gösterilmeyeceği **[seçim; Berke]** |
| Ö-A3'te fark 0'dan ayırt edilemiyor | Satır öldürülmez; kartın başlığından ayrıntı bölümüne iner |
| Doğrulama setinde ateşleme payı geliştirme setindekinden çok farklı | Raporlanır; eşik yazılmadı **[seçim]** |

**Doğrulama etiketi** (satır başına; N0b ve v1 ile aynı sözlük): `olculmedi` → gösterilmez; `dogrulanmadi`; `dogrulandi`.

### 7.6 Önceden yazılan dallar

| Durum | Ne yapılır |
|---|---|
| Mac'te DWARF yok | A3, A4 ve A5'in DWARF sınaması yalnız Debian'da; Mac için simge tablosu tabanlı sınama yazılır ya da Mac satırları "doğrulanmadı" kalır **[seçim; Berke]** |
| Fiil başvurusu gürültüsü (%25,7) Ö-D3'ü okunmaz kılıyor | Ö-D3 öldürme ölçütü olmaktan çıkar; A1 ve A2 yalnız koddan sınanır |
| A3 ölçüde tutuyor ama ayırt etmiyor | A3 başlıktan iner; gruplama T3'e bağlanır |
| Kalan 51 "hiç dönmez" uyuşmazlığı Ghidra'nın eksiği çıkıyor | İkinci türetim o alt satır için doğrulayıcı olamaz; `DW_AT_noreturn` beklenir |
| Yeni ürün koşusu bitince `adsiz` değişiyor | Sayım aynı komutla yeniden üretilir; tanımlar değişmez |

## 8. Hedef tartışması: "%75 doğru fiil" neye dönüşür?

Öneri değil, seçenek listesidir. "Üst sınır" bu belgedeki GT'siz ateşleme paylarıdır (havuz / Mac ikilisi).

| # | Hedef | Ölçü | İddia ettiği | İddia etmediği | Bugünkü üst sınır |
|---|---|---|---|---|---|
| H1 | **Satır kapsamı** | Adsız fonksiyonların en az P'si, doğrulanmış bir aileden en az bir satır alır | Kartların P'si boş değil; satırların X'i doğru | Fonksiyonun işinin anlaşıldığını; satırın yararlı olduğunu | %74,4 / %82,5 (altı aile); %44,0 / %35,3 (A3 ve A5 hariç) |
| H2 | **Fiil sınıfı kapsamı** (eski hedefin dürüst hâli) | Bütüncül, sınıf taşıyan satır alan ve sınıfı gerçek fiille aynı olan fonksiyon payı | Fiil doğru | Ad verildiğini; nesnenin bilindiğini | %5,1 / %11,6 (A1 ∪ A2). %75 erişilemez |
| H3 | **Sıfır yanlış satır** | Koddan kanıtlanan ailelerde doğrulayıcıya karşı ihlal ≤ ε; kapsam raporlanır, hedeflenmez | Kartta yazan her şey doğru | Kartın dolu olduğunu | Bugün A5'te 51 / 3 207 uyuşmazlık |
| H4 | **Karşıt fiil yasağı** | Hiçbir satır gerçek fiilin karşıtını ima etmez (karşıt oranı ≤ %5) | Satırlar okuru ters yöne götürmez | Kapsam; yarar | ölçülmedi |
| H5 | **Bilgi kazancı** | Satır değerleriyle gerçek ad etiketleri (fiil sınıfı, modül öneki) arasındaki karşılıklı bilgi, etiket entropisine oranla | Satırlar adlardaki bilginin şu kadarını taşıyor | İnsanın ya da modelin o bilgiyi kullanabildiğini | ölçülmedi |
| H6 | **Görev başarısı** | Kartı (ya da araç çıktısını) okuyan değerlendirici fonksiyonun amacını k aday arasından seçer; kartsız tabana göre artış | Kart anlamaya yardım ediyor | Tek tek satırların doğruluğunu | ölçülmedi; mekanik değil (insan ya da model değerlendirici) |

- H1 ile H3 birlikte seçilebilir (kapsam ve doğruluk ayrı sayılar). H2 eski hedefle karşılaştırılabilir tek seçenektir ve tavanı düşüktür.
- H6 kullanıcının bugünkü yönüne (kart ve model) en yakın olanıdır ama mekanik sınaması yoktur; bu belgenin 1. kuralına göre "yön gösterici" kalır.
- Hangi seçeneğin önemli olduğu bu belgede kararlaştırılmadı.

## 9. Seçenekler, dış uzman, kararlar

### 9.1 Ailelerin sıralaması (seçim yapılmadı)

Kapsam üst sınırına göre (program makrosu, `adsiz`); yanında sınama maliyeti.

| Aile | Makro | Mac ikilisi | Havuz | Sınama için eksik olan | Maliyet |
|---|---:|---:|---:|---|---|
| A3 alan | %41,9 | %61,8 | %31,5 | DWARF birleştirici betik; Mac'te DWARF | orta; Mac'te açık |
| A4 global | %20,8 | %14,4 | %24,4 | DWARF değişken okuma (doğrulanmadı); Mac'te simge tablosu sınaması | orta-yüksek |
| A5 sözleşme | %12,7 | %18,3 | %13,7 | "hiç dönmez" uyuşmazlığının çözümü; DWARF `const` birleştiricisi | düşük (çapraz denetim çalışıyor) |
| A6 sarma | %10,7 | %11,0 | %22,9 | p-code türetimi; ad içerme sayımı (GT oturumu) | düşük-orta |
| A2 yaşam | %3,7 | %7,4 | %2,5 | fiil uyumu sayımı (GT oturumu) | düşük; dünkü okuma var |
| A1 erişimci | %2,3 | %4,2 | %2,6 | fiil uyumu sayımı (GT oturumu) | düşük; örneklem küçük |

- Kapsamı en büyük aile (A3) en az bilgi taşıyan ve sınaması Mac'te açık olan ailedir. Sınaması en ucuz ve bugün en ileri olan aile A5'tir.
- Tablo yuvası kanıtı (makro %7,3) dün ayrı ölçüldü; aile olup olmayacağı ayrı karardır.

### 9.2 Dış uzmana üç soru

Sorular bağlamsız okunabilir yazıldı. Dış uzman okuması yeni bir ajan dalgasından önce gelmelidir.

1. Derlenmiş bir C programında adı bilinmeyen bir fonksiyonu inceleyen tersine mühendis için hangisi daha değerlidir ve neden: (a) fonksiyonun işini anlatan bir fiil (`get`, `set`, `free` gibi); (b) dokunduğu verinin kimliği (hangi yapı alanları, hangi global değişken, hangi tablo); (c) yan etki sözleşmesi ("belleğe yazmaz", "yalnız şu parametre üstünden yazar", "hiç dönmez", "tek işi şu kütüphane çağrısını sarmak")? Elinizde yalnız biri olabilseydi hangisini isterdiniz?
2. Böyle bir "davranış satırı"nın doğruluğunu kaynak koddaki ada bakmadan sınamak istiyoruz. İki doğrulayıcı adayımız var: hata ayıklama bilgisinden türeyen etiketler (yapı yerleşimi, `const` niteleyicisi, değişken adresleri, derleme birimi) ve aynı önermenin iki bağımsız çözümlemeyle (makine kodu üstünde veri akışı ile decompiler'ın ara gösterimi) çapraz denetimi. Bunlar yayımlanabilir bir yer gerçeği sayılır mı? Fonksiyon özeti ve yan etki çözümlemesi sonuçlarını literatür nasıl değerlendiriyor; bakmamız gereken çalışma ya da ölçüt var mı?
3. Fonksiyon adındaki fiil ile koddan çıkarılan davranış sınıfının uyuşmasını başarı ölçüsü saymak savunulur mu? Verimizde adların yaklaşık üçte birinde tek bir fiil yok ve otomatik fiil çıkarımı elle denetimde dörtte bir oranında yanlış sınıflıyor. Yerine hangisini birincil ölçü sayardınız: "karttaki her satır doğru" (sıfıra yakın yanlış iddia), satırların ad ve modül bilgisiyle karşılıklı bilgisi, yoksa görev deneyi (kartı okuyup fonksiyonun amacını bulma)?

### 9.3 Berke'nin karar vermesi gerekenler

1. **Hedef:** §8'deki seçeneklerden hangisi ya da hangileri (H1-H6).
2. **Aileler:** hangileri ön kayda girsin (§9.1). A3 ve A4 kısmi satırdır; karta "başlık" mı, "ayrıntı" mı yazılacakları.
3. **Eşikler:** E1-E6 (§7.4); özellikle A5 için "uyuşmazlık 0" koşulu.
4. **Mac'te DWARF:** A3, A4, A5'in sınaması yalnız Debian'da mı kalsın, Mac için simge tablosu tabanlı sınama yazılsın mı.
5. **"Doğrulanmadı" satırlar:** örneklemi yetmeyen alt satırlar (A1'in çoğu, söküm) kartta ve araç çıktısında gösterilsin mi.
6. **Tablo yuvası:** yedinci aile mi olsun, T1'e mi bırakılsın (dünkü A1 öldürme ölçütünün okuması da açık: `tablo_yuvasi_sayim.md:208-211`).
7. **Dünkü belge:** `on_olcum_gt_siz.md` §2.7'deki Debian FK3 ve dönmez sayıları için düzeltme notu yazılsın mı; `on_sayim.py`'deki iki hata orada mı düzeltilsin (dünkü dosyalar bu görevde değiştirilmedi).
8. **Birincil okuma:** havuz mu (coreutils %58), program makrosu mu, Mac ikilisi mi.
9. **Dış uzman:** kim okuyacak ve ne zaman.
10. **Yön denetimi:** Onuncu Adam ve farklı model ailesi bu görevde kullanılamadı; yön kararından önce çalıştırılsın mı.

## 10. Sınırlar, yapılmayanlar, bütünlük kaydı

### 10.1 Sınırlar

1. **Kesinlik yok.** Bu belgedeki her pay ateşleme payıdır. Okunan örnekler GT değildir ve satır başına 3-10 tanedir.
2. **Nüfus vekildir** ve koşu anına bağlıdır (§5.1). Derleyici çalışma zamanı fonksiyonları ve C++ ikili (`pzstd`; KS-1 ve v1 onu dışarıda tutuyordu) nüfustadır.
3. **Veri akışının sınırları** (dünkü zemin): gösterici aritmetiği ve iç içe alan izlenmiyor (A3 ve A5 "yalnız parametreye yazar" alt kestirim); dolaylı dallanmalı fonksiyonlar bütüncül ailelerin dışında; girişteki x0-x7 parametre sayılıyor.
4. **A4'ün adres izlemesi doğrusaldır;** yanlış adres oranı ölçülmedi.
5. **Mac'te derleyicinin dışarı aldığı kod parçaları** ayrı fonksiyon olarak nüfusta olabilir; etkisi ölçülmedi. "Gövde dışına düşme" düzeltmesi paylaşılan kuyrukların bir biçimini yakalıyor; başka biçimler olabilir.
6. **İki düzeltme bugün yazıldı;** öz sınama dışında testi yok. Düzeltmeli sayılar dünkü betiğin sayılarından ayrışır (§5.4).
7. **Tanımları yazan bir LLM ajanıdır** (Claude Fable 5.2); tmux, htop, coreutils, redis, zstd ve sqlite kaynaklarını eğitiminden tanıyor olabilir. Önlem: kurallar yapıya dayanır, hiçbir kural bir program fonksiyonunun adına başvurmaz.

### 10.2 Yapılmadı

- GT çaprazlaması (bilerek; ön kayıt kesinleşince ana oturumda).
- Ö-D2, Ö-D3, Ö-A1, Ö-A2, Ö-A3 sınayıcıları; A1, A2 ve A6 için ikinci türetim.
- Kalan 51 "hiç dönmez" uyuşmazlığının çözümü.
- A3 ve A4 örneklerinin elle okunması.
- Mutant kanıtlı testler.
- Yeni ürün koşusunun bitmesini bekleyip `adsiz` nüfusla son sayım (103 coreutils ikilisi bitmemişti).
- Onuncu Adam, farklı model ailesi, dış uzman okuması.

### 10.3 Bütünlük kaydı

- **Okunmadı:** GT dosyaları (dbgsym, DWARF, `macho_score.json`, simge tabloları), `docs/arge/dogrulama_seti*`, `docs/arge/test_seti*`, `docs/arge/dogrulama_seti_kanit/`, `targets/`, `scripts/measurement/*seti*`. Dünkü belgelerde yayımlanmış GT'li toplu sayılar kullanıldı; yeni çapraz sayım yapılmadı.
- **Okundu:** dünkü beş belge ve iki betik; plan v2.2; ürün taban ölçümü; `scripts/measurement/dwarf_tip.py` ve `parametre_hizala.py`'nin belge dizgileri; `karadul/config.py:523-531` ve `karadul/ghidra/headless.py:1194-1232` (p-code dışa aktarımı). Saklı `static/` çıktıları: 119 dizinin hepsi betikle; elle yaklaşık 85 fonksiyonun decompile metni.
- **Yeni ürün koşusundan okunan:** yalnız `reconstructed/src/naming_map.json` → `global` sözlüğü (bir `FUN_` anahtarının ürün adı alıp almadığı). Ürünün verdiği adlar çıktıya yazılmadı.
- **Yazılan:** yalnız `docs/arge/2026-11-11_n4_v2/` altındaki dört dosya. Git durumu değiştirilmedi.
- **Depo dışında bırakılanlar** (`~/karadul_olcum/runs/n4-v2-2026-11-11/`): örnek dosyaları (adresli), ara koşular (`deneme*.json`, `duzeltmesiz.json`, `son_onceki.json`, `tohum_*.json`), okuma ve özet betikleri.
