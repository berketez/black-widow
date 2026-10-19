# Kör etiket protokolü v2

- **Tarih:** 2026-10-19
- **Plan:** `docs/arge/2026-10-17_plan_v2.md`, §3 madde 5 ve §5 G4
- **Rubrik:** `docs/arge/etiket_rehberi.md`, sürüm 2
- **Araçlar:**
  - `scripts/measurement/etiket_paketi.py`: paket üretimi ve sızıntı denetimi
  - `scripts/measurement/etiket_puan.py`: puanlama ve cömertlik deneyi
  - `scripts/measurement/csrc_index.py`: C kaynak dizinleyicisi
- **Testler:** `tests/test_etiket_paketi.py`, `tests/test_etiket_puan.py`, `tests/test_csrc_index.py`

## 1. Neden v2

15 Ekim'deki "kör" paket kör değildi (Onuncu Adam İ5; plan v2 §2 madde 10):
- Her kayıtta gerçek ad (`gt`) duruyordu. Gövdenin imza satırında da özgün ad yazıyordu.
- Yanlış fiilli isimler `yalniz_alan` sayılıyor, yanlış sayacına girmiyordu.
- Değerlendirici aday, gerçek ad ve kaynağı aynı anda görüyordu.

| v1'deki sorun | v2'deki karşılığı |
|---|---|
| `gt` pakette | Gerçek ad yalnız gizli anahtarda. Değerlendirici dosyalarında yalnız beyaz listedeki alanlar var |
| Özgün ad gövdede | Öğenin kendi adı gövdede `FONKSIYON` olur; dosya adı fonksiyonun adıysa dosya adında da. Başka öğelerin adları görünür kalır, anahtarda `capraz_atif` ile işaretlenir (§5) |
| Aday, amaç belirlenmeden görülüyor | İki aşama. Aday dosyası, amaç dosyası teslim alındıktan sonra verilir. Puanlayıcı amaç cümlesinin değişmediğini denetler |
| Yanlış fiil sayılmıyor | Rubrik sürüm 2, kural 4 |
| Cömertlik ölçülmemiş | %10 yem ve gt'li/gt'siz deney |

## 2. Dosyalar ve kimin neyi gördüğü

| Dosya | İçerik | Kim görür |
|---|---|---|
| `amac_paketi.jsonl` | `id`, `dosya` (kaynak köküne göre yol), `govde` | değerlendirici, aşama 1 ve 2 |
| `aday_paketi.jsonl` | `id`, `aday` | değerlendirici, yalnız aşama 2 |
| `anahtar.json` | Künye (girdi özetleri, tohum, sayılar, dışarıda kalanlar) ve id başına gerçek ad, Karadul tahmini, `tp`/`wrong`, yem bilgisi, karartma sayıları, `capraz_atif` | yalnız koordinatör |
| `amac.jsonl` (değerlendirici yazar) | `id`, `amac` | koordinatör |
| `etiket.jsonl` (değerlendirici yazar) | `id`, `amac`, `etiket`, `gerekce` | koordinatör |

Ön etiket hiçbir değerlendiriciye gösterilmez. Buna Karadul'un otomatik durumu (`tp`/`wrong`), gevşek eşleşme ve başka bir değerlendiricinin etiketi dahildir.

## 3. Aşamalar

### 3.0 Hazırlık (koordinatör)

Tohum ve örneklem büyüklüğü paket üretilmeden önce ön kayda yazılır.

```bash
python scripts/measurement/etiket_paketi.py uret \
    --satirlar <koşu>/macho_score.json --kaynak <kaynak kökü> --ikili tmux \
    --orneklem 200 --tohum <tohum> --cikti <paket>/tmux_kor
python scripts/measurement/etiket_paketi.py sizinti-denetimi --paket <paket>/tmux_kor
```

- `uret` aynı denetimi kendisi de koşar.
- Denetim 0 hata vermeden paket dağıtılmaz. Çıkış kodu hata varsa 1, girdi hatasında 2'dir.
- Değerlendiriciye gidecek dosyalar ayrı bir klasöre kopyalanır. `anahtar.json` o klasöre girmez.

### 3.1 Aşama 1: amaç cümlesi

- Değerlendirici `etiket_rehberi.md` ile `amac_paketi.jsonl` dosyasını alır.
- Her id için fonksiyonun ana işini tek cümleyle yazar ve `amac.jsonl` olarak teslim eder.
- Koordinatör dosyanın bütün id'leri içerdiğini denetler ve sha256'sını kaydeder.

### 3.2 Aşama 2: aday ve etiket

- Değerlendirici ancak bundan sonra `aday_paketi.jsonl` dosyasını alır.
- Amaç cümlesi değişmez. Gövdeye yeniden bakılabilir.
- Her aday rubriğe göre etiketlenir ve `etiket.jsonl` olarak teslim edilir.

### 3.3 Puanlama

Bir değerlendiricinin bir dalgadaki bütün paketleri tek komutta verilir:

```bash
python scripts/measurement/etiket_puan.py puan \
    --anahtar <paket>/tmux_kor/anahtar.json --anahtar <paket>/htop_kor/anahtar.json \
    --etiket etiket_tmux.jsonl --etiket etiket_htop.jsonl \
    --amac amac_tmux.jsonl --amac amac_htop.jsonl --cikti puan.json
```

**Çıktı:**
- Program başına:
  - `n` (yemler hariç);
  - `tam`, yakın (`tam` + `dogru_tarif`), `yalniz_alan` ve `yanlis` oranları, her biri Wilson %95 aralığıyla;
  - değerlendiricinin ham etiket sayıları;
  - programın yem kabul oranı ve aralığı.
- `yem_toplam`: verilen bütün paketlerin yemleri birleştirilerek hesaplanan yem kabul oranı ve Wilson aralığı. Komut tek değerlendiricinin etiketleriyle koşulduğu için bu, o değerlendiricinin dalgadaki yem kabulüdür (§6).

**Duyarlılık analizi.** `--capraz-atifsiz` verilirse gerçek adı başka bir öğenin gövdesinde geçen öğeler (`capraz_atif > 0`; ana ve yem) dışarıda bırakılır ve oranlar yeniden hesaplanır. Dışarıda kalan sayılar çıktıda yazar. Asıl sonuç bütün öğelerle verilir; duyarlılık sonucu yanında raporlanır.

**Açık hatalar:**
- eksik ya da fazla id;
- yinelenen id;
- geçersiz etiket;
- boş amaç cümlesi;
- `--amac` dosyasındakinden farklı amaç cümlesi;
- `--capraz-atifsiz` verildiğinde anahtarda `capraz_atif` olmaması.

**`tam` anahtardan gelir** (ana oturumun kabulü, 2026-10-19).
- Kör kipte değerlendirici özgün adı bilemez. Bu yüzden otomatik tam eşleşme (`status == "tp"`, `function_f1.normalize_name` ile) `tam` sayılır.
- Değerlendiricinin `tp` olmayan öğeye verdiği `tam`, `dogru_tarif` sayılır.
- İki durumun id'leri `tutarlilik` altında listelenir:
  - `tp_yakin_disi`: özgün ada `yalniz_alan` ya da `yanlis` diyen etiket; değerlendiricinin katılığını gösterir.
  - `tam_ama_tp_degil`.

## 4. Örneklem ve payda

- **Popülasyon:** isim verilmiş fonksiyonlar (`tp` + `wrong`), gövdesi kaynakta tek anlamlı bulunanlar.
- **Dışarıda kalanlar** künyede adresleriyle listelenir:
  - gövdesi bulunamayanlar: makroyla üretilenler, `.cold` parçaları, `OUTLINED_FUNCTION`;
  - farklı metinli birden çok tanımı olanlar: platforma özgü dosyalar, aynı adlı `static` fonksiyonlar.
- **Örneklem:** tohumlu rastgele N; `--orneklem 0` popülasyonun hepsidir.
- **Kırpma:** gövde v1'deki gibi ilk 60 satırda kırpılır (`--azami-satir`). Kırpılan yer `/* ... */` ile işaretlenir.
- **Belirlenimcilik:** aynı girdi, aynı tohum ve aynı Python sürümüyle çıktı bayt bayt aynıdır. Künyede satır dosyasının sha256'sı, kaynak ağacının özeti ve Python sürümü yazar.

## 5. Karartma

Ana oturum kararı, 2026-10-19: yalnız öğenin kendi adı karartılır.

- **Öğenin kendi adı.**
  - Bütün gerçek adları baştaki `_` olan ve olmayan biçimleriyle, tam sözcük eşleşmesiyle aranır.
  - Gövdenin her yerinde `FONKSIYON` olur: imza, özyineleme, yorum, dize.
  - Benzer tanımlayıcılar kalır (`foo_count`, `my_foo`).
- **Dosya adı.**
  - Uzantısız hâli öğenin kendi adının biçimlerinden birine eşitse dosya adı karartılır: `xmalloc.c` → `FONKSIYON.c`, `lib/foo.h` → `lib/FONKSIYON.h`.
  - Diğer durumlarda dosya adı kalır, çünkü rubrik kural 7 modül bağlamı ister. Klasör adları da kalır.
- **Başka öğelerin adları görünür kalır.** Gerekçe:
  - Cömertlik deneyinde gt'li kip gövdeyi hiç karartmıyor. Kör kipte çağrılan fonksiyonların adları da silinirse iki koşulun farkı yalnız "gerçek adı görmek" olmaz.
  - Kuru koşuda 220 öğenin 78'inde (%35) amacı anlatan çağrı bilgisi kaybolurdu.
  - Plan yalnız fonksiyonun kendi adının karartılmasını istiyor.
- **Çapraz atıf.** Bedeli şu: değerlendirici bir öğenin gerçek adını başka bir öğenin gövdesindeki çağrıdan okuyup karartılmış gövdeyle eşleştirebilir. Bu yüzden:
  - Anahtarda öğe başına `capraz_atif` var: öğenin gerçek adının paketteki kaç başka öğenin gövdesinde geçtiği (geçiş değil öğe sayısı). Sayım iki kipte aynıdır.
  - Sonuçlar `--capraz-atifsiz` ile bu öğeler olmadan da raporlanır (§3.3).
  - Dosya adı yoluyla görünme (`xmalloc.c` içindeki başka fonksiyonlar) `capraz_atif`'e girmez. Künyede `dosya_adi_capraz_atifli_oge` olarak ayrıca sayılır.
  - Değerlendirici yönergesi eşleştirme yapılmamasını ister (§8).
- **Satır numarası verilmez.**

**Sızıntı denetimi (kör kip):**
- **Hata:**
  - beyaz liste dışı ya da eksik alan;
  - id kümesinin anahtarla uyuşmaması;
  - öğenin kendi adının kendi kaydında `aday` dışındaki bir alanda geçmesi (gövde, dosya adı, id);
  - yem adayının paketteki bir öğenin gerçek adı olması ya da bir gövdede tanımlayıcı olarak geçmesi.
- **Uyarı:** başka bir öğenin gerçek adının gövdelerde ya da dosya adlarında geçmesi. Öğe ve geçiş sayısıyla, ayrıca adı başka kayıtta görünen öğe sayısıyla verilir.

## 6. Yem

- **Sayı:** ana örneklemin %10'u, yukarı yuvarlanır (200 → 20). Oran plandan gelir ve değişmez.
- **Gövde:** örneklemde olmayan, isim verilmiş bir fonksiyonun gövdesi. İsimliler yetmezse isimsizlerden tamamlanır; künyede `yem_govde_havuzu` alanı. Yem gövdesi de ana öğeler gibi karartılır.
- **Aday:** pakette olmayan bir fonksiyonun kaynaktaki gerçek adı. Koşullar:
  - farklı kaynak dosyasından;
  - yem öğesinin gerçek adıyla normalize token kesişimi boş;
  - paketteki hiçbir gövdede tanımlayıcı olarak geçmiyor. Bu bir seçim kuralıdır; denetim ihlali hata sayar;
  - başka bir adayla (normalize) aynı değil.
- Yemler ana öğelerle karıştırılır. Biçimleri aynıdır, id sırası adres sırası değildir.
- **Kabul:** `tam` ya da `dogru_tarif` etiketlenen yem. Ana sayılara girmez.
- **Kabul oranı değerlendirici başına hesaplanır.** Bir dalgadaki bütün paketler birleştirilir (`yem_toplam`, §3.3). Wilson aralığı her zaman verilir.
- **Hedef:** yem kabulü ≤ %5 (plan G4). Hedef nokta tahmine uygulanır.
  - Sınırlama: aralığın üst sınırının %5'in altına inmesi için 0 kabulle yaklaşık 73 yem gerekir (§9). 200 öğelik bir pakette 20 yem var.
- **Değerlendiriciye yem olduğu söylenmez.** Bu bir öneridir, karar §12'de.

## 7. Cömertlik deneyi

**Kurulum.**
- Aynı tohumla iki paket üretilir: kör ve `--gt-goster`.
- İki pakette id'ler, adaylar, yemler ve `capraz_atif` aynıdır. gt'li pakette gövde ve dosya adı karartılmaz ve `gt` alanı vardır; bu, eski protokolün eşdeğeridir.
- İki aşamalı sıra iki kipte de korunur.
- Aynı 200 öğe iki kez etiketlenir: gt'li ve gt'siz, **farklı değerlendiricilerle**. Aynı değerlendirici iki kipi görürse ikinci etiketleme ilkinden etkilenir.

```bash
python scripts/measurement/etiket_paketi.py uret ... --tohum <aynı> --cikti <paket>/tmux_gt --gt-goster
python scripts/measurement/etiket_puan.py comertlik \
    --anahtar-gtli <paket>/tmux_gt/anahtar.json --etiket-gtli etiket_gt.jsonl \
    --anahtar-gtsiz <paket>/tmux_kor/anahtar.json --etiket-gtsiz etiket_kor.jsonl \
    --tohum <tohum> --cikti comertlik.json
```

**Çıktı:**
- yakın oranı (gt'li, gt'siz) ve Wilson aralıkları;
- fark (gt'li − gt'siz) ve eşli bootstrap %95 aralığı: öğeler yerine koyarak yeniden örneklenir, 10 000 tekrar, tohumlu;
- uyuşmazlık çiftleri;
- iki kipte yem kabulü.

`--capraz-atifsiz` burada da aynı duyarlılık analizini verir.

**Denetimler.** İki anahtar aynı öğeleri anlatmıyorsa ya da kipler ters verilmişse puanlayıcı hata verir.

**Karar** (plan G8; yorum deneyden önce yazıldı, 2026-10-19): fark için **nokta tahmin** 10 puanın üstündeyse v1 tabanındaki yakın oranları geçersiz sayılır. %95 bootstrap aralığı da raporlanır.

**Yorum sınırı.**
- Ölçülen fark iki protokolün toplam farkıdır. İçinde üç şey var:
  - gerçek adın (`gt` alanı) görünmesi;
  - öğenin kendi adının gövdede ve dosya adında görünmesi;
  - değerlendirici farkı.
- Başka öğelerin adları iki kipte de görünür, yani fark onlardan gelmez.
- Değerlendirici farkını ayırmak için çapraz düzen kurulabilir: her değerlendirici öğelerin yarısını gt'li, öbür yarısını gt'siz etiketler.
- Bootstrap yalnız öğe örnekleminin değişkenliğini kapsar, değerlendirici değişkenliğini kapsamaz.

## 8. Ajan değerlendirici yönergesi

**Koordinatör için:**
- Her değerlendirici kendi boş klasörünü alır. Aşama 1'de klasörde yalnız `etiket_rehberi.md` ve `amac_paketi.jsonl` bulunur; `aday_paketi.jsonl` aşama 2'de eklenir.
- İki aşama ayrı çağrılar olabilir. Aşama 2 ajanı aşama 1'in `amac.jsonl` dosyasını kullanır.
- Ajanın başka dosya okumadığı transcript'teki araç çağrılarından denetlenir. Mekanik bir engel yok, denetim zorunlu.
- Ajanlar etiketleyicilerle aynı model ailesindense bu yazılır. LLM yargıcın insanlarla uyumu ayrı raporlanır (G32).

### Aşama 1 metni

```text
Görev: Kaynak kodu verilen C fonksiyonlarının ana işini birer cümleyle yazacaksın.

Okuyabileceğin dosyalar yalnız bunlar:
- <klasör>/etiket_rehberi.md  (önce "Değerlendirme sırası" bölümünü oku)
- <klasör>/amac_paketi.jsonl  (her satır: id, dosya, govde)

Kurallar:
1. Başka hiçbir dosyayı okuma ve arama. İnternete bakma. Kaynak ağacına, anahtara ya da
   önceki etiketlere ulaşmaya çalışma.
2. Gövdede FONKSIYON, değerlendirdiğin fonksiyonun kendi adının yerine geçer. Dosya adı
   fonksiyonun adıysa dosya adında da FONKSIYON görünür (ör. FONKSIYON.c). Gizlenen adı
   tahmin etme. Kodu tanıdığını düşünsen bile ezberindeki adı yazma.
3. Gövdelerde başka fonksiyonların adları geçer; hangi gövdenin hangi ada ait olduğunu
   tahmin etmeye çalışma.
4. "dosya" alanı fonksiyonun kaynak dosyasıdır; modül bağlamı olarak kullanabilirsin.
5. Her id için ana işi tek cümleyle yaz: ne yapıyor, hangi nesne üzerinde. Ad önerme.
6. Gövde "/* ... */" ile bitiyorsa kırpılmıştır; gördüğün kadarına göre yaz.

Çıktı: <klasör>/amac.jsonl. amac_paketi.jsonl'deki her id için bir satır,
yalnız şu alanlar: {"id": "...", "amac": "..."}.
Bitince yalnız "AŞAMA 1 TAMAM, <satır sayısı> satır" yaz.
```

### Aşama 2 metni

```text
Aşama 2. Amaç cümlelerin (<klasör>/amac.jsonl) teslim alındı; artık değiştirilmez.

Okuyabileceğin dosyalar: <klasör>/etiket_rehberi.md, <klasör>/amac_paketi.jsonl,
<klasör>/amac.jsonl ve yeni dosya <klasör>/aday_paketi.jsonl (her satır: id, aday).
Aday, o fonksiyon için önerilen isimdir.

Her id için:
1. amac.jsonl'deki cümleni al, değiştirme.
2. Adayı rubriğe göre etiketle: dogru_tarif, yalniz_alan ya da yanlis.
   Özgün adı bilmediğin için tam kullanma.
3. Kısa bir gerekçe yaz ve dayandığın kuralı belirt (ör. "kural 4: getter/setter karışması").

Aşama 1'deki 1., 2. ve 3. kurallar geçerli.

Çıktı: <klasör>/etiket.jsonl. Her id için bir satır:
{"id": "...", "amac": "<amac.jsonl'deki cümlenin aynısı>", "etiket": "...", "gerekce": "..."}
Bitince yalnız "AŞAMA 2 TAMAM, <satır sayısı> satır" yaz.
```

gt'li pakette (cömertlik deneyi) iki metinde şu değişiklikler yapılır:
- 2. kural yerine şu cümle girer: "`gt` alanı fonksiyonun gerçek adıdır."
- Aşama 2'de `tam` serbesttir: aday gerçek adın kendisiyse `tam` yazılır.

## 9. Örneklem büyüklüğü

Hesaplar %95 düzeyindedir (z = 1,96).
- **Yakın oranı.**
  - En kötü durumda (p = 0,5) gereken öğe sayısı n ≈ z²·p(1−p)/E²: ±5 puan için 385, ±3 puan için 1068.
  - 200 öğe yaklaşık ±6,9 puan verir.
  - Aynı programdan ve aynı dosyadan gelen öğeler bağımsız değil. Wilson aralığı bağımsızlık varsayar, yani gerçek belirsizlik daha geniştir. Programlar arası birleşik sayılar için plan, program bazında bootstrap öngörüyor (§3 madde 4).
- **Yem kabulü (Wilson üst sınırı).**

  | Yem sayısı | Kabul | Üst sınır |
  |---|---|---|
  | 20 | 0 | %16,1 |
  | 20 | 1 | %23,6 |
  | 40 | 0 | %8,8 |

  Üst sınırın %5'in altına inmesi için 0 kabulle en az 73, 1 kabulle en az 110, 2 kabulle en az 142 yem gerekir. Bu yüzden ≤ %5 hedefi nokta tahmine uygulanır (§6) ve aralık her zaman yanında verilir.
- **Cömertlik farkı.**
  - Eşli farkın yarı genişliği uyuşmazlık oranına bağlıdır: ≈ z·√(uyuşmazlık oranı / n).
  - 200 öğede uyuşmazlık %10 ise yaklaşık ±4,4 puan, %20 ise ±6,2 puan, %30 ise ±7,6 puan.
  - G8 kararı nokta tahmine bakar (§7). Bu genişlikte aralık 10 puan eşiğini kesebilir; bu yüzden aralık kararın yanında raporlanır.

## 10. Bilinen sınırlamalar

1. **Doğal dil ipuçları.** Yorumlar, dizeler ve log iletileri amacı, bazen adı parça parça anlatır. Karartma yalnız tam adı gizler.
2. **Ezber.** tmux gibi ünlü programların kaynağını model değerlendiriciler tanıyabilir. Dosya adları, dizeler ve id öneki (`tmux-`) programı ele veriyor. Ölçmek için ayrı bir yoklama önerilir: karartılmış gövdelerden ad tahmini istenir ve tam eşleşme oranı raporlanır.
3. **Dosya adı.** Fonksiyonun kendi adıysa karartılır. Başka bir öğenin adıysa kalır.
   - Kuru koşuda `xmalloc` öğesinin dosya adı `FONKSIYON.c` oldu.
   - Aynı dosyadaki 2 başka öğenin kaydında `xmalloc.c` görünüyor.
4. **Çapraz atıf.** Başka öğelerin adları gövdelerde görünür (§5).
   - Kuru koşuda 220 öğenin 46'sının (43 ana, 3 yem) gerçek adı en az bir başka gövdede geçiyor; en çok geçen `fatalx`, 20 gövde.
   - 78 gövdede başka öğelerin adları geçiyor (133 geçiş).
   - Etkisi `--capraz-atifsiz` duyarlılık analiziyle ölçülür.
5. **Paydanın dışında kalanlar.** Gövdesi bulunamayan ya da belirsiz olan fonksiyonlar paydaya girmez: makrolar, `.cold`, `OUTLINED`, platforma özgü çoklu tanımlar. Kuru koşuda 871 isimli fonksiyondan 15 + 2.
6. **Kırpma.** 60 satırdan uzun gövdelerin sonu görünmez. Kuru koşuda 220 öğenin 33'ü kırpıldı.
7. **Yem sayısı.** %10 oranıyla 200 öğelik pakette 20 yem var. ≤ %5 hedefi nokta tahmine uygulanır. Aralığın üst sınırının %5'in altına inmesi için yaklaşık 73 yem gerekir (§9).
8. **Yemlerin inandırıcılığı.**
   - Yem adayı programın gerçek adlarından biri. Karadul'un adları biçimce ayrışabiliyor (`_2` ekleri, tek sözcükler, dizeden türemiş uzun kalıplar). Değerlendirici yemi biçiminden sezebilir; bu yüzden yem kabul oranı bir alt sınırdır.
   - Onuncu Adam aynı modülden yem önermişti; bu daha zor bir sınamadır. Burada farklı dosya ve boş token kesişimi seçildi, çünkü yemin gerçekten yanlış olmasını güvenceye alıyor.
9. **`tam` tanımı.** Normalize tam eşleşmenin (`function_f1.normalize_name`) rubrikteki "yalnız biçim farkı" tanımıyla aynı olduğu kabul edildi.
10. **Kaynak gövdesi ile derlenmiş fonksiyon.** Kaynak gövdesi derlenmiş fonksiyonun birebir karşılığı olmayabilir: inline edilmiş çağrılar var ve dizinleyici `#if` bloklarında yalnız ilk dalı okur.
11. **Ajanların dosya erişimi.** Yönerge yasaklıyor, transcript denetimi doğruluyor. Mekanik bir engel yok.
12. **Belirlenimcilik.** Python'un `random` modülüne bağlı; Python sürümü künyede yazılı.

## 11. Kuru koşu (2026-10-19, tmux, etiketleme yapılmadı)

- **Girdiler:**
  - `workspaces/2026-10-15_oturum_scratchpad/macho/runs_apple/tmux/macho_score.json`;
  - tmux 3.8 kaynağı `workspaces/2026-10-15_oturum_scratchpad/src/tmux-dl/tmux-3.8`. Ağaçtaki 209 `.c`/`.h` dosyası arşivdekilerle aynı.
- **Tohum:** 20261019. **Çıktı:** `workspaces/2026-10-19_g4_kuru/tmux_kor` ve `tmux_gt` (depo dışı). Karartma kararından sonra yeniden üretildi.
- **Popülasyon:** 2561 satır, 871 isimli fonksiyon. 854'ü uygun. 15'inin gövdesi bulunamadı: 13 `.cold` parçası, `OUTLINED_FUNCTION_0`, `BSDgetopt`. 2'si belirsiz: `format_window_name` (`format.c`, `names.c`) ve `osdep_event_init` (12 osdep dosyası).
- **Paket:**
  - 200 ana öğe (24 `tp`, 176 `wrong`) ve 20 yem (gövdeleri isimli havuzdan); toplam 220.
  - Kendi adı 232 kez karartıldı ve her öğede en az bir kez.
  - Dosya adı 1 öğede karartıldı (`xmalloc.c` → `FONKSIYON.c`).
  - 33 gövde kırpıldı.
- **Çapraz atıf:**
  - Gerçek adı başka bir gövdede geçen öğe 46 (43 ana, 3 yem). `capraz_atif` dağılımı: 0 → 174 öğe, 1 → 28, 2 → 8, 3 ve üstü → 10.
  - Başka öğelerin adları 78 gövdede geçiyor (133 geçiş).
  - Gerçek adı başka öğelerin dosya adında geçen öğe 1 (`xmalloc`, 2 kayıtta).
  - `capraz_atif` değerleri bağımsız bir sayımla 220 öğenin hepsinde uyuştu.
- **Sızıntı denetimi:** kör pakette 0 hata ve 2 uyarı (gövdelerde ve dosya adlarında başka öğe adları); gt'li pakette 0 hata.
- **Belirlenimcilik ve eşleşme:**
  - Aynı tohumla ikinci üretim bayt bayt aynı çıktı.
  - gt'li paketin id'leri, adayları, yemleri ve `capraz_atif` değerleri kör paketle aynı; iki `aday_paketi.jsonl` dosyasının sha256'sı aynı.
  - Öğeler ve adaylar karartma kararından önceki üretimle de aynı.

## 12. Kararlar ve bekleyenler

**Verilen kararlar (2026-10-19, ana oturum):**
1. Yalnız kendi ad karartılır; `BASKA_FONKSIYON` kaldırıldı. Çapraz atıf anahtarda işaretlenir ve `--capraz-atifsiz` ile duyarlılık analizi yapılır.
2. Dosya adının uzantısız hâli öğenin kendi adıysa dosya adı karartılır.
3. Bir gövdede tanımlayıcı olarak geçen ad yem adayı olamaz. Bu bir seçim kuralıdır; denetimde hata sayılır.
4. `tam` anahtardan gelir.
5. Yem oranı %10. Kabul oranı değerlendirici başına, dalga birleşik hesaplanır; hedef nokta tahmine uygulanır, Wilson aralığı her zaman verilir.
6. G8 cömertlik kuralı nokta tahmine bakar; aralık da raporlanır.

**Bekleyenler (karar verildi, ana oturum, 2026-10-19):**
1. **Yemin değerlendiriciye söylenip söylenmeyeceği:** söylenmez; söylenirse doğal hoşgörü ölçülemez.
2. **Gövde kırpma sınırı:** 120 satır (`--azami-satir 120`). 60 satırlık sınır uzun fonksiyonlarda amaç yargısını bozuyordu; v2 sayıları v1'le birleştirilmediği için eşdeğerlik gerekmiyor.
