# N2 ön kaydı (TASLAK): kanıt tavanı ve taze örneklemde susturmanın etkisi

- **Tarih:** 2026-10-21
- **Durum:** Taslak. Etiket görülmeden yazıldı. N1 ürüne bağlandıktan, **[S…]** maddeleri karara bağlandıktan ve §10'daki araçlar sınandıktan sonra kesinleşir ve commit'lenir. Örneklem ancak ondan sonra çekilir.
- **Plan:** v2.2 §3 N2 (`2026-10-21_plan_v2_2.md:71`), Kapı 1 (`:72`), takvim G13 (`:140`).
- **Dayanak:**
  - N0b ön kaydı `2026-10-21_g10_n0b/alt_kanal_onkayit.md` (f23f4ea) §5 ve sonucu `kesinlik_tablosu.md` (1f69b35);
  - kör protokol v2 ve çok adaylı kip: `etiket_protokolu_v2.md` §8, §9, §13 (baf6faa);
  - G4: `2026-10-19_g4_etiketleme/` (e9b9322);
  - kanıt paketi biçimi: `2026-10-19_g6_pilot/pilot_protokolu.md` §3.2.
- **Bu belgede olmayan:** kod, ölçüm, etiket. Sayılar ya belgelerden alıntıdır ya da etiketsiz sayımdır (§3.3); her birinin kaynağı yanında yazar.

## 1. Amaç ve Kapı 1'le bağ

Kapı 1: doğrulama setinde, yanlış (yanlış fiil dahil) ≤ %10 iken yakın kapsam ≥ kanıt tavanının %50'si (`plan_v2_2.md:72`). N2 geliştirme setindedir; kapı değildir.

| N2'nin çıktısı | Kapı 1'deki yeri |
|---|---|
| Tavan yordamı: vekil V-1, istem İ-1, kanıt paketi KP-1 (sha256'larla, §2) | Kapı 1'in paydası. Aynı yordam G14'te doğrulama örnekleminde koşulur **[S8]** |
| Alt kanal ve strateji kararları (§5.5, §6) | Kapı 1'de okunan ürün yapılandırması. Kapı 1 koşusundan önce tek commit'le donar |
| Uyum ve yem sonuçları (§4) | Kapı 1'in etiket yordamının geçerlilik kanıtı (aynı kip, aynı rubrik) |
| Geliştirmedeki oran R ve yanlış oranı (§5) | Kapı 1'in önceden yazılan öngörüsü. Karara girmez |
| Gözlenen oranlar | Kapı 1 örnekleminin büyüklük planı (sınıf başına ~385, `plan_v2_2.md:174`) |

## 2. Kanıt tavanı

### 2.1 Vekil (V-1)

- **Kim:** Claude Opus 5.5 ajanı **[S5]**. Değerlendiricilerden, kural yazan oturumlardan ve birbirinden ayrı oturumlar.
- **Görür:** yalnız KP-1 metni. Kaynak, Ghidra C'si, Karadul'un adı ve G4 verisi yok.
- **Oturumlar:** program başına bir oturum. Öğe kimlikleri opaktır (tohum §3.6). Öğenin kendi adresi metinde `FONKSIYON` olur; öğeler birbirine bağlanamaz.
- **Yeniden koşu:** her oturum öbür programın Çerçeve A'sından tohumla seçilmiş 25 öğeyi de adlandırır (V-1′) **[S20]**.
- **Çıktı:** her öğeye zorunlu ad (çekimser yok), güven 1-5, kanıtı anan kısa gerekçe. Eksik ya da geçersiz ad çekimser sayılır, yeniden sorulmaz; sayısı raporlanır.
- **Kuru koşu:** örneklem dışından tohumlu 10 öğe; yalnız biçim denetimi. İstem yalnız burada değişebilir; sonra İ-1 sha256 ile donar.
- **İstem İ-1** (İngilizce; gerekçe G6 ile aynı, `pilot_protokolu.md:186-189`; örnek adlar G6 P2'den, iki programda yok, `:193`):

```text
You are helping to measure how much static evidence reveals about what a function does.
Each line of <folder>/vekil_paketi.jsonl is one function from a stripped C program:
{"id": "...", "kanit": "..."}. The evidence was computed by a static analysis tool: the library
functions it calls (with counts), the program functions it calls and that call it (shown only as
FUN_<address>), callback registrations, the string literals it uses and its large constants.
FONKSIYON stands for the function itself. You do not see its code or its name.

For every id, give a name that states the function's main job, preferably a verb and an object
in snake_case (for example parse_header_field or hash_table_insert). It does not have to be the
original name. If the evidence is weak, still give your best name.

Rules:
1. Use only the evidence on that line. Do not use other lines.
2. Do not use any memory of the program's source code, even if you recognize the program.
3. Read no other file and do not search the web.

Output: <folder>/vekil.jsonl, one line per id, only these fields:
{"id": "...", "isim": "...", "guven": <1-5>, "gerekce": "<at most 20 words; name the evidence used>"}
guven: 1 = guess, 5 = certain. When done, write only "VEKIL TAMAM, <line count> lines".
```

### 2.2 Kanıt paketi (KP-1)

- **Kaynak:** N1 sonrası ürün koşusunun (§3.2) `static/` çıktıları üzerinde `karadul.reconstruction.tarif.build_evidence` (`EvidencePack` alanları, `evidence.py:34-48`).
- **Metin biçimi ve sınırlar:** G6 §3.2 (`pilot_protokolu.md:155-171`; `kanit_alanlari`, `llm_pilot.py:433-469`):
  - kütüphane çağrıları, sayılarıyla;
  - iç çağrılanlar (en çok 40) ve çağıranlar (en çok 30);
  - geri çağrı kayıtları, iki yönde (en çok 20'şer);
  - dizgiler (en çok 40, her biri en çok 120 karakter);
  - büyük sabitler (en çok 20).
- **Komşu adları:** yok. Bütün komşular çıplak `FUN_<adres>` **[S6]**.
- **Sürüm künyesi:** `evidence.py` ve paket üreticisinin sha256'sı; koşu kimliği; `ghidra_functions.json` ve `ghidra_xrefs.json` sha256'ları; program başına paket dosyasının sha256'sı. Tavan her yerde "tavan(KP-1, V-1, İ-1)" diye anılır. Bunlardan biri değişirse yeni sürümdür.
- **Sızıntı denetimi:** hedefin gerçek adı dizgi alanı dışında geçmez (`kanit_hedef_sizintisi`, `llm_pilot.py:472-476`); hata 0 olmalı. Adın dizgide geçmesi kanıttır; sayısı raporlanır.

### 2.3 Çok adaylı kör etiketleme

- `etiket_paketi.py uret-cok`, program başına bir paket: `--adresler` (§3.4), `--azami-satir 120` (protokol §12), `--sira-tohumu`, `--yem-tohumu`, `--guven-alani guven`.
- **Sistemler (adaylar):**
  - KD1: Karadul, N1 sonrası ürün adı ve güveni. Adsızsa `aday: null`, `durum: isimsiz`.
  - V1: vekil. V1′: yeniden koşu (25 + 25 öğe).
  - KD0: taban v2 adı, yalnız Çerçeve A'da **[S21]**.
- Değerlendirici sistem kimliğini görmez. Adaylar normalize gösterilir; aynı normalize ad tek adaydır (protokol §13.2, `etiket_protokolu_v2.md:382-384`).
- Paket, sızıntı denetimi 0 hata vermeden dağıtılmaz (protokol §3.0).

### 2.4 Tavanın tanımı

- **Birincil:** t(p) = program p'nin Çerçeve A'sında V1 adı yakın (tam + doğru tarif) olan fonksiyonların payı **[S7]**.
  - Payda Çerçeve A'nın bütün fonksiyonlarıdır. Vekilin geçersiz adı yakın sayılmaz.
  - Yanlış oranı tanıma girmez; yanında raporlanır.
- **Makro tavan:** t̄ = t(p)'lerin ortalaması.
- **İkincil (yalnız rapor):**
  - vekilin güvenine göre risk-kapsam ve yanlış ≤ %10 noktasındaki yakın kapsam;
  - birleşik tavan: V1 ya da KD1 adı yakın olan fonksiyonların payı.

### 2.5 Tavanın belirsizliği

1. **Örneklem:** program başına Wilson %95. t̄ ve R için kaynak dosya kümeli önyükleme (bootstrap), program katmanlı **[S19]**.
2. **Değerlendirici:** E1, E2 ve hakemli etiketle üç ayrı t(p).
3. **Vekil koşusu:** V1 ile V1′ çiftlerinde normalize ad eşleşmesi ve yakın uyumu.
4. **Ezber göstergesi:** V1'in otomatik `tam` adlarından, gerçek adın normalize biçimi paket dizgilerinde geçmeyenlerin sayısı. Kanıtsız tam eşleşme ezber ya da şanstır; tavanı şişirir.
5. **Model bağımlılığı:** ölçülmez (tek vekil). Sınırlama olarak yazılır.

## 3. Taze örneklem

### 3.1 Evren

- Geliştirme seti, Mac: tmux 3.8 ve htop 3.5.3 (Homebrew; `dogrulama_seti_onkayit.md` §8.1) **[S1]**.
- **Popülasyon P:** `macho_score.json` satırlarından `sinif == "program"` ve durumu `tp`, `wrong` ya da `unnamed` olanlar, yani isim bekleyenler (`macho_f1.py:18-25`). Kaynakta gövdesi tek anlamlı bulunmayanlar dışarıda kalır (`etiket_paketi.resolve_body`); sayıları künyeye yazılır.

### 3.2 Ürün koşusu (N1 sonrası)

- N1'in birleştiği commit'te `macho_measure.py all` (Ghidra 12.1.2), etiket `n2-<commit>`. Çıktılar: `naming_map.json`, `naming_provenance.json`, `macho_score.json`.
- **Ön koşullar** (biri tutmazsa N2 durur, D1):
  1. Aynı Ghidra çıktısında c_namer iki kez koşulur; `naming_map.json` bayt bayt aynı (ÖL-7; b7faeac).
  2. **Susturma denetimi:** köken kayıtları `alt_kanal.py sinifla` ile (sha256 `d0e6f544…`) yeniden sınıflanır. N0b'de susan alt kanallardan gelen ad sayısı 0 olmalı (`kesinlik_tablosu.md:69`).
  3. Ghidra çıktılarının sha256'sı taban v2'ninkiyle karşılaştırılır; fark varsa raporlanır.

### 3.3 Tazelik

- **Öğe** = (fonksiyon, ad).
- **Dışarıda:** G4'ün dört paketindeki ana öğeler ve yem gövdeleri **[S2]**. Liste, anahtarların yalnız `addr` ve `yem` alanlarından kurulur.
- **Halef istisnası [S4]:** G4'teki bir fonksiyonun N1 sonrası adı taban adda farklıysa ve yeni ad KS-1'den gelmiyorsa öğe tazedir. Gerekçe: yeni adın doğruluğu G4'te görülmedi.
- **KS-1:** N1'in kural yazarken GT'sine ya da etiketine baktığı öğeler taze sayılmaz. N1 bunu kayda yazmalıdır. Yazmazsa KS-1 tabakası "taze değil" diye raporlanır ve D8'de kullanılmaz.
- **G6 kümeleri** dışlanmaz **[S3]**; kesişim sayılır.

**Etiketsiz sayım** (taban v2 üzerinden; N1 sonrası değişir) [hesap]:

| | tmux | htop |
|---|---|---|
| P | 2545 | 597 |
| G4 ana öğe + yem gövdesi | 497 + 58 (yem gövdelerinin 17'si öbür paketin ana öğesi) | 97 + 10 |
| Taze P | 2007 | 490 |
| … bunun taban v2'de adlı olanı | 319 | 4 |
| Taze `kebap_ad` | 53 | 0 |
| Taze `oz_ad` | 51 | 0 |
| Taze `api_param_reverse` | 3 | 0 |
| `api_param_reverse` halefi: taze / G4 fonksiyonunda | 3 / 13 | 0 / 0 |
| G6 kümeleriyle kesişim | 123 | 130 |

- **Yöntem:** G4 anahtarlarının `addr` ve `yem` alanları; N0b kayıtlarının (`kayitlar_*.jsonl`) `adres`, `strateji`, `alt_kanal` ve `halef_urun` alanları; taban v2 `macho_score.json`'ın `addr`, `sinif` ve `status` alanları. Etiket, amaç cümlesi ve gerçek ad okunmadı.
- htop'taki 4 adlı fonksiyon, G4'te gövdesi belirsiz diye dışarıda kalan 4 öğedir (`g4_etiketleme/onkayit.md:21`). htop'ta etiketlenebilir taze adlı öğe yoktur.
- Halef sayısı 16, N0b'nin halef tablosuyla tutarlı (`alt_kanal_onkayit.md:166-177`, susan dokuz alt kanalın `api_param_reverse` sütunu).

### 3.4 Çerçeveler ve tabakalar

- **Çerçeve A (rastgele):** taze P'den program başına 200 fonksiyon **[S10]**. Tavan, Karadul kapsamı, R ve önce/sonra (KD0) buradan ölçülür.
- **Çerçeve B (tabakalı):** N1 sonrası Karadul adlarından taze olanlar. Tabaka sırası:
  1. `kebap_ad` (birincil sınama, H1);
  2. `oz_ad`;
  3. KS-1, N1'in her türü ayrı;
  4. `api_param_reverse` ve halefler;
  5. öbür stratejiler (`binary_extract` ve N1 sonrası görülen her yeni strateji).
- Tabaka nüfusu ≤ 100 ise hepsi alınır, değilse tohumlu 100 **[S11]**.
- Paket = A ∪ B; tavan ve susturma etkisi aynı etiketleme dalgasında ölçülür. A'daki bir öğe kendi tabakasının hesabına da girer.
- Vekil A ∪ B'nin hepsini adlandırır. Tavan yalnız A'dan hesaplanır; B'deki V1 adları tabaka başına Karadul–vekil karşılaştırması içindir.

### 3.5 Büyüklük

- **Tavan:** 200 öğede yarı genişlik en kötü durumda ±6,9 puan (`etiket_protokolu_v2.md:262`). ±5 için 385 gerekir (`:261`).
- **Karar tabakaları:** küçük havuzlar sayımla (hepsi) alınır. `karar()` kuralının sınırları (`alt_kanal.py:434-457`; n = 35 ve 100 satırları `alt_kanal_onkayit.md:263-272`'den, öbürleri aynı kuralla [hesap]):

| n | "doğrulandı" için en çok yanlış | "zayıf" için en az yanlış |
|---|---|---|
| 19 | — | 5 |
| 35 | 0 | 7 |
| 53 | 1 | 10 |
| 73 | 2 | 13 |
| 100 | 4 | 16 |

- **H1'in gücü** (n = 53, ikiterimli dağılım, aynı kural) [hesap]:
  - gerçek yanlış %35,5 (L3 okuması, `kesinlik_tablosu.md:64`): %99,7 olasılıkla "zayıf";
  - gerçek yanlış %10,8 (L1 okuması, `:19`): %92,7 "belirsiz", %5,5 "zayıf";
  - gerçek yanlış %20: %63,6 "zayıf".
- Sonuç: N2, `kebap_ad`'ın iki okumasını ayırır; "doğrulandı" ancak en çok 1 yanlışla çıkar.

### 3.6 Tohum ve belirlenimcilik

- **Yöntem:** tohum = `int(SHA-256(metin)[:16], 16)` (G6 ile aynı, `pilot_protokolu.md:82`).

| Kullanım | Metin | Tohum |
|---|---|---|
| Çerçeve A ve B | `karadul-n2-orneklem-v1` | 4484705772150770605 |
| Paket sırası (`--sira-tohumu`) | `karadul-n2-sira-v1` | 8234616437894371555 |
| Yem (`--yem-tohumu`) | `karadul-n2-yem-v1` | 3924096130379305062 |
| Kuru koşu, sonra V-1′ alt kümesi | `karadul-n2-vekil-tekrar-v1` | 5837463457169411576 |
| Vekil öğe kimlikleri | `karadul-n2-vekil-kimlik-v1` | 7155423372385705681 |
| Önyükleme | `karadul-n2-onyukleme-v1` | 18221795844361697329 |

- **Çekim:** her çerçeve adrese göre (tam sayı, artan) sıralanır. Tek `random.Random(tohum)` nesnesiyle sırayla çekilir: tmux A, htop A, sonra §3.4'teki tabaka sırası. Çekim sırası, Python sürümü ve girdilerin sha256'sı künyeye yazılır.
- Aynı girdi ve tohumla adres listesi bayt bayt aynı çıkmalıdır.

### 3.7 Yem

- Fonksiyonların tohumla seçilen %10'una birer yem aday konur (protokol §13.2, `etiket_protokolu_v2.md:394-397`). Değerlendiriciye söylenmez (`:334`).
- Kabul oranı değerlendirici başına; hedef nokta tahminde ≤ %5; Wilson aralığı her zaman verilir.
- Pakette ~500 fonksiyon, yani ~50-60 yem beklenir. 0 kabulde üst sınır %6,0-%7,1'dir [hesap]; "≤ %5" aralıkla gösterilemez (bilinen sınır, `:272`).

## 4. Etiketleme

### 4.1 Değerlendiriciler ve ayrılık

- **E1, E2:** iki bağımsız Claude Opus 5.5 ajanı **[S12]**. İkisi de bütün paketleri aynı kimliklerle etiketler. Her aşama ayrı çağrıdır (protokol §8, `etiket_protokolu_v2.md:201`).
- **E3 (hakem):** yalnız ayrışan adayların fonksiyonları (§4.4).
- **Ayrılık:**
  - Değerlendiriciler N0b, N1 ve N2 kararlarını uygulayan oturumlardan ve vekil oturumlarından ayrıdır. Yalnız rubriği ve paketi görürler.
  - Anahtarlar ve vekil kimlik eşlemesi ajanların eriştiği geçici dizinde tutulmaz (G4 dersi, `g4_etiketleme/sonuc.md:90`).
  - Başka dosyaya erişilmediği transcript'ten denetlenir; anahtar erişimi ayrıca aranır.
- **Ajan bütçesi [S22]:** vekil 2, E1 2, E2 2, E3 2: toplam 8 çağrı. Aynı anda en çok 2 (`plan_v2_2.md:132`). 20 dakikayı aşacak her ajana bekçi kurulur.

### 4.2 Rubrik

- `etiket_rehberi.md` sürüm 2 (sha256 `70e4cff7b679f855…`, `g4_etiketleme/onkayit.md:4`).
- Etiketler: `tam` (anahtardaki otomatik eşleşmeden), `dogru_tarif`, `yalniz_alan`, `yanlis`. Yanlış fiil `yanlis`'in içindedir (kural 4).
- **Ek alan [S13]:** `yanlis` etiketinde `yanlis_turu`: `fiil` ya da `diger`. Etiketi ve kararları değiştirmez; N4'ün yanlış fiil tabanını verir.

### 4.3 Uyum

- E1 ile E2 arasında, yem dışı adaylarda:
  - Cohen κ: üç sınıf (yakın, yalnız alan, yanlış), yakın/değil, yanlış/değil;
  - Krippendorff α, üç sınıf (`yontem_taramasi.md:109`).
- Sistem (KD1, V1) ve program başına ayrıca.
- G4'teki karşılıklar: dört etiket κ 0,736, yakın/değil 0,953 (`g4_etiketleme/sonuc.md:41-44`). Yanlış/değil G4'te hesaplanmadı; karar ölçüsü olduğu için N2'de birincil uyum ölçüsüdür.

### 4.4 Anlaşmazlık

- E1 ile E2 üç sınıfta ayrışırsa aday E3'e gider.
- E3, ayrışan adayların fonksiyonlarından kurulan ayrı paketi aynı iki aşamayla etiketler. E3'ün ayrışmayan adaylara verdiği etiket kullanılmaz.
- **Nihai sınıf:** çoğunluk. Üçü ayrı sınıf verirse `yalniz_alan`; duyarlılıkta `yanlis` **[S15]**.
- `tam` her durumda anahtardan gelir.

## 5. Ölçüler ve kararlar

### 5.1 Etiketsiz ölçüler

- **Susturma denetimi** (§3.2).
- **Yeni ad payı:** N1 sonrası her ad, taban v2'ye göre bir sınıfa girer:
  - `korunan`: aynı taban ad, aynı strateji ya da alt kanal;
  - `ks1`: KS-1 türü;
  - `halef`: taban v2 adı susan bir alt kanaldandı, şimdi başka stratejiden ad aldı;
  - `yeni_diger`: taban v2'de adsızdı, şimdi KS-1 dışından ad aldı;
  - `degisen`: aynı strateji, farklı taban ad (0 beklenir);
  - ayrıca `silinen` (adı `FUN_`'a dönenler).
- Pay = (`ks1` + `halef` + `yeni_diger` + `degisen`) / N1 sonrası bütün adlar, program başına.
- Gerçek halefler, N0b'nin halef öngörüsüyle (`kapsam.json`, `halef_urun`) karşılaştırılır.

### 5.2 Susturma sonrası yanlış oranı ve kapsam (KD1)

- **Tabaka başına:** n; tam, yakın, yalnız alan ve yanlış sayıları; Wilson %95.
- **Program başına tabakalı yanlış oranı:** ŷ(p) = Σₕ Nₕ(p)·ŷₕ / Σₕ Nₕ(p).
  - Nₕ(p): ürün koşusunda tabaka h'deki ad sayısı (köken kaydından).
  - ŷₕ: tabakanın taze etiketli öğelerindeki yanlış payı.
  - Taze öğesi olmayan tabaka iki uçla (%0 ve %100) ayrıca gösterilir.
  - Aralık: tabaka içinde dosya kümeli önyükleme, 10 000 tekrar.
- **Doğrudan tahmin:** Çerçeve A'daki KD1 adlarının yanlış oranı (küçük n; yalnız rapor).
- **Kapsam:** Çerçeve A'da yakın kapsam k(p) ve verilen kapsam; makro k̄.
- **Önce/sonra:** Çerçeve A'da KD0 ile KD1: yanlış oranı ve yakın kapsam; eşli fark, önyüklemeyle.
- Adlı öğesi olmayan programda (htop beklenir) yanlış oranı "tanımsız" yazılır ve makroya girmez.

### 5.3 Tavan ve oran R

- t(p), t̄, k̄ ve R = k̄ / t̄ **[S9]**; R'nin aralığı eşli önyüklemeyle (aynı fonksiyonlarda KD1 ve V1).
- Program başına R yalnız rapordur.
- Yanlarında program sınıfı eş değişkenleri (§5.6).

### 5.4 Risk-kapsam

- **Kademe eğrisi.** Sıra şimdi, N0b'nin G4 nokta tahminlerine göre yazıldı (`kesinlik_tablosu.md:16, 19, 46`):
  - K0: KS-1;
  - K1: K0 + `oz_ad`;
  - K2: K1 + `kebap_ad`;
  - K3: K2 + `api_param_reverse` ve halefler;
  - K4: K3 + öbür stratejiler.
- Her kademede tabakalı yanlış oranı ve Çerçeve A'da yakın kapsam verilir.
- **Güven eşiği tablosu:** `puan-cok` risk-kapsam çıktısı (KD1 ürün güveni; V1 1-5).
- Literatürdeki ana sayı da raporlanır: yanlış ≤ %10 noktasında yakın kapsam (`yontem_taramasi.md:110`).

### 5.5 Alt kanal ve strateji kararları

- **Kural:** N0b'nin `karar()`'ı aynen (`alt_kanal.py:434-457`; `alt_kanal_onkayit.md:232-239`) **[S16]**:
  - "doğrulandı": U ≤ %10;
  - "belirsiz": L ≤ %10 < U;
  - "zayıf": L > %10;
  - "ölçülemedi": n = 0.
- Yalnız taze, hakemli etiketlerle; programlar birleşik.
- **Okuma sırası:** önce H1 (`kebap_ad`) okunur ve kaydedilir. Sonra `oz_ad`, KS-1, halefler, öbürleri.
- **Yanında:** yalnız E1'le ve yalnız E2'yle verilen kararlar; `--capraz-atifsiz` duyarlılığı.
- Çoklu karşılaştırma düzeltmesi yapılmaz (N0b ile aynı, `alt_kanal_onkayit.md:290`).
- Kararın ürüne etkisi §6'dadır.

### 5.6 Eş değişkenler

- Program başına dizgi zenginliği ve boyut tabakası (`plan_v2_2.md:119-122`).
- Değerler kilitli değilse N2 seçiminden önce GT'siz hesaplanır ve ön kayda eklenir.

## 6. Önceden yazılan dallar

Ürün değişiklikleri (D5-D10) Kapı 1 koşusundan önce, karar tablosundan mekanik olarak, tek commit'te yapılır.

| # | Durum | Ne yapılır |
|---|---|---|
| D1 | Ön koşul tutmuyor (§3.2) | N2 durur; düzeltme N1'de; örneklem çekilmez |
| D2 | Paket sızıntı denetimi hata veriyor | Paket dağıtılmaz |
| D3 | Uyum eşiğin altında **[S14]** | Kanal kararları uygulanmaz; ürün N1'deki gibi kalır. Sayılar "uyum düşük" notuyla raporlanır. Rubrik sorunu ayrı ön kayıtla ele alınır |
| D4 | Bir değerlendiricinin yem kabulü > %5 (nokta) | Karar yalnız öbür değerlendiricinin etiketleriyle verilir; bu kayda yazılır. İkisi de aşarsa D3 uygulanır |
| D5 | `kebap_ad` | "zayıf" → susar. "belirsiz" → değişmez ("doğrulanmadı"). "doğrulandı" → etiketi "doğrulandı" olur |
| D6 | `oz_ad` | D5 ile aynı |
| D7 | `oz_ad` ve `kebap_ad` ikisi de susuyor | `string_context` tümüyle susar (`plan_v2_2.md:190` riski). Ürün KS-1 ve öbür stratejilerle ad verir |
| D8 | KS-1 türü (yalnız taze sayılan) | "zayıf" → tür susar; N1'in o tür için iddiası "taze veride tekrarlanmadı" diye kaydedilir. Zayıf değil ama yakın oranının Wilson üst sınırı < %95 → tür ad vermeyi sürdürür, N6'da çapa olamaz |
| D9 | Halefler ve öbür stratejiler | Aynı kural. Taze n = 0 ise **[S17]** |
| D10 | D5-D9'dan sonra, adlı öğesi olan bir programda ürünün tabakalı yanlış oranının alt sınırı > %10 **[S18]** | K4'ten geriye doğru "zayıf" olmayan en geniş kademe seçilir. K0 da zayıfsa ürün K0'da kalır ve sonuç kaydedilir |
| D11 | R ≥ 1 (nokta tahmin) | Vekil Karadul'dan zayıf; birincil tavan geçersiz. Kapı 1'den önce, doğrulamaya bakmadan birleşik tavan (§2.4) birincil olur; değişiklik kaydı yazılır |
| D12 | V1–V1′ yakın κ < 0,60 | Kapı 1'de vekil iki kez koşulur; tavan iki koşunun ortalamasıdır |
| D13 | V1'in tam eşleşmelerinin yarısından çoğu kanıtsız (§2.5 madde 4) | Tavan "ezber şüpheli" notu alır; Kapı 1 aynı tanımla okunur |
| D14 | t̄ < %10 | Bilgi: kanıt paketi isim için zayıf. KP-1 bu sonuca bakılarak değiştirilmez |
| D15 | N2 bir günü aşıyor | Kapı 1 kayar; ölçütler kaymaz (`plan_v2_2.md:175`) |

## 7. Yasaklar ve sızıntı korumaları

1. **Doğrulama seti:** N2 boyunca analiz edilmez, okunmaz (`dogrulama_seti_onkayit.md` §2 madde 1-2). `targets/`, `docs/arge/dogrulama_seti_kanit/` ve `docs/arge/test_seti*` açılmaz. G14'teki tavan ölçümü Kapı 1'in bakışına sayılır (`dogrulama_seti_onkayit.md` §14).
2. **G4:** amaç ve etiket dosyaları ile anahtarların `addr` ve `yem` dışındaki alanları kullanılmaz. G4 öğeleri tazelik kuralıyla dışarıdadır (§3.3). G4 etiketleriyle hiçbir kanalın kararı değişmez (`alt_kanal_onkayit.md:256`).
3. **Kural ayarı:** taze etiketlere bakılarak tanım, desen, eşik, KP-1 ya da istem değişmez. Ürüne yalnız §6'daki değişiklikler girer. Başka bir değişiklik gerekirse Kapı 1'den sonraya kalır ya da yeni bir taze örneklem ister.
4. N2 bittikten sonra etiketleri geliştirme verisidir; sonraki bir taze ölçümde kullanılmaz.
5. **Görünürlük:** vekil yalnız KP-1'i görür; değerlendirici yalnız rubriği ve paketi. Ön etiket hiç kimseye gösterilmez: KD1 durumu, otomatik tam, başka değerlendiricinin etiketi (protokol §2, `etiket_protokolu_v2.md:37`).
6. **Dondurma sırası (sha256):** ön kayıt commit'i → ürün koşusu → adres listeleri → vekil adları → paketler (sızıntı 0) → amaç dosyaları (donma kaydı) → etiketler → analiz betiğinin sha256 denetimi (`alt_kanal_olc.py`'deki gibi) → karar tablosu.
7. Gövdeli paketler depoya girmez (`g4_etiketleme/sonuc.md:5`). Depo açıktır.

## 8. Beklenti ve sınırlamalar

**Önceden yazılan beklenti** (karar dışı; G4 tabanlı oranların N1 sonrası tmux ürününe uygulanması) [hesap]:
- **Kalan adlar:** `oz_ad` 126, `kebap_ad` 147 (`alt_kanal_onkayit.md:151, 154`), `api_param_reverse` 12 (`:60`), `binary_extract` 1 ve 16 halef (§3.3). KS-1 hariç.
- **Yakın kapsam:** 126 × %84,6 + 147 × %8,1 ≈ 118 ad, P'nin %4,7'si (`kesinlik_tablosu.md:16, 19`).
  - KS-1 en çok %10,7 ekler (kâhin tavanı, `2026-10-21_v2_1/onuncu_adam.md:303`).
  - htop'ta ≈ %0: assert ve `__func__` dizgisi yok (`g7_alici_tip/rapor.md:187`), öbür alt kanallar susuyor.
- **Yanlış oranı:** `api_param_reverse` G4'te 5/5 yanlış (`kesinlik_tablosu.md:46`). Halefler de öyleyse tmux'ta ≈ %18; `api_param_reverse` ve halefler susarsa ≈ %9,7.
- **Kapı 1 için anlamı:** makro yakın kapsam %2,3-%7,7 beklenir. Kapsam koşulu için makro tavanın en çok bunun iki katı (%4,7-%15,4) olması gerekir.

**Sınırlamalar:**
- Vekil ve değerlendiriciler aynı model ailesinden ve kural yazan modelle aynı aileden. Öz yeğleme tavanı şişirebilir; kapıyı zorlaştırır.
- Karar tabakaları tek programdan (tmux) gelir. htop yalnız tavana ve kapsama girer.
- Wilson bağımsızlık varsayar; aynı dosyadan gelen öğeler bağımlıdır (`etiket_protokolu_v2.md:263`).
- tmux ünlü bir program; vekilde ve değerlendiricide ezber dışlanamaz (`:281`).

## 9. Açık seçimler

Kararı Berke verir. Her satırda öneri ve tek cümlelik gerekçe var.

| # | Seçim | Öneri | Gerekçe |
|---|---|---|---|
| S1 | Evren | Mac tmux + htop. Debian 13'ün 8 programı girmez | Etiket hattı ELF satırını ve Debian kaynak ağacını okumuyor; karar tabakalarının taze havuzu zaten tmux'ta; Debian'daki tmux ve htop aynı kaynak fonksiyonlarıdır. Alternatif: Mac'in öbür 6 geliştirme programı (KS-1'in tek taze sınaması olur, `macho_corpus.json` kaydı ve kaynak ağacı ister) |
| S2 | G4 yem gövdeleri dışlansın mı | Evet | G4'te amaç cümleleri yazıldı; bedeli küçük (`kebap_ad` 57 → 53) |
| S3 | G6 kümeleri dışlansın mı | Hayır | G6'nın Karadul koşulu taban v2'ye sabit; dışlama htop havuzunu 490'dan 360'a indirir |
| S4 | Halef istisnası (§3.3) | Evet | `api_param_reverse` havuzu 6'dan 19'a çıkar; yeni adın doğruluğu G4'te görülmedi |
| S5 | Vekil | Claude Opus 5.5 ajanı | Tavan, kanıtın izin verdiği en iyi sonuca yakın olmalı; zayıf vekil kapıyı kolaylaştırır. Alternatif: Qwen3.8-27B (G6 hattı, belirlenimci ama daha zayıf) |
| S6 | KP-1'de komşu adları | Yok | Kapı 1'deki Karadul adları komşu adı kullanmıyor (yayılım N6'da); payda incelenen kurallardan bağımsız kalır |
| S7 | Tavan tanımı | Zorunlu adla vekil yakın kapsamı | Plan v2 G7'nin "başarı oranı" (`2026-10-17_plan_v2.md:127`); en tutucu payda |
| S8 | Kapı 1'in paydası | Aynı yordam G14'te doğrulama örnekleminde | Tavan programa bağlı; geliştirmedeki tavan doğrulama kapsamının paydası olamaz |
| S9 | R'nin birleşimi | Makro kapsam / makro tavan | Program başına oran, tavanı küçük programda patlar |
| S10 | Çerçeve A | Program başına 200 | ±6,9 puan; 385, iki değerlendiricinin yükünü ikiye katlar |
| S11 | Tabaka üst sınırı | 100 | Bilinen havuzların hepsi bunun altında; sayım yapılır |
| S12 | Değerlendiriciler | İki Opus 5.5 + hakem | G4 ve N0b'yle karşılaştırılabilir; `kebap_ad` ayrışması tek değerlendiricinin yetmediğini gösterdi |
| S13 | `yanlis_turu` alanı | Evet | Kararı değiştirmez; N4 yanlış fiil tabanını ister, gerekçe metninden ayıklamak güvenilmez |
| S14 | Uyum eşiği | κ (yanlış/değil) ≥ 0,60 ve κ (yakın/değil) ≥ 0,60 | Yaygın "önemli uyum" sınırı (Landis ve Koch 1977; depoda doğrulanmadı); G4'ün dört etiket κ'sının (0,736) belirgin altı |
| S15 | Üç ayrı sınıf | `yalniz_alan`; duyarlılıkta `yanlis` | İki sistemi aynı yöne itmez |
| S16 | Karar kuralı | N0b'nin kuralı aynen | N0b "belirsiz" kanalların N2'de yeniden ölçüleceğini yazdı (`alt_kanal_onkayit.md:237, 253`); katı kural bu n'lerde iyi kanalı da çoğunlukla susturur (`:302`) |
| S17 | Taze n = 0 olan strateji | Karar yok; "ölçülmedi" etiketiyle sürer | Yokluğa dayanan susturma `binary_extract` gibi doğrulamada önemli olabilecek kanalı kapatır. Alternatif: susar (agresif emsali) |
| S18 | D10 (kesinlik turu) | Uygulanır | Kapı 1, geliştirmede bile tutmadığı bilinen yapılandırmayı okumasın |
| S19 | Önyükleme birimi | Kaynak dosya, program katmanlı | İki programla program düzeyinde kümeli önyükleme tanımsız |
| S20 | V-1′ | Program başına 25, öbür programın oturumunda | Ek çağrı gerektirmeden koşu değişkenliğini ölçer |
| S21 | KD0 adayları | Çerçeve A'da evet | Aynı taze fonksiyonlarda önce/sonra; tmux'ta ~20 ek aday (taze P'nin 212 susan adının 200/2007'si) |
| S22 | Ajan bütçesi | 8 çağrı, aynı anda en çok 2 | Plan v2.2 §6 sınırı; CLAUDE.md §26'nın "3-5" yönergesini aşıyor, Berke onayı gerekir |

## 10. Kesinleşmeden önce

1. N1 ürüne bağlanır. N1 şunları yazar: KS-1 türlerinin adları ve köken kaydındaki alanları; kural yazarken GT'sine ya da etiketine bakılan öğeler; ürün commit'i.
2. Berke **[S…]** maddelerini karara bağlar.
3. Eksik araçlar yazılır; her biri testli ve mutant kanıtlı (plan v2 §3 madde 9):
   - seçim betiği: tazelik, tabaka, gövde süzgeci, tohum → `--adresler`;
   - aday dönüştürücü: köken kaydı ve `naming_map` → KD1 ve KD0 satırları;
   - vekil paketi üreticisi ve vekil çıktısı → V1 ve V1′ satırları;
   - hakem akışı ve çoğunluk birleştirme;
   - çok adaylı uyum (κ, α);
   - analiz: tabaka katılımı, tabakalı oran, makro, R, dosya kümeli önyükleme, kademe eğrisi, `karar()`;
   - yeni ad payı ve halef karşılaştırması;
   - dizgi zenginliği hesaplayıcısı.
4. Vekil kuru koşusu yapılır; İ-1 donar.
5. Belge "TASLAK" ibaresinden çıkarılıp commit'lenir. Seçim, vekil ve etiketleme ancak ondan sonra başlar.
