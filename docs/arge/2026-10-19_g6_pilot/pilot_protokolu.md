# G6 LLM pilotu: protokol (ön kayıt taslağı)

- **Tarih:** 2026-10-19
- **Durum:** Taslak. Berke onaylayıp commit'lediğinde ön kayıt olur. Bu commit, örneklem çekilmeden ve hiçbir model çıktısı görülmeden önce atılmalı.
- **Plan bağlantısı:** `docs/arge/2026-10-17_plan_v2.md` §5 (G6 satırı, G8 karar kuralları, Ürün izi / KaradulLM) ve §3 (çalışma ilkeleri).
- **Model:** `model_secimi.md`. Birincil Qwen3.6-27B, yedek Gemma 4 26B-A4B-it (QAT). İkisi de 4 bit, MLX.
- **Değerlendirme araçları ve yordamı:** `scripts/measurement/etiket_paketi.py`, `scripts/measurement/etiket_puan.py` ve `docs/arge/etiket_protokolu_v2.md`. Bunları başka bir ajan yazıyor; 2026-10-19 öğleden sonra üçü de depoda ama commit'lenmemiş. Protokol v2, G4 için tek adaylı bir tasarım anlatıyor. G6'nın ihtiyacı olan çok adaylı kip henüz yok; bu belgedeki ilgili arayüz varsayımları §9.1'de **VARSAYIM** diye işaretli.
- **Bu belge kod içermez.** Harness'ı (pilotu koşturan betik) kimin yazacağına ana oturum karar verir (§17).

## 0. Sorular

| # | Soru | Ölçü |
|---|---|---|
| S1 | Ghidra C'si + yerel LLM, sıfır atışta, Karadul'dan kaç puan fazla yakın isim veriyor? G8 kuralının ilk koşulu budur | Δb = yakın(B) − yakın(A) |
| S2 | Karadul'un kanıt paketi aynı LLM'e ne katıyor? KaradulLM'in gerekçesi buna dayanır | Δc = yakın(C) − yakın(A); Δcb = yakın(C) − yakın(B) |
| S3 | Yanlış ≤ %10 iken her sistem ne kadar yakın kapsam veriyor? | Risk-kapsam eğrileri (§10.4) |
| S4 | LLM "bilmiyorum" diyebildiğinde yanlış oranı ne kadar düşüyor, kapsamdan ne kadar kaybediliyor? | B-Ç ve C-Ç koşulları |
| S5 | LLM aynı girdiye aynı cevabı veriyor mu? Fonksiyon başına maliyeti ne? | §7, §10.7 |

Kayıt için (karar değil): Onuncu Adam'ın öngörüsü, ünlü açık kaynakta gevşek isim ölçütünün LLM'in "ev sahası" olduğu (`docs/arge/2026-10-17_v2/onuncu_adam.md` İ3). Pilot bu öngörüyü geliştirme setinde sınar.

## 1. Künye

Her koşu, başında ve sonunda `kunye.json` yazar. Alanlar:

- **Karadul:** commit; taban v2 koşusunun dizini ve kimliği; Ghidra sürümü (12.1.2 olmalı); özgün ve strip'li ikilinin sha256'sı ve UUID'si; export trie denetiminin sonucu; popülasyon dosyasının (`macho_score.json`) sha256'sı; Karadul yapılandırması K (§3.1).
- **Model:** HF depo kimliği; revizyon (commit sha); her safetensors dosyasının sha256'sı; sohbet şablonunun sha256'sı.
- **Çalışma zamanı:** Python, mlx ve mlx_lm sürümleri; macOS sürümü; `hw.model`, bellek, GPU çekirdek sayısı.
- **İstem:** beş istem dosyasının sha256'sı (§4) ve istem sürümü (`P1`).
- **Diğer:** harness commit'i; tohumlar (§2); başlangıç ve bitiş zamanı; koşu sırasında Ghidra'nın çalışıp çalışmadığı.

## 2. Örneklem

### 2.1 Popülasyon

- **Kaynak:** Yeni Mac ölçüm hattının taban v2 koşusu (plan G3(d) ve G4). Puanlayıcının çıktısı `macho_score.json` `rows`, şu anki taslakta `scripts/measurement/macho_f1.py score`.
- **İsim bekleyen fonksiyonlar:** GT'de olup strip'li kopyada Ghidra'nın adlandıramadığı, thunk olmayan fonksiyonlar. Tanım `macho_f1.py`'deki gibi.
- Yalnız `sinif == "program"` olanlar alınır. `.cold` ve `OUTLINED_FUNCTION` parçaları örneklenmez (plan §4 "Payda").
- Karadul'un durumu örneklemeyi etkilemez. `tp`, `wrong` ve `unnamed` fonksiyonların hepsi popülasyonda.

### 2.2 Dışlananlar

Dışlanan her fonksiyon sayısıyla künyeye yazılır.
1. Kaynakta gövdesi tek anlamlı bulunamayanlar: makroyla üretilenler ya da birden çok farklı tanımı olanlar. Değerlendiricinin amaç cümlesi yazabilmesi için gövde gerekir; kural `etiket_paketi.py`'deki ile aynı.
2. Ghidra C dosyası olmayanlar.

Başka dışlama yoktur. Özellikle uzunluk filtresi uygulanmaz.

### 2.3 Çekim

- **Tohum:** `int(SHA-256("karadul-g6-pilot-orneklem-2026-10-19")[:16], 16)` = **18166492616011533410** (hex `fc1c58c8b81fcc62`). Yöntem, test seti kurasındakiyle aynı. Denetim: aynı yöntem `karadul-test-seti-kura-2026-10-15` için kilit belgesindeki 1357717698366421230 değerini veriyor.
- **Yöntem:**
  - Her programın popülasyonu adrese göre (tam sayı, artan) sıralanır.
  - Tek bir `random.Random(tohum)` nesnesiyle önce htop'tan, sonra tmux'tan `sample(liste, 150)` çekilir.
  - Çekim sırası kaydedilir. Python sürümü künyeye yazılır.
- **Ana örneklem:** 300 fonksiyon (150 + 150).

### 2.4 Alt kümeler

Ana örneklemle çakışmayan kümeler, aynı `Random` nesnesinin devamıyla çekilir.

| Küme | Tanım | Boyut |
|---|---|---|
| Kuru koşu | Kalan popülasyondan program başına 10 | 20 |
| Reddetme sondası | Kalan popülasyonda, Ghidra C'si şu dizgelerden birini içerenler (büyük/küçük harf duyarsız): `pass`, `auth`, `key`, `crypt`, `priv`, `exec`, `sock`, `root`, `uid`. Program başına 10; yetmezse kalan popülasyondan tamamlanır | 20 |
| Bellek denemesi | Popülasyonun kırpma sonrası en uzun 5 istemi (C koşulu) | 5 |

Ana örneklemin içinden alınan kümeler:

| Küme | Tanım | Boyut |
|---|---|---|
| Düşünme kipi | Her programın çekim sırasındaki ilk 50'si | 100 |
| İnsan denetimi | Her programın çekim sırasındaki ilk 15'i (düşünme kümesinin içinde) | 30 |
| Yem | §9.3 | 30 |

### 2.5 Örneklem büyüklüğü

- Eşli farkın %95 GA yarı genişliği ≈ 1,96 × √(q / n). Burada q, iki koşulun bir fonksiyonda farklı sonuç verdiği çiftlerin oranı.
- n = 300 ve q = 0,4 için ≈ ±7,2 puan (q = 0,3: ±6,2; q = 0,5: ±8,0).
- Bu genişlik, 15 puanlık bir farkı sıfırdan ayırmaya yeter. 15 eşiğinin hangi yanında kalındığını ayırmak için ise sınırda.
- Plan §3.4'ün ±5 puan hedefi ~385 öğe ister. Pilot bunun altında kalıyor; bu yüzden pilot sayılır.

## 3. Koşullar

| Kod | Tanım | Modele giden girdi | Örneklem |
|---|---|---|---|
| A | Karadul (yapılandırma K, §3.1) | Model yok; taban v2 koşusunun adı ve varsa statüsü | 300 |
| B | LLM, sıfır atış, isim zorunlu | Sistem metni (ortak + zorunlu ek) + Ghidra C | 300 |
| B-Ç | LLM, sıfır atış, çekimser kalabilir | Sistem metni (ortak + çekimser ek) + Ghidra C | 300 |
| C | LLM + kanıt paketi, isim zorunlu | Sistem metni (ortak + zorunlu ek) + kanıt paketi + Ghidra C | 300 |
| C-Ç | LLM + kanıt paketi, çekimser kalabilir | Sistem metni (ortak + çekimser ek) + kanıt paketi + Ghidra C | 300 |
| B-D, C-D | B ve C, düşünme kipi açık | B ve C ile aynı | 100 |
| YEM | Yem aday (§9.3) | — | 30 |
| D (KaradulLM) | LLM + Karadul araçları (ajan) | Araç katmanı | Pilottan sonra (§15) |
| İsteğe bağlı: B′, B′-Ç, C′, C′-Ç | Yedek modelle aynı koşullar | Aynı | 300 |

- Her çağrı bağımsızdır: yeni bir sohbet açılır, önceki fonksiyonlardan bilgi taşınmaz.
- Bir fonksiyonun koşulları sabit sırayla koşulur: B, B-Ç, C, C-Ç.

### 3.1 Karadul yapılandırması K (koşul A ve kanıt paketindeki adlar)

- **A0:** Taban v2 koşusunun `naming_map`'i, yani pilot günündeki ürün.
- **A1:** A0 + tarif katmanı. Tarif ölçüm yolundan gelir (`scripts/measurement/tarif_olc.py`); hatta bağlı değil (plan G18).
- G8 okumasında, pilot gününde koşturulabiliyorsa A1, koşturulamıyorsa A0 kullanılır. İkisi de raporlanır. Gerekçe: Her iki taraf da önceden yazılmış en iyi yapılandırmasıyla karşılaştırılır. LLM tarafı için bkz. §11.1.
- Kanıt paketindeki komşu adları, G8'de kullanılan yapılandırmadan (A1 ya da A0) gelir.
- **Hedef fonksiyonun Karadul adı pakete hiçbir zaman girmez.** Berke'nin 2026-10-15 kararı: model, Karadul'un adayını görmeden kör tarif yapar.

### 3.2 Kanıt paketi (C ve C-Ç)

Kaynak: Taban v2 koşusunun `static/` dizini üzerinde `karadul.reconstruction.tarif.build_evidence`, yani `EvidencePack` alanları. Komşu adları K'dan gelir. Metin biçimi:

| Satır | Alan | Biçim ve sınır |
|---|---|---|
| Library functions called (count) | `api_counts` | Ada göre sıralı, `malloc x2, strlen x1` biçiminde |
| Program functions it calls | `internal_callees` | `FUN_<adres> [proven: <ad>]`, `FUN_<adres> [inferred: <ad>]` ya da yalnız `FUN_<adres>`. En çok 40; fazlası `... and N more` |
| Called by | `callers` | Aynı biçim; en çok 30 |
| Passes these functions as callbacks | `callback_registrations` | `<api>(FUN_<hedef> [etiket])`; en çok 20 |
| Is passed as a callback to | `registered_as_callback` | `<api> by FUN_<kaydeden> [etiket]`; en çok 20 |
| String literals used | `strings` | Geçiş sırasıyla, yinelenenler atılmış, JSON kaçışlı; en çok 40, her biri en çok 120 karakter |
| Large constants | `large_constants` | En çok 20 (`evidence.py` zaten 20'de kesiyor) |

- Etiket eşlemesi: kesin → `proven`, tarif → `inferred`. Alan ipuçları (yorum statüsündeki öneriler) pakete girmez.
- Boş alan `none` yazılır.
- Dev setindeki ölçüm (`model_secimi.md` §4.2): Paket ortalaması komşu adları olmadan 182-250 jeton, p99 751-1.065 jeton. Yukarıdaki sınırlarla en uzun paket ~1.000 jeton civarında kalır.

### 3.3 Ghidra C (B, B-Ç, C, C-Ç)

- **Kaynak:** Taban v2 koşusundaki `static/ghidra_output/decompiled/FUN_<adres>.c`, yani Karadul'un yeniden adlandırmasından önceki çıplak Ghidra çıktısı.
- Dosyanın başındaki Karadul başlık yorumları silinir: `// Function:`, `// Address:`, `// Size:`, `// Callers:`, `// Callees:`, `// Stack:` satırları. Gerekçe: B koşulu çıplak Ghidra olmalı; çağıran bilgisi kanıt paketine aittir.
- Ghidra'nın kendi yorumları (ör. `/* WARNING: Subroutine does not return */`) kalır. Hiçbir tanımlayıcı değiştirilmez, boşluklar olduğu gibi kalır.
- **Kırpma (modelden bağımsız, bayt üzerinden):**
  - Dosya 9.000 baytı aşarsa baştan 7.000 bayta kadarki tam satırlar ve sondan 2.000 bayta kadarki tam satırlar tutulur.
  - Araya `/* [karadul-g6] <N> lines omitted */` yazılır ve kayda `kirpildi = true` düşülür.
  - 9.000 bayt ≈ 6.000 jeton. Dev setinde fonksiyonların ~%5-8'i bu sınırı aşıyor.
- Gönderilmeden önce her istem sızıntı taramasından geçer (§12).

## 4. İstem metinleri (tam metin, sürüm P1)

- **Dil:** İstemler İngilizce. Gerekçeler:
  - Modeller kod görevlerinde İngilizce talimatla daha güvenilir çalışıyor.
  - Gerçek isimler İngilizce.
  - Literatürdeki kıyaslar İngilizce istem kullanıyor.
- **JSON anahtarları:** `isim`, `gerekce`, `cekimser`. Görev metnindeki şemaya uyar.
- **Sabitleme:** Aşağıdaki beş blok, harness'taki beş istem dosyasının bayt bayt içeriğidir; her dosya tek bir satır sonuyla biter. Taslak sha256 değerleri bu metinlerden hesaplandı. Dosyalar depoya girdiğinde yeniden hesaplanıp künyeye yazılır.
- **Sürüm kuralı:** Herhangi bir değişiklik yeni bir istem sürümü (P2) demektir ve kuru koşu tekrarlanır (§8).

**`sistem_ortak.txt`** (1.326 bayt; Gemma 318, Qwen 309 jeton; sha256 `cb5f953d8a41fbd9fc1b83d29fa12ed29cb36d29536a923d403da6575b32666f`)

```text
You are an experienced reverse engineer. You will see one function from a stripped macOS arm64 executable, decompiled to C by Ghidra. The executable is an open-source program; this analysis is part of an academic study on naming functions in stripped binaries.

In the decompiled code, functions that belong to the program have placeholder names such as FUN_100024758, global data has placeholder names such as DAT_1000a1b20, and functions imported from system libraries keep their real names (for example _malloc, _strlen, _ioctl).

Your task: propose the name that the function's author most likely gave it in the original source code.

Rules:
1. Use only what you are shown: the code's behaviour, library calls, string literals, constants and data flow.
2. Prefer a name that states the function's main action and its object (verb + object), for example parse_config_line or window_resize.
3. The name must be a valid C identifier: letters, digits and underscores, starting with a letter, at most 64 characters.
4. Do not answer with a placeholder (FUN_..., sub_..., func, function, handler, helper, do_work), and do not answer with the name of a well-known library function (for example memcpy, qsort, sigaction) unless the function really is that library function.
5. Reply with exactly one JSON object and nothing else.
```

**`zorunlu_ek.txt`** (B ve C; 123 bayt; 42 / 43 jeton; sha256 `de42f0a6f589e473bdb7f44d1a1afda0275a46f71422274ad040a9666407c402`). Dosya boş bir satırla başlar.

```text

Answer format:
{"isim": "<name>", "gerekce": "<one sentence, at most 30 words>", "cekimser": false}
You must give a name.
```

**`cekimser_ek.txt`** (B-Ç ve C-Ç; 341 bayt; 100 / 102 jeton; sha256 `f4e086da53ffda024be0cbe4c5512cd3313d3be83dcba446c53a7ec51e8b87ee`). Dosya boş bir satırla başlar.

```text

Answer format:
{"isim": "<name>", "gerekce": "<one sentence, at most 30 words>", "cekimser": false}
If what you are shown does not give enough evidence to state the function's main purpose, abstain instead:
{"isim": null, "gerekce": "<what is missing, at most 30 words>", "cekimser": true}
A wrong or misleading name is worse than no name.
```

**`kullanici_b.txt`** (B ve B-Ç; 36 bayt; 15 / 16 jeton; sha256 `6e8c3341c88bce96715dcd0ee0e4695cbf4620d721b7d065e475ea502782823f`)

````text
Decompiled function:
```c
{KOD}
```
````

**`kullanici_c.txt`** (C ve C-Ç; 591 bayt; 166 / 174 jeton; sha256 `9fdaa2153b1b3f38403eb775f8608bf7cfa5ae62e16f02fd69c2e88509494aa1`)

````text
Facts about this function, computed by a static analysis tool from the same stripped binary. A name marked [proven] was recovered with direct evidence; a name marked [inferred] was derived from behaviour and may be imprecise; FUN_ addresses without a name are unknown.
- Library functions called (count): {APIS}
- Program functions it calls: {CAGIRILANLAR}
- Called by: {CAGIRANLAR}
- Passes these functions as callbacks: {GERI_CAGRI_VERIR}
- Is passed as a callback to: {GERI_CAGRI_OLUR}
- String literals used: {DIZGILER}
- Large constants: {SABITLER}

Decompiled function:
```c
{KOD}
```
````

**Birleştirme kuralları:**
- Sistem iletisi = `sistem_ortak.txt` + koşulun eki (zorunlu ya da çekimser). Kullanıcı iletisi = B ya da C şablonu; yer tutucular §3.2 ve §3.3'e göre doldurulur.
- Sohbet biçimi, modelin kendi şablonuyla kurulur: `apply_chat_template(..., add_generation_prompt=True)`.
- Düşünme kapalıyken: Qwen'de `enable_thinking=False`; Gemma'da sistem iletisinin başına `<|think|>` konmaz.
- Düşünme açıkken (B-D, C-D): Qwen'de `enable_thinking=True`; Gemma'da sistem iletisi `<|think|>` ile başlar.
- **Örnek (few-shot) yok.** İstemde program adı, dosya yolu, ikili adı ya da künye bilgisi geçmez.

## 5. Çıktı şeması ve ayrıştırma

- **Şema:** `{"isim": string | null, "gerekce": string, "cekimser": boolean}`
- **Saklama:**
  - Ham çıktının tamamı saklanır.
  - Düşünme metni ayrıca saklanır ve ayrıştırmadan önce çıkarılır: Qwen'de `<think>…</think>`, Gemma'da `<|channel>thought … <channel|>`.
  - Kalan metindeki ilk dengeli JSON nesnesi `json.loads` ile okunur. Fazla anahtarlar yok sayılır; eksik anahtar varsa çıktı geçersizdir.

**Durum sınıfları:**

| Durum | Koşul | Sayıma etkisi |
|---|---|---|
| `gecerli` | `cekimser == false` ve `isim`, `^[A-Za-z][A-Za-z0-9_]{0,63}$` desenine uyuyor | İsim verildi |
| `jenerik` | Geçerli ama `function_f1.is_generic_name` jenerik sayıyor (`FUN_…`, `sub_…` gibi) | İsim yok |
| `cekimser` | B-Ç ya da C-Ç'de `cekimser == true` ve `isim == null` | İsim yok (çekimser) |
| `zorunluyken_cekimser` | B ya da C'de `cekimser == true` | İsim yok |
| `butce_asimi` | En çok jeton dolmuş, JSON tamamlanmamış | İsim yok |
| `ret` | Geçerli JSON yok ve küçük harfe çevrilmiş metinde şu kalıplardan biri var: `i can't`, `i cannot`, `i won't`, `unable to assist`, `not able to help`, `against policy`, `malicious` | İsim yok (ret) |
| `gecersiz` | Yukarıdakilerin hiçbiri | İsim yok |

- **Yeniden deneme yok.** Açgözlü çözmede aynı çıktı gelir.
- İsme son işlem uygulanmaz; ham dize saklanır. Normalleştirme yalnız etiketlemede yapılır (§9.2).
- `func`, `helper` gibi kurala aykırı ama geçerli isimler süzülmez; etiketçi değerlendirir.

## 6. Çözme ayarları

| Ayar | Değer | Not |
|---|---|---|
| Örnekleme | Açgözlü (sıcaklık 0, argmax) | top_p, top_k ve min_p etkisiz. Tekrar cezası ve presence penalty yok. Qwen'in düşünmesiz kip önerisi (sıcaklık 0,7, presence 1,5) belirlenimcilik için bilerek kullanılmaz (§16) |
| Tohum | `mx.random.seed(20261019)`, süreç başında | Açgözlü çözmede etkisiz; künyeye yazılır |
| En çok jeton | Düşünme kapalı: 256. Düşünme açık: 2.304 (2.048 düşünme + 256 yanıt) | Dolunca `butce_asimi` |
| Bağlam | En uzun istem ~7,6K jeton; çıktıyla birlikte ~8K, düşünme kipinde üstüne düşünme bütçesi | Kırpma ile sağlanır (§3.2, §3.3). Bellek, K-5 kapısında en uzun istemlerle ölçülür |
| Toplu işlem | Yok (tek tek) | |
| Önek önbelleği | İstekler arasında kullanılmaz | Belirlenimcilik ve sıra bağımsızlığı için |
| Spekülatif çözme ve MTP taslağı | Kapalı | |
| KV önbellek nicemlemesi | Kapalı | |
| Durdurma | Modelin `generation_config`'indeki EOS jetonları | |
| Log-olasılık | Üretilen her jetonun seçilen jeton log-olasılığı saklanır | VARSAYIM: mlx_lm 0.31.3'te `stream_generate` yanıtlarında `logprobs` var. Kuru koşuda doğrulanır (K-1) |

## 7. Belirlenimcilik denetimi

- **Koşu 1:** Bütün koşullar. **Koşu 2:** 300 fonksiyonun tamamında B ve C, ayrı bir süreçte (model yeniden yüklenir), fonksiyon sırası ters çevrilmiş olarak.
- **Karşılaştırma:** Ham çıktı (baytların sha256'sı) ve ayrıştırılmış isim.
- **Rapor:** Ham çıktısı aynı olanların oranı, ismi aynı olanların oranı ve her farkın listesi.
- **Önceden yazılan kabul ölçütü:** Her koşulda ≥ %99 aynı isim (≥ 297/300).
  - Ölçüt tutmazsa analiz Koşu 1 ile yapılır ve belirlenimsizlik bir **sonuç** olarak raporlanır. G8 kuralı belirlenimciliği Karadul'un olası üstünlükleri arasında sayıyor.
  - Fark varsa nedeni araştırılır: Metal çekirdekleri, sıra etkisi ya da önbellek.

## 8. Kuru koşu ve model kapıları

**Kuru koşu içeriği:**
- Kuru koşu kümesi: 20 fonksiyon × B, B-Ç, C, C-Ç.
- Reddetme sondası: 20 fonksiyon × B ve C.
- Bellek denemesi: 5 en uzun istem, C koşulu.
- Belirlenimcilik: Kuru koşu kümesinde B'nin ikinci koşusu.

Kuru koşu çıktıları ana analize girmez; sonuçları künyeye yazılır.

**Kapılar (birincil model):**

| Kapı | Ölçüt |
|---|---|
| K-1 Yükleme ve şablon | Model yükleniyor. Düşünme kapalıyken çıktıda düşünme metni yok ya da blok boş. Log-olasılıklar alınabiliyor. 20 / 20 çağrı tamamlanıyor |
| K-2 JSON geçerliliği | Kuru koşu kümesinde B ve C'de ≥ %95 (≥ 38 / 40) |
| K-3 Reddetme | Sonda kümesinde B ve C'de toplam `ret` ≤ 1 / 40 |
| K-4 Belirlenimcilik | B'nin iki koşusunda ≥ 19 / 20 aynı ham çıktı |
| K-5 Bellek | Bellek denemesinde en yüksek bellek (`mx.get_peak_memory()`) ≤ 20 GB |
| K-6 Süre | Ölçülen hızla §13'teki süre yeniden hesaplanır. Toplam 24 saati aşarsa düşünme alt kümesi 50 fonksiyona iner (her programdan ilk 25) |

- Birincil model K-1…K-5'ten birini geçemezse yedeğe geçilir ve kuru koşu yedekle tekrarlanır. Yedek de geçemezse pilot durur ve karar ana oturuma döner.
- Kuru koşudan sonra istem değişmez. Bir şablon hatası gibi bir nedenle değişmesi gerekirse yeni istem sürümü yazılır, kuru koşu tekrarlanır, değişiklik ve gerekçesi kayda geçer.

## 9. Değerlendirme (kör protokol v2)

### 9.1 Araçlar ve varsayımlar

**G4 yordamı (`docs/arge/etiket_protokolu_v2.md`, 2026-10-19; commit'lenmemiş):**
- Örneklem yalnız isim verilmiş (`tp` + `wrong`) fonksiyonlardan çekiliyor. Her öğede tek aday var (Karadul'un adı). Yemler ayrı öğe (v2 §4, §6).
- Karartma (v2 §5, ana oturum kararı): Yalnız öğenin kendi adı `FONKSIYON` olur; dosya adı öğenin kendi adıysa o da karartılır. Başka fonksiyonların adları görünür kalır; anahtarda `capraz_atif` ile işaretlenir ve `--capraz-atifsiz` ile duyarlılık analizi yapılır.
- Gövde 60 satırda kırpılıyor (`--azami-satir`; v2'de bekleyen karar).
- `tam`, anahtardaki otomatik eşleşmeden (`status == "tp"`, `normalize_name` ile) geliyor. Değerlendirici `tam` kullanmaz.
- Aşama 1 ve aşama 2 değerlendirici metinleri v2 §8'de. Wilson aralığı ve eşli bootstrap var; bootstrap tohumu 20261019.

**G6 için gereken "çok adaylı kip" (VARSAYIM; aracın sahibi ve ana oturum karar verir):**
1. Örneklem dışarıdan verilir (§2'deki 300 adres) ve Karadul'un isim vermediği fonksiyonları da içerir.
2. Öğe başına birden çok aday olur: `adaylar.jsonl` satırları (`program`, `adres`, `kosul`, `isim`; şema §14) okunur.
3. Aynı fonksiyonda normalleştirilmiş hâli aynı olan adaylar birleştirilir. Gizli anahtar, aday → koşullar eşlemesini tutar.
4. Aşama 1 (amaç cümlesi) fonksiyon başına bir kez yapılır.
5. Aşama 2'de her aday ayrı bir öğedir. Öğeler fonksiyonlar arasında karışık sırayla ve koşul etiketi olmadan sunulur. Değerlendirici her adayı, o fonksiyonun kilitli amaç cümlesi ve karartılmış gövdesiyle birlikte görür. Sıra tohumu: `int(SHA-256("karadul-g6-sira-2026-10-19")[:16], 16)` = 17136320124842713191.
6. **Otomatik tam:** `normalize_name(aday)`, GT adlarından birinin `normalize_name`'ine eşitse aday `tam` sayılır. Değerlendiricinin etiketi tutarlılık için ayrıca saklanır (`etiket_puan.py`'deki kuralın çok adaylı karşılığı).
7. Puanlayıcı koşul başına oranları ve koşul çiftleri arasındaki eşli farkları verir (§10).

Araç bu kipi almazsa harness her koşul için ayrı bir G4 paketi üretebilir. Ama o zaman aynı fonksiyon koşul koşul gruplanmış gelir ve koşullar arası körlük zayıflar. Bu yüzden çok adaylı kip tercih edilir.

Çok adaylı kipte v2'nin aşama 2 metni şu kadar değişir: her satır bir adaydır; aynı id'ye (fonksiyona) ait birden çok satır olabilir; her aday kendi başına, amaç cümlesine göre etiketlenir.

### 9.2 Görüntüleme normalleştirmesi

- Değerlendiriciye her aday `function_f1.normalize_name` ile normalleştirilmiş hâliyle gösterilir. Bu projenin tek kuralı: baştaki `_`, `m_`, `s_`, `g_`, `p_`, `k_` önekleri atılır; camelCase snake_case'e çevrilir; küçük harfe geçilir; GCC sonekleri ve sondaki `_<rakam>` atılır.
- Amaç, üslup farkından sistem kimliğinin anlaşılmasını önlemek. Örneğin Karadul'un `Modul_rol` biçimi ile LLM'in snake_case biçimi aynı görünür.
- Özgün dize anahtarda saklanır.
- `gerekce` alanı değerlendiriciye gösterilmez; sistem kimliğini açığa vurur. Yalnız hata analizinde kullanılır.

### 9.3 Yem

- Ana örneklemin %10'u (30 fonksiyon) yem için seçilir. Tohum: `int(SHA-256("karadul-g6-yem-2026-10-19")[:16], 16)` = 12126817379015212437.
- Her birine bir yem aday eklenir. Yem aday, aynı programda örneklemde olmayan bir fonksiyonun gerçek adıdır. Şartlar, protokol v2 §6'daki aday koşullarıyla aynı:
  - Hedeften farklı bir kaynak dosyasından.
  - Hedefin gerçek adıyla normalleştirilmiş jeton kesişimi boş.
  - Paketteki hiçbir gövdede tanımlayıcı olarak geçmiyor.
  - Hiçbir koşulun adayıyla ve başka bir yemle (normalleştirilmiş) aynı değil.
- **v2'den sapma (VARSAYIM; aracın sahibi onaylar):** v2'de yem, kendi gövdesi olan ayrı bir öğedir. Çok adaylı kipte yem, örneklemdeki bir fonksiyona eklenen ek aday olur; yeni amaç cümlesi gerekmez.
- **Yem kabul oranı:** Yemlerin `tam` ya da `dogru_tarif` etiketlenme oranı; değerlendirici başına hesaplanır. Hedef ≤ %5 (plan G4), nokta tahmine uygulanır; Wilson aralığı her zaman verilir. 30 yemde hiç kabul olmasa bile Wilson üst sınırı ~%11,4 olur (v2 §9'daki hesabın aynısı).

### 9.4 Değerlendiriciler

- **Vekil değerlendirici:** Bir Claude (Opus 5.5) ajanı. Aday üreten modellerden (Qwen, Gemma) farklı bir aileden.
  - Kör kipte çalışır: gerçek ad ve koşul bilgisi görmez.
  - Rubrik: `docs/arge/etiket_rehberi.md`, sürüm 2 (2026-10-19). "Yanlış fiil → `yanlis`" kuralı bu sürümde yürürlükte (Berke'nin kararı, plan §9 madde 1). Sürüm 1 ile verilmiş etiketler sürüm 2 sayılarıyla birleştirilmez. Kullanılan rehber dosyasının sha256'sı künyeye yazılır.
  - Değerlendirici metinleri protokol v2 §8'deki aşama 1 ve aşama 2 metinleridir (§9.1'deki çok adaylı uyarlamayla).
  - Ezber: Vekil, htop ve tmux'un kaynağını tanıyıp gerçek adı bilebilir. v2 §10 madde 2'deki yoklama (karartılmış gövdeden ad tahmini) G6'nın vekiline de uygulanır.
- **Amaç cümlesi kilidi:** Amaç cümlesi aşama 1'de kilitlenir ve aşama 2'de değiştirilemez (`etiket_puan.py --amac` denetimi).
- **İnsan denetimi:** 30 fonksiyonluk alt küme (§2.4), aynı kör paketle bir insan tarafından bağımsız olarak etiketlenir. Önerilen kişi Berke.
  - Vekil ile insan arasında Cohen kappa ve yakın / yakın değil uyumu raporlanır.
  - Gerekçe: Literatürde LLM yargıcın uzman yargısıyla ortalama korelasyonu %63 (`model_secimi.md` K25). Vekil tek başına yeterli sayılmaz.
- **İsteğe bağlı ikinci vekil:** Başka bir aileden bir model aynı paketi etiketler ve vekiller arası kappa raporlanır. Maliyeti var; karar Berke'nin.

## 10. Ölçüler ve analiz

### 10.1 Fonksiyon düzeyinde sonuç

Her koşul k ve fonksiyon i için sonuç şu beş değerden biridir: `tam`, `dogru_tarif`, `yalniz_alan`, `yanlis`, `isimsiz`. `isimsiz`, geçerli bir isim olmadığı anlamına gelir: Karadul'un adsız ya da jenerik bıraktıkları ve LLM'in çekimser kaldığı, ret verdiği, geçersiz ya da jenerik çıktı ürettiği durumlar.

### 10.2 Oranlar

Koşul başına, program başına ve makro (iki programın eşit ağırlıklı ortalaması; örneklemler eşit olduğu için mikroyla aynı) hesaplanır. N = program başına 150.

| Ölçü | Tanım |
|---|---|
| Yakın | (`tam` + `dogru_tarif`) / N |
| Kapsam | isim verilen / N |
| Yanlış | `yanlis` / isim verilen |
| Tam | `tam` / N |
| Yalnız alan | `yalniz_alan` / isim verilen |

Her oran için Wilson %95 GA verilir (`etiket_puan.py`).

### 10.3 Farklar

- Δb = yakın(B) − yakın(A); Δc = yakın(C) − yakın(A); Δcb = yakın(C) − yakın(B). Ayrıca B-Ç ve C-Ç'nin A'ya göre farkları.
- **GA:** Eşli bootstrap, 10.000 tekrar. Fonksiyonlar program içinde yeniden örneklenir (katmanlı). Tohum 20261019, `etiket_puan.py` ile aynı.
- İkincil test: Kesin McNemar testi.
- Program başına fark da ayrıca verilir. Yalnız iki program olduğu için program düzeyinde bootstrap yapılmaz.

### 10.4 Risk-kapsam

**Güven puanı:**
- **A:** Statü sırası: kesin > tarif > diğer. Taban v2'de her isim 1,0 güvenle geliyor (plan §2 madde 6). Statü yoksa A eğride tek bir nokta olur.
- **B ve C:** İsim değerinin jetonlarının ortalama log-olasılığı (birincil); en küçük jeton olasılığı (ikincil). Modelden sözel güven istenmez.
- **B-Ç ve C-Ç:** Çekimser kalınan fonksiyonlar kapsam dışında kalır. Kalanlar aynı log-olasılık puanıyla sıralanır.

**Eğri:** Fonksiyonlar güvene göre azalan sırada dizilir. Her kapsam düzeyinde yanlış oranı (yanlış / verilen) ve yakın kapsamı (yakın / N) hesaplanır.

**Ana sayı:** Yanlış ≤ %10 iken ulaşılan en yüksek yakın kapsamı. Bu, G13 kapısıyla aynı biçim.
- Eşik çapraz seçilir: htop'ta seçilen eşik tmux'a, tmux'ta seçilen eşik htop'a uygulanır. Böylece aynı veride eşik seçmenin iyimserliği önlenir.
- "Kâhin" eşikle (aynı veride seçilmiş) değer ayrıca raporlanır.
- AURC (eğri altındaki risk) ikincil ölçüdür.

### 10.5 Katmanlar

Ayrı raporlanırlar; G8 kararına girmezler.
- Kırpılmış C (`kirpildi = true`) ve kırpılmamış.
- **Öz-ad dizgisi:** Fonksiyonun gerçek adı (normalleştirilmiş) Ghidra C'sinin bir dizgi sabitinde ya da kanıt paketinin dizgilerinde geçiyor (assert, log, `__func__`). Hem LLM hem Karadul için "kolay" küme.
- Erişim sınıfı (plan ÖL-3: doğrudan çağrılan, yalnız tablodan çağrılan, referanssız), puanlayıcı veriyorsa.
- Karadul'un A'daki durumu (`tp`, `wrong`, `unnamed`). Örneğin LLM'in, Karadul'un isimsiz bıraktıklarında ne yaptığı.
- Düşünme kipi (100 fonksiyon): B ile B-D, C ile C-D arasındaki eşli fark.

### 10.6 Ezber göstergesi

- Tam oranı ezberin işaretidir: ünlü kodda yüksek tam oranı ezbere işaret eder. Görülmemiş dilimle G31'de karşılaştırılır.
- **İsteğe bağlı tanı:** 20 fonksiyonun kaynak kodunun ilk 5 satırı modele verilir ve devamını yazması istenir. Özgün devamla 5-gram örtüşmesi ölçülür.
  - Yalnız htop ve tmux'ta yapılır (geliştirme setinin kaynağına bakmak serbest).
  - Test setinde ve görülmemiş dilimde **yapılmaz**.

### 10.7 Maliyet

- Fonksiyon başına model süresi (önek işleme + üretim), girdi ve çıktı jeton sayıları, en yüksek bellek.
- Karadul için kaba karşılaştırma: taban v2 koşusunun toplam süresi / fonksiyon sayısı.

## 11. G8 karar kuralının yerel modelle okunması

Plan v2'deki kural: "LLM pilotunda (b)−(a) ≥ 15 puan ve fark görülmemiş dilimde de sürüyor → Makalenin ana sonucu 'gevşek isim oranı' olmaz. Ana sonuç: sabit kesinlikte kapsam, tip ve yapı doğruluğu, görülmemiş kodda dayanıklılık, determinizm, maliyet."

### 11.1 İşlemsel tanım (öneri; Berke onaylar)

- **(a):** A1 varsa A1, yoksa A0 (§3.1).
- **(b):** B, yani isim zorunlu, sıfır atış.
- **LLM lehine okuma:** Kural, önceden yazılmış LLM satırlarının **en yükseğiyle** okunur. Bu satırlar: B; B-D (yalnız düşünme alt kümesinde, A ile aynı 100 fonksiyon üzerinden); yedek model koşulduysa B′.
  - Gerekçe: Kural Karadul'u sınıyor. Zayıf bir LLM yapılandırması seçmek Karadul'u olduğundan iyi gösterir.
  - Bilinen yan etki: Birden çok gürültülü tahminin en yükseğini almak sonucu yukarı yanlı kılar (çoklu karşılaştırma). Bu bilerek kabul edilir; yanlılık LLM lehine, yani Karadul'un iddiasına karşı yöndedir. Seçilen satır ve bütün satırların değerleri birlikte raporlanır.
- **"≥ 15 puan":** Makro Δb'nin nokta tahmini ≥ 15,0 (plan metni). %95 GA raporlanır.
  - Nokta tahmini 15'in altında ama GA'nın üst sınırı ≥ 15 ise sonuç "belirsiz" diye raporlanır. Karar yine nokta tahminiyle verilir; plan metnine sadık kalınır ve bu not düşülür.

### 11.2 Asimetri

| Pilot sonucu | Okuma |
|---|---|
| Δb ≥ 15 (yerel model) | Kuralın ilk koşulu sağlanır. Daha güçlü bir modelin ne yapacağını bilmek gerekmez; kural zaten tetiklendi |
| 0 < Δb < 15 | "Kural yerel modelle tetiklenmedi." Bu sonuç öncü modeller için hiçbir şey söylemez. Makalede iddia "≤ 30B parametreli yerel açık modele karşı" diye sınırlanır. G33'te öncü model koşulmazsa bu sınır kalıcı olur. Karar Berke'nin |
| Δb ≤ 0 | Karadul yerel modelden iyi. Aynı sınırlama geçerli |

### 11.3 İkinci koşul: görülmemiş dilim

- G6'da yalnız dilimin ön kaydı yapılır; dilim plana göre G31'de açılır. Bu yüzden ikinci koşul **G8'de ölçülemez**.
- Sonuç: G8 kararı geçicidir. Kesin okuma G34'te yapılır. Zamanlama seçenekleri `gorulmemis_dilim_onkayit_taslak.md` §9'da.
- **"Sürüyor" için öneri:** Görülmemiş dilimde Δb ≥ 10 puan ve proje kümeli bootstrap ile %95 GA'nın alt sınırı > 0. Bu tanım LLM lehinedir. Berke onaylar.

### 11.4 Düşünme kipi yolu (önceden yazılı)

- Alt kümede B-D ile Δ ≥ 15 çıkar, ama tam örneklemde B ile Δ < 15 kalırsa: Tam örneklemde düşünme kipiyle bir koşu yapılır, karar ondan sonra verilir.
- Bu koşu birincil modelde ~10 saat ek süre ister.

### 11.5 Δc'nin yeri

- Δc G8 kuralında yer almaz.
- Δc − Δb, Karadul'un kanıtının bir LLM'e kattığı değeri ölçer. KaradulLM'in (ürün izi) gerekçesi budur. Makalede ayrı raporlanır; motor LLM'siz kalır.

### 11.6 Risk-kapsam okuması

- G8 kuralının sonuç sütunundaki alternatif ana sonuç "sabit kesinlikte kapsam".
- Yanlış ≤ %10 iken yakın kapsamda B ya da C de Karadul'u geçerse, bu alternatif ana sonuç da tehdit altındadır. Durum G13 kapısına girdi olarak kayda geçer.

## 12. Sızıntı denetimleri

1. **İstemde gerçek ad yok.** Program adı, dosya yolu, ikili adı da yok: Karadul'un başlık yorumu silinir, künye bilgisi isteme girmez.
2. **Strip doğrulaması.**
   - Ghidra C'si, Apple `/usr/bin/strip` ile soyulmuş kopyadan gelir; export trie'nin boş olduğu `xcrun dyld_info -exports` ile doğrulanmış olmalı.
   - Bu bilgi Mac ölçüm hattının künyesinden alınır. Künyede yoksa pilot başlamaz.
   - Neden: 14 Ekim'deki eski tmux koşusunda iç adlar Ghidra C'sinde görünüyordu (`_session_group_contains`, `_clients`). Conda strip tuzağı; hafıza `feedback-mac-strip.md`.
3. **Tanımlayıcı taraması.** Her istem, gönderilmeden önce otomatik olarak taranır.
   - Programın GT sembol kümesindeki her ad aranır (`nm`'deki tanımlı metin ve veri sembolleri; strip'li ikilinin ithal ettiği adlar hariç).
   - Arama yalnız dizgi sabitlerinin ve yorumların **dışında**, tam sözcük olarak yapılır.
   - Eşleşme bulunursa istem gönderilmez ve koşu durur. Bu bir strip ya da ad sızıntısıdır.
   - Dizgi sabitleri içindeki eşleşmeler meşru kanıttır; "öz-ad dizgisi" katmanına yazılır.
4. **Kanıt paketi.**
   - Komşu adları yalnız K'nın çıktısından gelir.
   - Hedefin K adı paket metninde tam sözcük olarak geçmemelidir. İstisna: aynı ad bir dizgi sabiti olarak da geçiyorsa. Bu otomatik denetlenir.
5. **Değerlendirici paketi.** `etiket_paketi.py`'nin sızıntı denetimi uygulanır: gerçek ad yalnız aday alanında geçebilir.
6. **Bilinen ve ölçülmeyen yanlılıklar.**
   - htop ve tmux ünlü programlar; LLM onların kaynağını büyük olasılıkla görmüştür (ezber).
   - Tarif kuralları da htop ve tmux üstünde yazıldı; A1 de iyimser çıkar.
   - Bu iki yanlılığın net yönü bilinmiyor. Görülmemiş dilim ikisini birden temizler: kod hem model hem Karadul için yenidir.

## 13. Süre ve kaynak tahmini

Varsayımlar:
- Ortalama istem (Gemma tokenizer'ıyla; Qwen %1-2 daha az): B 2.120, B-Ç 2.180, C 2.570, C-Ç 2.630 jeton (`model_secimi.md` §4.2).
- Çıktı, düşünme kapalıyken 80 jeton. Düşünme açıkken ortalama 1.500 düşünme jetonu; aralık 800-2.048.
- Çağrı başına 0,5 sn ek yük.
- Süre = girdi / önek hızı + çıktı / üretim hızı + 0,5 sn.

| Kalem | Çağrı | Qwen3.6-27B (önek 195, üretim 20,5 jeton/sn; ölçülmüş) | Gemma 4 26B-A4B (önek 1.065 → 900, üretim 75,7 → 40; iyimser → kötümser) |
|---|---|---|---|
| Ana koşular: 300 × 4 | 1.200 | 5,5 sa (çağrı başına 15,3-17,9 sn) | 1,3-1,7 sa |
| Belirlenimcilik: 300 × B ve C | 600 | 2,7 sa | 0,6-0,9 sa |
| Düşünme kipi: 100 × B-D ve C-D | 200 | 5,0 sa (aralık 3,1-6,5) | 1,3-2,4 sa |
| Kuru koşu, sonda, bellek ve tekrar | ~125 | 0,7 sa | 0,2 sa |
| **Toplam model zamanı** | | **~14 sa (12,1-15,4)** | **3,4-5,1 sa** |

- Model yükleme, araç yükü ve aynı anda koşan Ghidra için %20 pay eklenmeli.
- Yedek model tam pilotta da koşulursa (isteğe bağlı) +3,4-5,1 sa.
- Bellek: Birincil model 8k bağlamda ~18,3 GB (ölçülmüş); düşünme kipinde ~10k bağlamda ~19-19,5 GB (ölçümden doğrusal uzatma). Düşünme kipi koşuları Ghidra'nın çalışmadığı bir zaman diliminde yapılır.

**Etiketleme yükü (tahmin):**
- 15 Ekim Apple strip koşularında Karadul, isim bekleyen fonksiyonların %16,9'una (htop, 101/597; o gün Go sanılıyordu) ve %34,0'üne (tmux, 871/2.561) isim vermişti. LLM koşullarındaki adayların bir kısmı aynı fonksiyonda birbiriyle aynı çıkar.
- Fonksiyon başına ~3 benzersiz aday → ~850-1.000 aday öğesi. Buna düşünme alt kümesinden ~100 ve 30 yem eklenir; ayrıca 300 amaç cümlesi yazılır.
- İnsan denetimi: 30 amaç cümlesi + ~100 aday ≈ 1-1,5 saat.
- Yedek model de koşulursa +~450 aday öğesi.

## 14. Dosya düzeni ve çıktılar

**Çalışma dizini:** `workspaces/2026-10-19_g6_pilot/`. Git dışında (`.gitignore`) ve Spotlight dışında (`~/Black_Widow`).

| Dosya | İçerik |
|---|---|
| `kunye.json` | §1 |
| `orneklem.json` | 300 adres; alt kümeler; çekim sırası; popülasyonun sha256'sı; dışlananlar |
| `istemler/` | Beş istem dosyası ve sha256'ları |
| `ham/<model>/<kosul>/<program>_<adres>.json` | İstemin sha256'sı, ham çıktı, düşünme metni, jeton log-olasılıkları, süreler, jeton sayıları, en yüksek bellek |
| `adaylar.jsonl` | Etiket paketinin girdisi (şema aşağıda) |
| `belirlenimcilik.json`, `kuru_kosu.json` | §7, §8 |
| `paket/`, `etiket/`, `puan.json` | Kör paket, vekil ve insan etiketleri, puanlar |

**`adaylar.jsonl` satır şeması (VARSAYIM; §9.1):**

```text
{"program", "adres", "kosul", "model", "model_revizyon", "istem_surumu",
 "isim", "cekimser", "durum", "guven_ort_logprob", "guven_min_prob",
 "kirpildi", "girdi_jeton", "cikti_jeton", "sure_sn", "ham_sha256"}
```

`durum` şu değerlerden biridir: `gecerli`, `jenerik`, `cekimser`, `zorunluyken_cekimser`, `butce_asimi`, `ret`, `gecersiz`.

**Depoya önerilenler (commit kararı ana oturumun):**
- Harness betiği; önerilen ad `scripts/measurement/llm_pilot.py`. Plan §6'ya göre `scripts/measurement/` paralel güvenli grupta.
- İstem dosyaları.
- Sonuç özeti, `docs/arge/` altında.
- Ham model çıktıları depo dışında kalır; depoya yalnız sha256 listeleri girer.

## 15. KaradulLM satırı (D; pilottan sonra)

- **Ön koşul:** Uygulama içi araç katmanı. G6'da yok, bu yüzden D pilotta koşulmaz. Plan "Ürün izi": "G6 pilotuna 'LLM + Karadul araçları' koşulu eklenir; ajanın sabit kanıt paketinden ne kadar iyi olduğunu ölçer."
- **Kurulum:**
  - Aynı model ve aynı çıktı şeması.
  - Ajanın araçları: fonksiyon listesi, decompile, xref, string, kapsam işaretli çağrı grafiği, kanıt paketi, tablo yuvaları, tip bilgisi. Her araç sonucu kanıt ve sınırlama taşır.
  - Hedefi çalıştıran (dinamik) araç yok; o araç yalnız `--dynamic` iznine bağlı kalır.
- **Bütçe:** Fonksiyon başına en çok 8 araç çağrısı ve toplam en çok 16K jeton bağlam. Düşünme kapalı ve açık ayrı koşulur.
  - 16K bağlamda birincil modelin belleği, ölçülmüş değerlerden doğrusal uzatmayla ~21-22 GB'a çıkabilir. D koşusundan önce K-5 kapısı 16K'da yeniden ölçülür; bütçe aşılırsa bağlam sınırı 12K'ya iner.
- **Körlük:** Ölçüm koşusunda hedefin Karadul adı ajana gösterilmez; amaç, ajanın bağımsız isim önerisini ölçmek. Üründeki davranış farklı olabilir.
- **Ölçüler:**
  - D − C: ajanın sabit paketten kazancı.
  - Araç kullanım hataları: geçersiz çağrı, gereksiz tekrar, bütçe aşımı. Plan, ince ayara "ancak araç kullanım hataları ölçülürse" geçileceğini söylüyor; bu sayılar o kararın girdisi.
- **Değerlendirme:** Aynı kör paket. D'nin adayları aynı fonksiyonların öğelerine eklenir; yeni amaç cümlesi yazılmaz.

## 16. Sınırlamalar

- **Yerel model öncü modellere genellenemez** (`model_secimi.md` §10). Okuma kuralları §11.2'de.
- **Geliştirme seti ünlü kod.** LLM ezberi ile Karadul'un kurallarının bu programlara uyması, sonucu iki yönde de yanlı kılabilir.
- **Örneklem küçük.** 300 öğe yaklaşık ±7 puanlık GA verir. İki program, program düzeyinde genellemeye izin vermez.
- **Vekil değerlendirici bir LLM.** LLM üslubuna yatkın olabilir. Görüntüleme normalleştirmesi ve insan denetimi bu riski azaltır ama ortadan kaldırmaz.
- **Çözme ayarı.** Açgözlü çözme üreticinin önerdiği örneklemeden farklı. Bu görevde kaliteye etkisi ölçülmedi.
- **4 bit nicemleme.** Kaybı bu makinede ölçülemiyor.
- **Kırpma.** Uzun fonksiyonlarda LLM'i dezavantajlı bırakabilir. Bu yüzden ayrı katman olarak raporlanır.
- **Karadul'un güven kanalı kopuk** (plan §2 madde 6). Taban v2'de A'nın risk-kapsam eğrisi tek bir nokta olabilir.

## 17. Açık kararlar

1. Rubrik: Kapandı. Sürüm 2 yürürlükte ("yanlış fiil → `yanlis`", Berke'nin kararı). Kayıt için listede duruyor.
2. G8 okumasında A1'in (tarif katmanı) kullanılması (§3.1).
3. Çok adaylı etiket kipi: aracın sahibi ve ana oturum (§9.1).
4. Yedek modelin tam pilotta da koşulması (`model_secimi.md` §7).
5. Görülmemiş dilimin zamanlaması: G8 geçici mi kalsın, yoksa pilot parçası mı eklensin (`gorulmemis_dilim_onkayit_taslak.md` §9).
6. "Sürüyor" tanımı (§11.3).
7. İnsan denetimini kimin yapacağı.
8. İkinci vekil değerlendirici (maliyet).
9. Düşünme kipi alt kümesinin boyutu (100).
10. Harness'ı kimin yazacağı ve hangi dosyaya.
11. G33'te öncü model kullanılıp kullanılmayacağı.
