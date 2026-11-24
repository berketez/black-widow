# GK-0 — Geri kurma hattının tasarımı

**Durum: İSKELET (2026-11-24 14:1x).** Bölümler yazıldıkça doldurulur; yarıda kesilirse kalınan yer bu satırdan ve bölüm başlıklarındaki `[YAZILMADI]` işaretinden okunur.

Karar: `KARARLAR.md` A-41 (Berke, 2026-11-24). İş emri: `docs/arge/2026-11-23_dalga1/gonderim/GK0.md`. Ölçüm betiği: `scripts/arge/gerikurma/derlenebilirlik.py`. Koşu kökü: `~/karadul_olcum/runs/dalga1-2026-11-23/GK0/` (özet `ozet/`).

Bu belge ürün kodu içermez. Ölçülmeyen her sayı "ölçülmedi" ya da "TAHMİN" diye işaretlidir.

## 0. Özet [YAZILMADI]

## 1. Bugünkü durumun ölçümü [YAZILMADI]

## 2. Boşluk sınıflaması [YAZILMADI]

## 3. Denetleyicinin tasarımı

Denetleyici bu hattın kalbidir: motorun ya da modelin ürettiği her parça için "geçti / geçmedi / hükümsüz" cevabını **makine** verir. Bu bölümdeki oranların hiçbiri ölçülmedi; hepsi GK-D ve GK-E'nin ön kayıtlı ölçümüdür. Ölçülmüş olan yalnız şunlardır: (a) bugünkü çıktının B0 / B1 sayıları (§1), (b) makinedeki derleyicinin başka hedefler için nesne dosyası üretebildiği (aşağıda 3.2), (c) KİMLİK hattının derleyiciler arası benzerlik sayıları (3.3'te taban olarak anılır).

### 3.1 Basamaklar ve "ne zaman tuttu sayılır"

| Basamak | Tanım | Birim | "Tuttu" ölçütü (makinenin cevabı) | Ölçen |
|---|---|---|---|---|
| **B0** sözdizimi geçerli | Derleyicinin ayrıştırıcısı metni kabul eder | dosya, işlev | `clang -fsyntax-only` çıktısında `Parse Issue` ve `Lexical or Preprocessor Issue` kategorisinde hata 0 | `derlenebilirlik.py` (bugün var) |
| **B1** tek başına derlenir | Birim (işlev gövdesi + üretilmiş önsözü) hedefin mimarisi için nesne dosyası verir | dosya, işlev | Öntanımlı hata kümesiyle hata 0 (`-w` ya da `-Wno-error=…` yok); nesne dosyasında işlevin simgesi tanımlı | `derlenebilirlik.py` (bugün `-fsyntax-only`; GK-A nesne kipini ekler) |
| **B2** projeyle bağlanır | Bütün birimler B1'de ve yeniden yerleştirilebilir bağlama hatasız | program; işlev için "imza tutarlı" | (a) çift tanımlı simge 0; (b) çözülmeyen simge kümesi ⊆ özgün ikilinin içe aktarım tablosu ∪ adresi bilinen veri simgeleri; (c) her çağrı noktasındaki bildirim, projedeki tek tanımın imzasıyla aynı. Çalıştırılabilir dosya üretilmesi gerekmez; üretilirse de çalıştırılmaz | GK-H |
| **B3** işlev düzeyinde eşdeğer | Yeniden derlenen işlev, özgün ikilideki aynı adresteki işlevle aynı gözlenebilir davranışı verir | işlev | Kabul eden kanıt türünün **ölçülmüş** yanlış kabul oranının Wilson üst sınırı eşiğin altında (3.5). Üç kanıt türü: `komut_eş` (3.3 K1), `öykünme` (K2), `smt` (K3) | GK-D, GK-E, GK-F |
| **B4** bayt eşit | Yeniden derlenen işlevin makine kodu özgün işlevin baytlarına eşit (yeniden yerleştirme alanları maskelenir, hedefleri ayrıca eşlenir) | işlev | Bayt karşılaştırması; kanıt türü `bayt_eş` | GK-D |

Program düzeyi sayılar her basamak için oran olarak verilir: işlev sayısıyla ve kod baytı ağırlığıyla (büyük işlevler küçüklerin arkasına saklanmasın). "Program eşdeğer" diye tek bir hüküm verilmez; verilebilecek en güçlü cümle "N işlevin M'si B3'te, kalan N − M için hüküm yok / geçmedi"dir.

İki not:

1. **B4 yalnız üst basamak değil, en ucuz ve yanlış kabulü olmayan denetleyicidir.** Bayt eşitliği tuttuğu yerde eşdeğerlik tanım gereği tutar; öykünmeye ya da SMT'ye gerek kalmaz. Bu yüzden denetim sırası ucuzdan pahalıya ve sağlamdan olasılığa doğrudur: `bayt_eş` → `komut_eş` → `smt` → `öykünme`. Kapsamının ne olacağı ölçülmedi; derleyicisi ve bayrakları bilinmeyen ikilide düşük olması beklenir (TAHMİN, sayı verilmiyor).
2. **B3 bir olasılık hükmüdür, ispat değil** (`smt` ve `bayt_eş` dışında). Çıktıda her işlev hangi kanıt türüyle geçtiğini ve o türün ölçülmüş hata sınırını taşır (§5.5 etiket şeması).

### 3.2 Yalıtılmış birim ve derleme

Denetleyicinin girdisi tek işlevdir; çıktının tamamının derlenmesini beklemez (bugün 0 dosya derleniyor; §1).

1. **Birim:** aday işlevin C metni + üretilmiş **birim önsözü**: o işlevin kullandığı tipler, çağırdığı işlevlerin bildirimleri, başvurduğu veri simgelerinin `extern` bildirimleri (§4 GK-C). Önsöz belirlenimci üretilir; modelin yazdığı metinde önişlemci yönergesi (`#…`) bulunamaz (bekçi kuralı, §5.6).
2. **Derleme:** hedefin mimarisi ve nesne biçimi için `clang -c`. Bu turda denendi (kendi yazdığım iki satırlık bir C dosyasıyla, hedef kodla değil): `Apple clang 21.0.0` aynı makinede `--target=aarch64-unknown-linux-gnu -ffreestanding` ile ELF aarch64, `--target=x86_64-unknown-linux-gnu -ffreestanding` ile ELF x86-64, `--target=arm64-apple-macos` ile Mach-O arm64 nesne dosyası üretti; `/usr/bin/objdump` ELF aarch64 nesnesini çözdü (`GK0/capraz_deneme/`). Sistem başlıkları gerekmediği için (`-ffreestanding` + kendi önsözümüz) Linux hedefinde sysroot gerekmez. Bağlama (B2) için hedef kitaplıkları gerekmez: yalnız yeniden yerleştirilebilir bağlama yapılır.
3. **Derleyici profili:** özgün derleyici ve bayraklar bilinmediğinden birim küçük bir profil kümesiyle derlenir (öneri: `clang` `-O0`, `-O1`, `-O2`, `-Os`, `-O3`; makinede Homebrew GCC 16.2.0 var ama yalnız Mach-O hedefli, ELF için GCC çapraz derleyicisi yok → ELF'te GCC profili bugün kurulamaz, "ölçülemedi" yazılır). Karşılaştırıcılar her profile uygulanır; biri geçerse işlev geçer ve geçen profil kayda yazılır. Profil sayısı yanlış kabul fırsatını çoğaltır: ölçüm (3.4) aynı profil kümesiyle yapılır, eşik o kümeyle birlikte geçerlidir.
4. **Güvenlik:** derleme hedef kodu çalıştırmaz. Modelin yazdığı metni derlemek ayrı bir risktir (dosya içerme, derleyici eklentisi): önsöz dışında önişlemci yönergesi yasak, `-nostdinc` + yalnız kendi önsöz dizini, derleme `sandbox-exec` ile ağ kapalı ve yazma yalnız koşu dizinine (KİMLİK V1 derlemesindeki düzenin aynısı; `kimlik/PK-6.md` "V1 derlemesi"). Derlemeyi model değil denetleyici başlatır: KaradulLM'in araç kayıt defterinde süreç başlatan araç yine yoktur (`2026-11-18_karadullm_v2/TASARIM.md` §3.9).

### 3.3 Karşılaştırıcılar (hüküm 4'ün adayları)

| Kod | Aday | Ne karşılaştırır | Güçlü yanı | Zayıf yanı | Ghidra | Maliyet (ölçülmedi) | Hangi basamak |
|---|---|---|---|---|---|---|---|
| **K1** | Bayt / normalize komut dizisi eşitliği | Yeniden derlenen işlevin komutları ↔ özgün işlevin komutları; yeniden yerleştirme alanları maskelenir, çağrı ve veri hedefleri simge ↔ adres eşlemesiyle ayrıca karşılaştırılır | Tuttuğunda yanlış kabul yok (yapım gereği); Ghidra gerektirmez (`/usr/bin/objdump` + özgün baytlar adres + boyuttan) | Derleyici / bayrak tutmazsa hiç tutmaz; kapsamı derleyici profiline bağlı | hayır | TAHMİN işlev × profil başına 10–100 ms | B4 (`bayt_eş`), B3 (`komut_eş`: yazmaç adı ve eşdeğer komut seçimi normalize edilmiş) |
| **K2** | P-code öykünmesinde davranış farkı | İki işlev aynı başlangıç durumundan (yazmaçlar + tembel bellek) N girdi vektörüyle yorumlanır; dönüş değeri, yazılan bellek kümesi ve çağrı izi (hedef + argümanlar) karşılaştırılır | Derleyiciden bağımsız; bir vektörde fark = somut karşı örnek (ret sağlam) | "Fark görülmedi" ispat değildir; dış çağrı ve bellek modeli hükmü etkiler; döngü / adım sınırı; öykünücü sadakati | evet (özgün program + nesne dosyası; başsız betik) | TAHMİN işlev başına 0,1–2 sn (N = 64) | B3 (`öykünme`) |
| **K3** | Simgesel eşdeğerlik (SMT) | İki işlevin P-code'u bit vektörü formülüne çevrilir; çıktıların her girdide eşit olduğu çözücüye sorulur (`z3` 4.16.0 makinede kurulu) | İspat verir; yanlış kabul yalnız çeviri hatasından | Yalnız döngüsüz ve küçük işlevler (döngüde sınırlı açma = ispat değil); çağrılar yorumlanmamış işlev; bellek kuramı pahalı | evet (P-code) | TAHMİN küçük işlevde < 1 sn, zaman aşımı 10 sn | B3 (`smt`) |
| **K4** | BSim benzerliği | Ghidra'nın işlev öznitelik vektörleri | Hazır (`karadul/ghidra/bsim.py`) | **Denetleyici olarak önerilmiyor:** KİMLİK ölçümünde derleyici değişince en iyi aday kesinliği 0,610 [0,580–0,639] (tmux), 0,634 (htop); eşiği yükseltmek düzeltmedi (≥ 0,7: 0,610; = 1,0: 0,561); `-O0` ↔ `-O2` 0,592 (`kimlik/BULGULAR.md` §0 madde 5, §2.3, §3.8). Benzerlik "aynı işlev mi" sorusunu bile eşiğin altında cevaplıyor; "aynı davranış mı" sorusunu hiç cevaplamaz (tek sabiti değişmiş işlev benzer kalır) | evet | — | hiçbiri; yalnız **ön süzgeç** (çok düşük benzerlik = erken ret, zaman kazancı) |
| **K5** | CFG eşbiçimliliği + komut kümesi | `karadul/pipeline/steps/cfg_iso_match.py` (`attributed_cfg`) | Hazır | Aynı ölçümde derleyiciler ve derleyici sürümleri arasında 0 eşleşme; aynı derleyicide `-O3` ↔ `-O2` 1 216 / 2 ama kapsam %26,5 (`kimlik/BULGULAR.md` §3.8). Sabitleri ve işleçleri görmez: sınır koşulu değişmiş işlevi kabul eder | hayır (döküm var: `static/ghidra_cfg.json`) | — | hiçbiri; ön süzgeç |
| **K6** | Kendi derlediğimiz iki ikilinin karşılaştırması | Kaynağı elde olan geliştirme ikililerinde (A-23) doğru kaynaktan derleme ↔ yeniden kurulan koddan derleme | Etiketli zemin verir: K1–K3'ün hata oranları burada ölçülür (3.4) | Ürün yolu değil, ölçüm yolu | K2 / K3 için evet | — | ölçüm düzeni |

**Önerilen bileşim:** B4 ve B3 için sırayla K1 → K3 → K2; K4 / K5 yalnız erken ret süzgeci. Her karşılaştırıcının üç cevabı vardır: `geçti`, `geçmedi` (K2'de karşı örnek vektörüyle), `hükümsüz` (adım sınırı, desteklenmeyen komut, çözülemeyen simge, çözücü zaman aşımı). `hükümsüz` hiçbir zaman `geçti` sayılmaz.

**K2'nin modeli (tasarım; GK-E ayrıntılandırır):**

- Özgün program Ghidra'da açıktır. Yeniden derlenen işlevin baytları öykünücünün bellek durumunda boş bir adrese yazılır; yeniden yerleştirmeleri özgün adreslere çözülür (`DAT_<adres>` ve `FUN_<adres>` adları adresi zaten taşır; adlandırılmış simgeler ad haritasından adrese döner). Böylece iki koşuda da işlevin dışındaki her şey **aynı özgün bellek görüntüsüdür**; fark yalnız sınanan işlevden gelebilir.
- Çağrılar yürütülmez: her çağrı noktasında hedef ve argüman yazmaçları ize yazılır, dönüş değeri (tohum, çağrı sırası, hedef)'ten türetilen sözde rastgele sayıdır; iki tarafta aynı sırada aynı değer. Yani denetlenen şey "çağrılanların davranışı aynıyken bu işlev aynı mı"dır (işlev içi eşdeğerlik).
- Okunan ama ilklenmemiş bellek (yığın üstü, işaretçi argümanların gösterdiği bölgeler) adresten türetilen sözde rastgele içerikle tembel doldurulur; iki tarafta aynıdır. İşaretçi argümanlar ayrı sahte bölgelere bakar.
- Karşılaştırılan gözlenebilirler: dönüş yazmaçları, giriş yığın işaretçisinin üstüne ve yığın dışına yapılan yazmalar, çağrı izi. Yığın çerçevesinin içi karşılaştırılmaz (derleyiciye göre değişir).
- Girdi vektörleri: sınır değerleri (0, 1, −1, en büyük / en küçük, işlevdeki sabitler ve ±1 komşuları) + tohumlu rastgele; N ve tohum ön kayıtta yazılır.
- Sistem çağrısı / kesme komutu, dolaylı dallanmanın bilinmeyen hedefe gitmesi, adım sınırı → `hükümsüz`.

**"Çalıştırma yasağı" ve öykünme (karar maddesi K-2, §9):** P-code öykünmesinde hedefin hiçbir komutu işlemcide koşmaz; komutlar JVM içinde yorumlanır, bellek bir kopyadır, dış çağrı ve sistem çağrısı yürütülmez. Önerim: bu, "hedef ikili çalıştırılmaz" kuralının kapsamı dışında sayılsın, şu koşullarla yazılı olarak: (1) yalnız yorumlama (yerel koda çeviri, hata ayıklayıcı, süreç başlatma yok); (2) tek işlev, yalıtılmış; (3) dış çağrı ve sistem çağrısı hiçbir zaman yürütülmez; (4) adım, bellek ve süre bütçesi; (5) durağan sınama: denetleyici kodunda süreç başlatan tek çağrı derleyici ve Ghidra'dır. Karar Berke'nindir; kabul edilmezse B3 yalnız K1 + K3 ile verilir (kapsam ölçülmedi; daha dar olacağı kesin).

### 3.4 Yanlış kabul / yanlış ret nasıl ölçülür

Denetleyici, çıktıya bağlanmadan önce kendisi ölçülür. Zemin: kaynağı elde olan ve bizim derlediğimiz ikililer (A-23; `~/karadul_olcum/kimlik_v1/`: tree, libzstd, sqlite3, redis; çıktılar çalıştırılmaz).

| Küme | Nasıl kurulur | Gerçek etiket | Ne ölçer |
|---|---|---|---|
| **P (pozitif)** | Aynı kaynak işlevinin iki ayrı derlemesi: (a) aynı derleyici, farklı düzey; (b) farklı derleyici (GCC ↔ clang; Mach-O'da ikisi de var); (c) aynı derleyici ve bayrak (denetim: K1 burada %100 vermelidir) | eşdeğer (derleyicinin doğruluğu varsayılır) | yanlış ret, karşılaştırıcı × derleme uzaklığı başına |
| **N1 (bozulmuş)** | Kaynak işlevine tek mutasyon (karşılaştırma işleci, sabit ±1, sınır, argüman sırası, işaret / genişlik, bir atamanın silinmesi, dal koşulunun değillenmesi) + derleme | eşdeğer değil; **üst sınır:** eşdeğer mutantlar ayıklanamaz, yalnız nesne kodu bozulmamış hâliyle bayt eşit olan mutantlar atılır | yanlış kabulün üst sınırı |
| **N2 (yabancı)** | Aynı imza biçimine sahip başka bir işlevle eşleştirme | eşdeğer değil | kolay yanlış kabul (ayrı satır; N1 ile havuzlanmaz) |
| **A (gerçek aday)** | Aynı ikililerin Karadul çıktısındaki işlevler, B1'e getirilebilenler | bilinmiyor | hüküm dağılımı ve `hükümsüz` payı (hata oranı değil) |

- Sayım A-14 düzeniyle: örnek düzeyi ve tekil kaynak işlevi düzeyi; en az 3 bağımsız program; Wilson aralığı. Kümeler tohumla seçilir, tohum ön kayıtta.
- Geliştirme / sınama ayrımı: mutasyon işleçleri ve K2'nin gözlenebilir tanımı iki programda (tree, libzstd) geliştirilir, dondurulur (dondurma commit'i yazılır), sonra kalan programlarda (sqlite3, redis) bir kez ölçülür. Kilitli setler açılmaz.
- "Yeni yanlış"ın bu hattaki tanımı (§6): denetleyiciden `geçti` alıp gerçekte eşdeğer olmayan işlev. Ölçümde N1 ∪ N2 üstünde sayılır; üründe sayılamaz (gerçek bilinmez), bu yüzden eşik ölçüm kümesinden gelir.

### 3.5 Eşik (A-13 / A-14 düzeni)

- A-13'ün sayısı (0,909 = L / (L + 1), L = 10; `karadul/core/naming_labels.py` `AD_ESIGI`, `MALIYET_ORANI_L`) **ad** için verilmiş bir hükümdür: yanlış ad, eksik adın 10 katı kötü. "Eşdeğer" etiketi için maliyet oranı ayrı bir karardır (K-3, §9). Önerim: bir kanıt türü `geçti` etiketi yazabilsin ancak ve ancak (i) N1 üstünde yanlış kabul oranının Wilson **üst** sınırı ≤ 0,01, (ii) en az 3 bağımsız programda ölçülmüş, (iii) P üstünde yanlış reddi raporlanmış (eşik yok; yalnız kapsam kaybıdır). Gerekçe: "eşdeğer" etiketi analistin o işlevi bir daha okumayacağı anlamına gelir; yanlış ad okuyanı yanıltır, yanlış "eşdeğer" ise okutmaz.
- Karar gelene kadar asgari sınır A-13'ün kendisidir: kabul edilenlerin kesinliğinin Wilson alt sınırı ≥ `AD_ESIGI`. Yeni sabit tanımlanırsa tek yerde (`karadul/core/naming_labels.py`'nin yanında, GK-I) tanımlanır ve içe aktarılır; hiçbir pakette sayı yazılmaz.
- Eşiği sağlamayan kanıt türü etiket yazmaz; hükmü **kanıt satırı** olur (A-14'teki "bayrak arkasında kalır ya da kanıt satırı yazar" kuralının aynısı).
- `bayt_eş` için eşik gerekmez (yanlış kabul yapım gereği yok); yine de N1 üstünde 0 verdiği ölçülür (uygulama hatasına karşı).

### 3.6 Model dolgusunun denetimi

Denetleyici, parçanın kimden geldiğine bakmaz: motorun çıkardığı gövde de modelin onardığı gövde de aynı kapıdan geçer. Modelin önerebileceği parça türleri ve her birinin kapısı:

| Parça | Kapı (hepsi makinenin cevabı) |
|---|---|
| Ad (işlev, değişken, alan) | Ad davranışı değiştirmez: yeniden derlenen birimin nesne kodu ad değişmeden önceki nesne koduyla **bayt eşit** olmalı (simge tablosu dışında). Adın doğruluğu bu hattın konusu değildir; `model önerisi` etiketiyle kalır (ad kapıları: `karadul/lm/guard.py` `check_proposal`) |
| Tip / bildirim | Birim B1'e çıkmalı ve B2'nin imza tutarlılığı bozulmamalı; işlev daha önce B3'teyse B3'te kalmalı (aynı karşılaştırıcı yeniden koşar) |
| Gövde onarımı (derlenmeyen işlevi derlenir yapmak) | B1 + B3. B3 alamayan onarım çıktıya **girmez**; "derleniyor ama doğrulanmadı" diye de girmez. Kanıt satırı olur |
| Eksik işlev gövdesi (decompile edilememiş) | B1 + B3 (özgün baytlar var olduğu sürece denetlenebilir) |
| Yorum / açıklama | Kod değildir; var olan özet bekçisi (`check_summary`) |

Bu tablo hüküm 2'nin ("denetimden geçmeyen öneri çıktıya girmez") mekanik karşılığıdır.

## 4. Belirlenimci katman [YAZILMADI]

## 5. KaradulLM katmanı [YAZILMADI]

## 6. Ölçüm düzeni ve ön kayıt [YAZILMADI]

## 7. Önceki çalışmalarla ilişki [YAZILMADI]

## 8. Uygulama planı

### 8.0 Paketler, sıra, zincirler

14 alt paket. "Kim" sütunu A-40 düzeniyle: planı ve ölçümü belli yazma işi Opus, ağır mühendislik Mythos. "Bugün" = önkoşulu olmayan, 2026-11-24'te gönderilebilir.

| Paket | Tema | Kim | Ghidra | Model | Derleyici | Önkoşul | Bugün |
|---|---|---|---|---|---|---|---|
| **GK-A** | Ölçüm aracı, taban ve "geriye gitme yok" kapısı | Opus | hayır | hayır | clang | — | evet |
| **GK-B** | `types.h` onarımı (başlık kaynaklı hatalar) | Opus | hayır (yeniden oynatma) | hayır | clang (yalnız ölçüm) | — (dosya zinciri: ÇA paketleriyle sıralı) | evet |
| **GK-C** | Birim önsözü: bildirim üretimi (yeni modül, bağlamasız) | Opus | hayır (yeniden oynatma) | hayır | clang (yalnız ölçüm) | — | evet |
| **GK-D** | Etiketli çift kümesi + K1 (`bayt_eş`, `komut_eş`) | Mythos | hayır | hayır | clang, GCC 16 (Mach-O) | — (A-23 kaynakları yerinde) | evet |
| **GK-E** | K2: P-code öykünme karşılaştırıcısı | Mythos | evet (kuyruk) | hayır | clang | GK-D (çift kümesi), karar K-2 | hayır |
| **GK-F** | K3: SMT eşdeğerliği (küçük, döngüsüz işlev) | Mythos | evet (P-code) | hayır | clang | GK-E'nin nesne → P-code köprüsü | hayır |
| **GK-G** | Ghidra artıklarının çevrilmesi (p-code işleçleri, sahte değişkenler, etiketler) | Opus | hayır | hayır | clang (ölçüm) | GK-B, GK-C | hayır |
| **GK-H** | B2: yeniden yerleştirilebilir bağlama ve simge mutabakatı | Opus | hayır | hayır | clang, `/usr/bin/ld`, `/usr/bin/nm` | GK-B, GK-C | hayır |
| **GK-I** | Etiket / köken şeması, `geri_kurma.json`, rapor sütunları | Opus | hayır | hayır | — | GK-A (alan adları), karar K-3 | hayır |
| **GK-J** | KaradulLM `onar` görevi (döngü, bağlam, bekçi kuralları; sahte arka uçla sınanır) | Mythos | hayır | hayır (pakette model koşmaz) | clang | GK-C, GK-D ya da GK-E (en az bir B3 kanıtı), GK-I; `karadul/lm` zinciri | hayır |
| **GK-K** | Modelli ölçüm (ön kayıtlı; ana oturum koşar) | ana oturum | evet | **evet** (yerel) | clang | GK-J, makine boş | hayır |
| **GK-L** | Dil uyarlamaları: C++ / ObjC / Go / Swift (çalışma zamanı bildirimleri, çağrı düzeni uyarlayıcısı) + hedef setinde kapsam | Mythos | evet | hayır | clang | GK-E, üst veri okuyucuları (main'de) | hayır |
| **GK-M** | Boru hattına bağlama: `geri_kurma` adımı (bayrak arkasında, öntanım kapalı), CLI, arayüz ve MCP görünümü | Opus | hayır | hayır | clang (çalışma anında, isteğe bağlı) | GK-B, GK-C, GK-G, GK-H, GK-I; karar K-5 | hayır |
| **GK-N** | Kapanış ölçümü: hedef seti + 119 + S8, ön kayıtlı son sayılar; README amaç cümlesi | ana oturum + Opus | evet | isteğe bağlı sütun | clang | hepsi | hayır |

**Zincirler (aynı dosya; sıralı gider):**

1. `karadul/reconstruction/c_project_builder.py`: GK-B → ÇA paketleri (A-39; sırayı ana oturum belirler, ikisi aynı anda gitmez) → GK-G'nin bağlaması → GK-M. GK-B yalnız `GHIDRA_TYPEDEF_LINES` ve `_build_types_h`'ye dokunur; ÇA yerleşim ve adlandırma işlevlerine. İşlev kümeleri ayrık ama dosya aynı: CLAUDE.md §2 kuralı gereği **sıralı**.
2. `karadul/reconstruction/c_type_recoverer.py`: GK-B (enum sabit adları, `types.h` metni) — bugün başka paketin listesinde değil (HZ7a `c_namer.py` ve `api_param_db.py`'de; `gonderim/HZ7a.md`).
3. `karadul/lm/**`: P22'nin kalanları → GK-J. GK-J yeni dosyada (`karadul/lm/onar.py`) yaşar; `agent.py`, `protocol.py`, `guard.py`'ye dokunuşu yama ya da zincir sırasıyla.
4. Ghidra köprüsü: GK-E ve GK-F `karadul/ghidra/headless.py`'ye **dokunmaz** (ÖL-3 / HZ-4a zinciri orada); ayrı, tek amaçlı başsız betik yazar (`karadul/ghidra/scripts/` altında yeni dosya) ve kuyruğa ad / kimlik koşusu gibi girer (A-31).
5. `karadul/config.py`: kimse yazmaz (A-19, A-34). Bayrak alanları (GK-M) yama olarak bırakılır.

**Serbest (yalnız yeni dosya):** GK-A, GK-C, GK-D, GK-H, GK-I.

**Önkoşul olarak bağlanan var olan paketler (hüküm 7):**

| Var olan iş | Bu hatla ilişkisi |
|---|---|
| P18 (alt sistem başlıkları; main'de) | Başlıklar tanımla tutarlı hâle geldi (36 078 çelişkili bildirim → 0) ama `.c` dosyaları onları **içermiyor** (§1.4): GK-C bu boşluğu kapatır. P18'in "kalan"ı (`analysis/xref_index.md`, `subsystem_map.md` eski adlar) bu hattı etkilemez |
| Tip kurtarma (`c_type_recoverer.py`, `struct_recovery`, `type_recovery_consumer`) | `types.h`'nin içeriğini üretir; bugün derlenmiyor (§1.3). GK-B onarır; tip **doğruluğu** B3'le dolaylı denetlenir (yanlış alan genişliği davranışı değiştirir) |
| ÇA (çıktı ağacı, A-39) | Adres ↔ dosya dizini GK'nin birim bulma yoludur: GK paketleri dosya yoluna değil adrese bağlanır (`// Address:` satırı bugün; ÇA'nın dizini gelince o). ÇA dosya adlarını değiştirince GK-A tabanı adres anahtarlı olduğu için bozulmaz |
| ÖL-10 (tembel derinlik) | Decompile edilmemiş işlevin adayı yoktur: B düzeyleri "decompile edilmedi" paydasını ayrı gösterir (`static/tembel_durum.json` sayacı; `olcek/OL10_TASARIM.md` §4) |
| P22 (KaradulLM altyapısı) | Olay akışı, kipler, oturum, araç kaydı v2 ağaçta (`karadul/lm/events.py`, `modes.py`, `session.py`, `tools/read_more.py`); arayüz ve ölçüm paketlerinin durumu bu turda denetlenmedi. GK-J bunların üstüne kurulur |
| P24 (MCP) | GK-M'in MCP görünümü P24'ün sunucusuna bir araç ekler (`geri_kurma_durumu`: salt okur); P24'ten önce yazılmaz |
| HZ hattı | Derleme ve denetim süresi HZ ölçümlerine yeni satır olarak girer; gündüz süre ölçümü yapılmaz (ORTAK_D1 §2) |

### 8.1 GK-A — ölçüm aracı, taban, kapı (Opus; bugün)

- **Amaç:** `scripts/arge/gerikurma/derlenebilirlik.py`'yi kalıcı ölçüm aracına çevirmek ve §1'in sayılarını taban olarak kilitlemek.
- **Kalemler:** (1) aracı `scripts/measurement/gk_derlenebilirlik.py`'ye taşı (arge betiği durur; yeni araç onu içe aktarmaz, kopyalar ve sınar); (2) hedef seçimi: çıktının `report.json`'ındaki biçim / mimariden derleyici üçlüsü (`--target`) ve `-ffreestanding`; iki kip yan yana raporlanır (ana makine üçlüsü = bugünkü ölçüm; hedef üçlüsü); (3) nesne kipi (`-c`, çıktı koşu kökünde; B1'in tam tanımı); (4) adres anahtarlı kayıt: her birim `// Address:` satırıyla anahtarlanır, dosya yolu ikincil; (5) işlev sınırı sezgiseli `definition_signatures` (`c_project_builder.py`) sayımıyla karşılaştırılır, fark raporlanır; (6) taban dosyası `ozet/gk_taban.json` (9 çıktı) + karşılaştırma kipi: "geçen birim kümesi tabanın üst kümesi mi"; (7) testler (yapay C dosyaları: her hata sınıfına bir örnek) + mutasyon tanımı.
- **Dosyalar:** yeni `scripts/measurement/gk_derlenebilirlik.py`, `tests/test_gk_derlenebilirlik.py`, `scripts/measurement/mutation_specs_gk_a.json`, `docs/arge/2026-11-19_mythos/gerikurma/GK-A.md`, `GK-A_on_kayit.md`.
- **Ön kayıt (ölçümden önce commit):** H1: yeni araç ana makine üçlüsünde §1.2 ve §1.3 tablolarının dosya ve hata sayılarını **birebir** yeniden üretir (9 / 9 çıktı; aynı clang sürümü). H2: hedef üçlüsünde ELF çıktılarında `+sdk_cakismasi` sınıfı 0'a iner. H3: işlev sayısı farkı (sezgisel ↔ `definition_signatures`) her çıktıda ≤ %2. H4: mutant ≥ 6, hepsi ölür.
- **Kabul:** H1–H4; tam takım yeşil; araç hiçbir girdi köküne yazmaz (sınama: girdi kökü salt okunur bağlanmış geçici kopyada koşu).

### 8.2 GK-B — `types.h` onarımı (Opus; bugün; `c_project_builder.py` zincirinin başı)

- **Amaç:** §1.3'ün bulgusu: her çıktıda bütün hataların büyük çoğunluğu ve her dosyanın ilk hatası `types.h`'den geliyor; başlık derlenmediği için hiçbir dosya derlenmiyor.
- **Kalemler (hepsi §1.3'te ölçülmüş sınıflar):** (1) Ghidra'nın temel tip adları (`byte`, `word`, `dword`, `qword`, `uint`, `ulong`, `ushort`, `longlong`, …) `GHIDRA_TYPEDEF_LINES`'a; (2) enum sabit adları: geçersiz tanımlayıcı (eksi işaretli değerden üretilen ad) ve enum'lar arası çakışan sabit adı (`c_type_recoverer.py`'de `VAL_<değer>` üretimi) → sabit adı enum adıyla öneklenir, geçersiz karakter çevrilir; (3) kurtarılan yapıların üye bildirimlerindeki ayrıştırma hataları (üye adı tip adıyla aynı, saklama sınıfı belirteci, yinelenen üye): önce sınıf başına sayım, sonra onarım; (4) hedef platformun kendi sistem tipleri (`__off_t` ailesi): Ghidra'nın tip dökümünde (`static/ghidra_types.json`) tanımı varsa oradan, yoksa "tanımsız tip" olarak **yorumla** yazılır, uydurulmaz; (5) ana makine SDK'sıyla çakışan adlar (`sdk_cakismasi` sınıfı): `types.h` barındırılan başlıkları çekmeyecek biçimde kurulur ve projenin derleme dosyaları (`_build_makefile`, `_build_cmake`, `_build_compile_commands`) hedef üçlüsünü ve `-ffreestanding`'i yazar; (6) derleme dosyalarındaki `-w` bayrağına bu pakette dokunulmaz (karar K-6); ölçülen: bu clang sürümünde `-w` hataya yükseltilmiş uyarıları susturmuyor (§1.1); (7) testler: üretilen `types.h`'nin `clang -fsyntax-only`'den geçtiği, clang yoksa atlanan sınama + mutasyon.
- **Dosyalar:** `karadul/reconstruction/c_project_builder.py` (yalnız `GHIDRA_TYPEDEF_LINES`, `_build_types_h`, üç derleme dosyası üreticisi), `karadul/reconstruction/c_type_recoverer.py` (yalnız enum sabit adı ve `types.h` metnini üreten işlevler), yeni `tests/test_gk_b_types_h.py`, `scripts/measurement/mutation_specs_gk_b.json`, `gerikurma/GK-B.md`, `GK-B_on_kayit.md`. **Dokunma:** yerleşim ve dosya adlandırma işlevleri (ÇA), `output_formatter.py` (PUV6b).
- **Ölçüm yolu:** Ghidra'sız yeniden oynatma (P18'in yöntemi: `CProjectBuilder` çalışma alanının `reconstructed/annotated/` girdisiyle yeniden koşar; P18'de `out/src` ile bayt bayt aynı çıktı verdiği gösterildi).
- **Ön kayıt:** H1: 9 / 9 çıktıda başlık kaynaklı hata 0 (bugün: §1.2 tablosunun "başlıkta" sütunu). H2: ürün kipinde K ile geçen dosya sayısı her çıktıda ≥ bugünkü önsöz kipindeki sayı (§1.3 tablosu); tutmayan çıktı nedenleriyle yazılır, eşik değişmez. H3: `.c` dosyalarının gövdesi ve ad haritası değişmez (S8 8 / 8 bayt eşit; fark yalnız `include/types.h` ve derleme dosyalarında). H4: 119 ikilinin yeniden oynatmasında `types.h` tek başına `clang -fsyntax-only`'den 119 / 119 geçer.
- **Kabul:** H1, H3, H4 tutar; H2'nin sonucu yazılır; tam takım yeşil; mutant ≥ 6.

### 8.3 GK-C — birim önsözü: bildirim üretimi (Opus; bugün; yalnız yeni dosya)

- **Amaç:** §1.3'te başlık devre dışıyken kalan hataların en büyük sınıfı eksik bildirim (çağrılan işlev, veri simgesi). `.c` dosyaları yalnız `types.h`'yi içeriyor; P18'in düzelttiği alt sistem başlıkları hiçbir dosyaya girmiyor.
- **Kalemler:** (1) envanter: her eksik bildirim ailesi için bildirimin kaynağı var mı — program işlevleri: `definition_signatures`; içe aktarımlar ve taslaklar: `static/ghidra_functions.json` (`return_type`, `parameters`, `is_thunk`); veri simgeleri (`DAT_`, `PTR_`, dizgi simgeleri): adres + tip dökümü var mı (bu turda **bakılmadı**; yoksa kalem 4); (2) saf işlev: (birimler, statik dökümler) → birim başına önsöz metni; yalnız o birimin kullandığı adlar (kullanım kümesi derleyicinin "undeclared" iletilerinden değil, metnin belirteç taramasından çıkar); (3) çelişki kuralı: aynı ad için iki farklı imza kaynağı varsa bildirim yazılmaz, sayılır (P18'in kuralı); (4) veri simgesinin tipi bilinmiyorsa `extern undefined1 AD[];` (adres alma ve dizinleme derlenir; değer olarak kullanım derlenmez ve "tipi bilinmeyen veri" sınıfında sayılır) — köprüden tip dökümü gerekiyorsa ÖL-3 zincirine kalem olarak **önerilir**, bu pakette `headless.py`'ye dokunulmaz; (5) ölçüm: GK-A aracıyla, üretilen önsöz `-include` ile verilerek (ürün çıktısı değişmeden); (6) testler + mutasyon.
- **Dosyalar:** yeni `karadul/reconstruction/gerikurma/__init__.py`, `karadul/reconstruction/gerikurma/bildirim.py`, `tests/test_gk_c_bildirim.py`, `scripts/arge/gerikurma/onsoz_olc.py`, `scripts/measurement/mutation_specs_gk_c.json`, `gerikurma/GK-C.md`, `GK-C_on_kayit.md`.
- **Ön kayıt:** H1: önsöz kipi + üretilen bildirimlerle `eksik_bildirim_islev` sınıfının hata sayısı her çıktıda §1.3'teki değerin ≤ %10'una iner. H2: K ile geçen dosya oranı her çıktıda §1.3'teki G oranına ulaşır ya da geçer (G = örtük bildirim hataları sayılmadığında geçenler; bildirim gelince bu dosyaların geçmesi beklenir). H3: üretilen bildirimlerden doğan **yeni** hata (`tip_celiskisi_bildirim`) sayılır; payı raporlanır (eşik yok: bu sayı tip kurtarmanın imza hatasını ölçer). H4: önsöz belirlenimci (iki koşu bayt eşit).
- **Kabul:** H1, H4 tutar; H2, H3 yazılır; ürün davranışı değişmez (bağlama GK-M'de).

### 8.4 Sonraki paketlerin kabul ölçütleri (kısa)

| Paket | Kabul ölçütü ve ön kayıt çekirdeği |
|---|---|
| **GK-D** | Çift kümesi dondurulur (sha256 dökümü; ≥ 3 program; P ≥ 300 çift, N1 ≥ 1 000 mutant, tohum yazılı). P(c) (aynı derleyici, aynı bayrak) üstünde `bayt_eş` %100; N1 ∪ N2 üstünde `bayt_eş` ve `komut_eş` kabulü **0**; P(a), P(b) üstünde yanlış ret oranı raporlanır (eşik yok). Hiçbir derleme çıktısı çalıştırılmaz. Dosyalar: yeni `karadul/reconstruction/gerikurma/karsilastir_komut.py`, `scripts/arge/gerikurma/{cift_kumesi,mutasyon_c,k1_olc}.py`, testler |
| **GK-E** | Geliştirme programlarında (tree, libzstd) gözlenebilir tanımı ve girdi üreteci dondurulur; sınama programlarında (sqlite3, redis) bir kez: N1 üstünde yanlış kabul Wilson üst sınırı ≤ eşik (K-3) ise `öykünme` kanıtı etiket yazar, değilse kanıt satırı. `hükümsüz` payı ve nedenleri raporlanır. Durağan sınama: betikte sistem çağrısı yürüten yol yok |
| **GK-F** | Yalnız döngüsüz, ≤ ön kayıtlı P-code işlem sayılı işlevler; N1 üstünde kabul 0 (ispat iddiası); P üstünde kapsam raporlanır; çözücü zaman aşımı `hükümsüz` |
| **GK-G** | Önsöz kipi + GK-C + işleç başlığıyla `ghidra_pcode_isleci` sınıfı 0; sahte değişken sınıfları (`in_`, `unaff_`, `extraout_`) **bildirimle susturulmaz** — derlenir kılınan her işlev "B1: yapay bildirimle" etiketini taşır ve B3'e gitmeden "kurtarıldı" sayılmaz |
| **GK-H** | S8 çıktılarında `ld -r`: çift tanım sayısı, çözülmeyen simge kümesinin içe aktarım tablosuyla farkı; B2 tuttu / tutmadı program başına |
| **GK-I** | Şema (§5.5) + doğrulayıcı; rapor sütunları yalnız gerçek sayılardan dolar, veri yoksa "ölçülmedi" (sahte veri yasağı sınaması: şemada varsayılan sayı yok) |
| **GK-J** | Sahte arka uçla: (a) denetimden geçmeyen öneri çıktıya giremez (mutant: kapıyı atlayan yol → test ölür); (b) deneme sınırı ve süre bütçesi aşılmaz; (c) modelin metninde önişlemci yönergesi → ret; (d) her öneri köken kaydı üretir |
| **GK-K** | §6.3 ön kaydı |
| **GK-L** | Dil başına B0–B3 oranı hedef setinde; uyarlayıcı kapsamı (kaç işlevin çağrı düzeni C'ye çevrilebildi) sayıyla |
| **GK-M** | Bayrak kapalıyken S8 çıktısı bayt eşit; bayrak açıkken `geri_kurma.json` üretilir, süre ayrı satır; clang yoksa adım "atlandı: derleyici yok" der (uydurma sonuç yok) |
| **GK-N** | Ön kayıtlı son tablo: çıktı × basamak × (motor tek başına / + KaradulLM) |

### 8.5 Süre (TAHMİN; ölçüm değil)

Dayanak: iki uygulama oturumunda ölçülen hız yaklaşık 2,8 paket / saat (4–5 ajanla; `2026-11-23_dalga1/DURUM.md` "Oturum kapanışı"). GK paketlerinin altısı (D, E, F, J, L, N) o ortalamadan ağır.

- GK-A, B, C, D birlikte: TAHMİN 1 oturum (3–5 saat).
- GK-E, F, G, H, I: TAHMİN 2–3 oturum; GK-E Ghidra kuyruğuna bağlı.
- GK-J, K, L, M, N: TAHMİN 3–5 oturum + 1–2 gece (modelli ölçüm ve hedef seti).
- Toplam: TAHMİN 6–9 oturum (25–40 oturum saati) + 1–2 gece. Var olan plana (kalan yaklaşık 81 paket, 40–55 oturum saati) **eklenir**; en çok oynatacak belirsizlik K2'nin `hükümsüz` payıdır (ölçülmedi).

## 9. Riskler, dürüst sınırlar, karar listesi

### 9.1 Ulaşılamayan (bilgi ikilide yok ya da bugünkü yolla geri gelmez)

| Ne | Neden | Sonucu |
|---|---|---|
| Özgün adlar, yorumlar, makrolar, dosya ve dizin düzeni (üst verisi olmayan C / C++) | Derleme siler (`2026-10-15_makale/tersine_derleme_sinirlari.md` §3) | Geri kurulan kod **başka adlarla** yazılır; A-41 bunu açıkça kabul ediyor. Ad doğruluğu bu hattın ölçüsü değildir |
| Özgün kaynak **metni** | Çok-bire eşleme: aynı makine kodunu veren sonsuz kaynak var | Hedef "özgün kaynak" değil "aynı davranışı veren derlenebilir kaynak"tır. Belgelerde "eski hâline döndü" yerine "yeniden derlenebilir ve denetlenmiş eşdeğer" yazılmalı |
| Bayt eşit yeniden derleme (genel durumda) | Özgün derleyici, sürüm, bayraklar, bağlama sırası bilinmiyor; LTO ve profil yönlendirmeli derleme yeniden üretilemez | B4 hedef değil, tuttuğu yerde bedava kanıt |
| Satır içine alınmış işlevlerin sınırları | Derleyici gömmüş; ikilide ayrı işlev yok (KİMLİK'te yanlışların ana sınıfı: `kimlik/BULGULAR.md` §0 madde 3) | Geri kurulan işlev kümesi ikilinin işlev kümesidir, kaynağınki değil |
| Kullanılmayan (bağlayıcının attığı) kod, koşullu derlemenin öbür dalları | İkilide yok | Kapsam "ikilide olan kod"dur |
| Program düzeyinde davranış eşdeğerliğinin **ispatı** | Kararsız (genel durumda); hedef çalıştırılmadığı için uçtan uca sınama da yok | En güçlü cümle: "işlevlerin şu kadarı işlev içi eşdeğerlik denetiminden geçti" |
| Go / Swift'te aynı dilde kaynak | Dil yapıları (goroutine, arayüz, genel tip örneklemesi, ARC) çalışma zamanı çağrılarına indirgenmiş; C sözdizimi çıktısı dilin çağrı düzenini ifade etmez | §2.3: bu dillerde hedef "C olarak derlenen + uyarlayıcıyla denetlenen" koddur; aynı dilde geri kurma bu planda yok (K-7) |
| C++ istisna yolları | Ghidra'nın C çıktısı açma tablolarını göstermez | B3 yalnız istisnasız yollar için söylenebilir; etiket bunu yazar |

### 9.2 En büyük üç risk

1. **B3'ün kapsamı küçük çıkabilir.** K1 derleyici tutmayınca tutmaz; K3 yalnız küçük işlevlerde; K2'nin `hükümsüz` payı ve ölçülecek yanlış kabulü bilinmiyor. KİMLİK ölçümü yapısal benzerliğin derleyiciler arasında çöktüğünü gösterdi (BSim 0,61; CFG 0 eşleşme) — K2 de beklentiyi karşılamazsa hattın söyleyebildiği "derleniyor ama eşdeğerliği gösterilemedi" olur. Erken ölçüm: GK-D (Ghidra'sız, bugün) ve GK-E'nin ilk 100 çifti; ikisi de üründen önce.
2. **B1'e giden yol "derlenir kılmak için uydurma"ya kayabilir.** Eksik bildirimi `int f()` ile, sahte değişkeni boş yerel değişkenle doldurmak derleme sayısını yükseltir ama kodu yanlış yapar. Bugünkü G sütunu (§1) tam olarak bu sahte iyileşmenin büyüklüğünü gösteriyor. Koruma: B1 tek başına hiçbir yerde "kurtarıldı" diye raporlanmaz; yapay bildirimle derlenen birim etiketlidir (GK-G); model dolgusu B3 almadan çıktıya girmez (§3.6).
3. **Modelin onardığı gövde denetleyicinin kör noktasına oturabilir.** Model, K2'nin girdi vektörlerinde aynı davranan ama genelde farklı kod yazabilir (özellikle vektörleri görürse). Koruma: model girdi vektörlerini ve tohumu görmez; kabul için kullanılan vektör kümesi onarım döngüsündekinden ayrıdır (döngüde geri bildirim yalnız derleyici hatası ve "geçmedi" + tek karşı örnek); yanlış kabul, model önerileri üstünde ayrıca ölçülür (GK-K: kaynağı elde olan ikilide modelin geçen önerileri doğru kaynağın derlemesiyle K3 / geniş vektörle yeniden sınanır).

Ek riskler: çıkış süresi (13 159 işlev × 5 profil × K2; ölçülmedi); ana makine ↔ hedef platform farkı (ELF çıktısı Mac'te derleniyor: §1'de `sdk_cakismasi` sınıfı olarak ölçüldü; hedef üçlüsüyle giderilir, GK-A H2); yerel modelin bellek tavanı (ölçülen tepe 17,63 GiB; aynı anda Ghidra + derleyici koşarsa bütçe: ölçülmedi).

### 9.3 Karar listesi (Berke / ana oturum)

| No | Karar | Önerim |
|---|---|---|
| **K-1** | Basamak tanımları (B0–B4, §3.1) ve program düzeyinde tek "eşdeğer" hükmü verilmemesi | Kabul. Raporlar basamak başına oran verir |
| **K-2** | P-code öykünmesi "hedef ikili çalıştırılmaz" kuralına girer mi? | **Girmez**, §3.3'teki beş koşulla ve yazılı olarak. Kabul edilmezse B3 yalnız K1 + K3 ile (dar kapsam) |
| **K-3** | "Eşdeğer" etiketinin eşiği: A-13'ün sayısı mı (kesinlik alt sınırı ≥ 0,909), ayrı ve daha sıkı bir sayı mı | Ayrı sabit: yanlış kabulün Wilson üst sınırı ≤ 0,01, ≥ 3 program; karar gelene kadar A-13 asgari sınır |
| **K-4** | Derleyici profili kümesi (kaç bayrak / derleyici denenecek) ve ELF için GCC çapraz derleyicisi kurulsun mu (paket kurma izni gerekir) | Önce yalnız clang 5 profil; GCC çapraz derleyicisi GK-D'nin ölçümünden sonra, K1 kapsamı ELF'te düşük çıkarsa Berke'ye sorulur |
| **K-5** | Ürün çalışma anında derleyici çağırsın mı (`geri_kurma` adımı clang ister) | Evet, isteğe bağlı adım olarak, öntanım kapalı; clang yoksa "atlandı: derleyici yok". Paketlemede (Y8) Xcode komut satırı araçları **bağımlılık olarak yazılır**, gömülmez |
| **K-6** | Projenin kendi derleme dosyalarındaki `-w` ve hedef üçlüsü | `-w` kalır (okuyanı uyarı selinden korur) ama README'deki derleme iddiası ölçülen B1 oranıyla değişir; hedef üçlüsü ve `-ffreestanding` yazılır |
| **K-7** | Go / Swift / ObjC / C++'ta "eski hâline dönmek" = C olarak derlenen ve denetlenen kod; aynı dilde kaynak bu planda yok | Kabul; ObjC'de `.m` çıktısı (C gövdeli) ayrı ve sonraki bir karar |
| **K-8** | KaradulLM'in gövde önerisi çıktıya nasıl girer: denetimden geçince kendiliğinden mi, analistin onayıyla mı (A-33 K-6 ile ilişki) | Denetimden geçen öneri **ayrı katmana** kendiliğinden yazılır (`model önerisi` + kanıt türü etiketiyle; motorun çıktısının üstüne yazılmaz); motor çıktısının yerine geçmesi analistin onayıyla. Model kendi başına decompile ya da derleme başlatmaz |
| **K-9** | İlk üç paket (GK-A, GK-B, GK-C) ve GK-D bugün gönderilsin mi; `c_project_builder.py` zincirinde GK-B ↔ ÇA sırası | Evet; GK-B önce (küçük ve ölçümü hazır), ÇA paketleri arkasından |
| **K-10** | README'deki amaç cümlesi (aşağıda 9.4) ne zaman girer | GK-B + GK-C main'e girip §1 tablosu yenilenince; o güne kadar README değişmez |
| **K-11** | Model katmanının ölçümünde (GK-K) kullanılacak yerel model: bugünkü Qwen3.8-27B Q4_K_M mi, kod onarımına ayrı bir model mi | Önce eldeki modelle (indirme yok); ayrı model ancak ölçüm yetersiz çıkarsa ve Berke'nin indirme izniyle |

### 9.4 Proje belgelerindeki ana amaç cümlesi (öneri; iddia değil HEDEF)

> **Amaç.** Karadul, derlenmiş bir programdan **yeniden derlenebilen ve özgün programla aynı davranan** kaynak kodu çıkarmayı hedefler. Motor, ikilide bulunan bilgiyi belirlenimci hesapla kurtarır; kalan boşlukları isteğe bağlı yerel model (KaradulLM) önerir; her parça bir denetleyiciden geçer ve hangi denetimden geçtiğini üstünde taşır. Adlar özgün olmayabilir; kod denetlenebilir olmalıdır.
>
> **Bugün neredeyiz (‹tarih›, ‹commit›; ölçüm: `gk_derlenebilirlik`):** çıktıdaki `.c` dosyalarının %‹B1› kadarı tek başına derleniyor; işlevlerin %‹B3› kadarı özgün işlevle eşdeğerlik denetiminden geçti (‹kanıt türü dağılımı›); bayt eşit %‹B4›. Hedef ikili hiçbir aşamada çalıştırılmaz.

Yer tutucular GK-A'nın tabanından dolar. Bugünkü değerlerle (§1) cümle "‹B1› = 0" diye yazılırdı; bu yüzden cümlenin README'ye girişi K-10'a bağlandı. "Kurtarıldı", "geri kazanıldı", "özgün kaynak" sözcükleri kullanılmaz.

## Ek A. Atıf doğrulaması [YAZILMADI]
