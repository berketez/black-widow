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

## 8. Uygulama planı [YAZILMADI]

## 9. Riskler, dürüst sınırlar, karar listesi [YAZILMADI]

## Ek A. Atıf doğrulaması [YAZILMADI]
