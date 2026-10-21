# K1 ve K2 ön kaydı (TASLAK)

- **Tarih:** 2026-10-21
- **Durum:** Taslak. T0b (parametre hizalaması) ve T0c (çıplak Ghidra tabanı) sonuçlarından sonra, doğrulama setine bakılmadan kesinleşir ve commit'lenir. Kesinleşmeden önce mikro teknik seçimler (işaretli: **[seçim]**) Codex'e danışılır.
- **Plan:** v2.2 §5 (Berke'nin kararı, 2026-10-21): eşikler %95, ölçü tanımları aşağıdaki gibi.
- **Dayanak ölçümler:** T0a (`2026-10-21_g9_t0/dwarf_tip_notu.md` §4-§5), Onuncu Adam İ3-İ5 (`2026-10-21_v2_1/onuncu_adam.md`).

## 1. Ortak zemin

- **Gerçek:** Debian 13 arm64 dbgsym DWARF'ı, `scripts/measurement/dwarf_tip.py` ile (dwz farkında; çözülen tip payı geliştirme setinde %100).
- **Birim:** Ghidra decompiler'ının parametreleri (HighFunction). T0b hizalamasıyla, depolama üzerinden bir DWARF `formal_parameter`'a eşlenenler.
- **Dil:** yalnız C birimleri. pzstd gibi C++ programları ve redis'teki C++ birimleri dışarıda. Birim dili DWARF'tan (`DW_AT_language`) okunur; araca eklenecek **[T0c]**.
- **Dışlananlar** (sayıları raporlanır, karar ölçüsüne girmez):
  - klonlar: sonek (`.isra`, `.constprop`, `.part`, `.cold`) VEYA `tekrar` VEYA `sira ≠ somut_sira`. `abstract_origin` tek başına ölçüt değildir; LTO'da her şeyi işaretler.
  - konumsuz ya da hizalanamayan parametreler (T0b'nin "eşleşmeyen" sınıfları);
  - değişken argümanlı fonksiyonların `...` kısmı;
  - değerle geçen yapılar (`yapi_degerle`).
- **Geliştirme / doğrulama:**
  - Kural ve sayısal alt sınırlar Debian 13 geliştirme setinde (8 program) belirlenir.
  - Kapı doğrulama setinde **tek okumayla** verilir (K1 G19, K2 G23).
  - Doğrulama setine bakarak kural ayarı yapılmaz (`dogrulama_seti_onkayit.md` §2 madde 2-4 ve §14).
  - Mac tarafı kapı gününde newlisp ve nagios dSYM'leriyle ayrıca okunur.
- **Ağırlık:** program başına hesaplanır, programlar arasında **makro ortalama** alınır (plan v2 §7). Geliştirme setinde `yapi*` nüfusu redis 4 799, tree 30; çift sayımı programlar arasında birleştirilmez.

## 2. K1: tip

### 2.1 "Aynı tip" (gerçek eşdeğerlik)

- **Kanonik tip:** typedef soyulur; `const`, `volatile` ve `restrict` atılır; işaretçi derinliği tutulur (araçta `kanonik`).
- **Yapı kimliği:**
  - Tanımı olan adlı yapı: (tür, ad, yerleşim imzası). Aynı adlı farklı yerleşimler ayrı tiptir (redis/hiredis `dict`: 56 ve 48 bayt).
  - Anonim yapı: yerleşim imzası. Varsa typedef adı da eklenir.
  - Yalnız bildirim (yerleşimsiz kök): (tür, ad, "bildirim"). Aynı ikilide o adın birden çok tanımı varsa ("çok tanımlı ad"), bu kökler karar ölçüsünden çıkar ve ayrı raporlanır.
- **Kalıtım ailesi:** X'in 0. ofsetteki üyesi `struct Y` ise X → Y bağı kurulur; bu bağların bağlı bileşeni bir ailedir. Aynı ailedeki tipler K1'de aynı sayılır. Yalnız tanımı olan yapılarda uygulanır.
- **Birlikler:** `yapi*` içindeki birlikler (geliştirme setinde tmux 2, zstd 26, redis 21) ayrı sınıftır **[seçim: karar ölçüsüne dahil mi]**.
- **Karar ölçüsünün dışında, ayrı raporlanan sınıflar:** `void *` (joker), `char *`, skalerler.

### 2.2 Ölçü

Kümeler Karadul'un tip sınıflarıdır (T3). Program başına, yalnız `yapi*` parametreleri üzerinden:
- **Çift kesinliği (karar ölçüsü):** aynı kümeye konan parametre çiftlerinden gerçekte aynı tipte olanların payı. Tek elemanlı kümelerin çifti yoktur; saflığı şişiremezler.
- **Çift duyarlılığı:** gerçekte aynı tipte olan çiftlerden aynı kümeye konanların payı.
- **Kapsam:** en az iki üyeli bir kümeye düşen `yapi*` parametrelerinin payı.
- **Ek (karar dışı):** B-cubed kesinlik ve duyarlılık. Büyük kümelerin karesel ağırlığını göstermek için; tekiller hariç.

### 2.3 Negatif kontrol

- Program içinde küme etiketleri karıştırılır: küme boyut dağılımı korunur, tohumlu, 1 000 kez.
- **Geçme ölçütü [seçim, öneri]:** gözlenen çift kesinliği, karıştırılmış dağılımın %99 yüzdeliğinin en az 0,30 puan üstünde.

### 2.4 Kapı

- Doğrulama setinde, makro ortalama: çift kesinliği ≥ %95.
- Kapsam ≥ **[T0c'de, geliştirme setindeki tabandan yazılacak alt sınır]**.
- Negatif kontrol geçer.
- **Tutmazsa** (plan v2.2 §5): tip izi ölçülen hâliyle raporlanır, ürün tip yazmaz (yalnız ad). Düzeltme geliştirme setinde yapılır; doğrulama bir sonraki kapı gününde yeniden okunur.

## 3. K2: yapı

### 3.1 Birim ve gerçek

- **Birim:** T5'te mühürlenen ölçüte göre "doğrulanmış" sayılan yerleşimler. Mühür, P/R hesaplanmadan önce commit'lenir.
- **Sınıfın gerçek tipi:** sınıfa hizalanan parametrelerin çoğunluk DWARF yapısı **[seçim: çoğunluk eşiği, öneri > %50]**. Çoğunluk yoksa yerleşim değerlendirilemez ve sayısı raporlanır.
- **Yaprak alanlar:** iç içe yapılar düzleştirilir. Diziler **[seçim]**: eleman düzeyinde ya da tek alan. Birlikler: üyelerden biriyle eşleşme yeter.

### 3.2 Ölçü

- **Kesinlik (karar ölçüsü):** kurtarılan alanlardan, gerçekte aynı ofsette aynı genişlikte ve aynı işaretçi/skaler sınıfında bir yaprağa denk gelenlerin payı. Program başına hesaplanır, makro ortalama alınır.
- **Şans tabanı:** her kurtarılan alan için, aynı hizalamadaki rastgele bir ofsetin bir yaprağa aynı genişlik ve sınıfla denk gelme olasılığı (analitik). Kesinlikle birlikte raporlanır.
- **Kontroller:**
  - yanlış yapı kimliği: aynı boyut sınıfından rastgele başka bir yapıya karşı puan;
  - yalnız ofset 0: yalnız 0. ofsetteki alanların payı.
- **Kapsam:** alan kapsamı (gerçek yapraklardan kurtarılanların payı) ve sizeof doğruluğu.

### 3.3 Kapı

- Doğrulama setinde, makro ortalama: alan kesinliği ≥ %95.
- Şans tabanı ve kontroller raporlanır **[seçim: şans tabanı üstü için alt sınır]**.
- **Tutmazsa:** geri yazma yalnız ad kipinde kalır; yapı izi raporlanır.

## 4. Kesinleşmeden önce

1. T0b: hangi parametreler hizalanıyor, eşleşmeyenlerin dağılımı.
2. T0c: çıplak Ghidra'nın adlı tip doğruluğu (taban) ve geliştirme setinde kapsam tabanı.
3. Araç: `DW_AT_language` ve yerleşim imzası çıktısı.
4. **[seçim]** işaretli maddeler için Codex danışmanlığı. Sonra bu belge "TASLAK" ibaresinden çıkarılıp commit'lenir; ancak ondan sonra doğrulama setine bakılır.
