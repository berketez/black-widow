# P-S3b ön kaydı — gnulib ön ad kanalı: sürümden ve platformdan bağımsız varlık kanıtı + kalan gnulib ad kusurları

Yazıldığı an: 2026-11-18 akşam, kod değişmeden ÖNCE (taban **cce2e8c**, yerel `main` ucu). Bu dosya kalem kodlarından önce
commit'lenir; sonradan değiştirilmez. Tutmayan madde `P-S3b.md`'ye "tutmadı" diye yazılır; kural sonradan gevşetilmez.
P-S3'teki süreç sapması yinelenmez: her kalemin kodu, aşağıdaki kabul ölçümü yapıldıktan SONRA commit'lenir.

Ölçüm kökü: `~/karadul_olcum/runs/onarim-2026-11-18/P-S3b/` (betikler ve çıktılar orada).

## Bu kayıttan önce görülenler
- P-S3 kaydı (`P-S3.md`): Homebrew coreutils 9.12 `gcat`'te varlık kanıtı 1 / 2 modül (yalnız version-etc); gcat'te
  getopt.c metinleri, version_etc_arn'ın "Written by %s, %s, and %s." dizgisi ve error.c'nin "Unknown system error"
  dizgisi var (P-S3'ün önerisi). **Bu yüzden gcat taze değil**: ayrı satırda raporlanır, kabul kararı taze ikililerle verilir.
- İşaret dağılımı (`isaret_tarama.py` → `isaret_tarama.json`; ürünün dizgi çıkarıcısıyla, taban kodu): geliştirme seti 119
  (coreutils 106, coreutils dışı 13) ve `/usr/bin`'in 640 Mach-O dosyası (ham baytlarda alt dizgi):

| Aday modül (kaynak) | coreutils (106) | coreutils dışı (13) | /usr/bin (640) |
|---|---|---|---|
| getopt, uzun seçenek iletileri `'%s%s'` (getopt.c) | 0 | 0 | 0 |
| getopt, kısa seçenek iletileri (getopt.c) | 0 | 0 | 0 |
| error ("Unknown system error", error.c) | 105 | 0 | 0 |
| version-etc ("Written by %s, %s, and %s." ve öbür 6 dizgi) | 104 | 0 | 0 |
| version-etc-fsf ("Copyright %s %d Free Software Foundation, Inc.") | 104 | 0 | 0 |
| openat-die | 3 | 0 | 0 |
| c-stack ("stack overflow", "program error") | 0 | **4** (redis ×2, tmux ×2) | **1** (sqlite3) |
| xalloc-die ("memory exhausted") | 105 | **1** (tree) | **8** |
| closeout ("write error") | 105 | **5** | **20** |
| progname / argmatch / closein (P-S3 işaretleri) | 105 / 25 / 5 | 0 | 0 |
| xstrtol-error (P-S3 işareti) | **ham 0**, kaçışı çözülmüş 8 | 0 | 0 |

- **Kaçış bulgusu:** Ghidra decompile çıktısında tek tırnağı `\'` diye kaçırıyor (`"Try \'%s --help\' …"`). P-S3'ün
  xstrtol-error işaretleri tek tırnak içerdiği için üründe hiç eşleşmiyordu (ham 0 / çözülmüş 8).
- getopt ve error modüllerinin iletileri glibc'nin kendi `getopt.c` / `error.c`'siyle aynı metin. Glibc'li Linux'ta dinamik
  bağlı programda bu metinler `libc.so`'da kalır (geliştirme setinde 0); macOS'ta gnulib bunları ikiliye derler (P-S3: gcat).
  Statik glibc'li gnulib'siz bir ikili ikisini birden taşıyabilir (geliştirme setinde yok; ölçülmedi).
- Kabul seti yalnız `nm` ile (GT tarafı: ikilide gnulib fonksiyon simgesi var mı) seçildi; dizgilerine bakılmadı:
  gnulib'li taze Mach-O: `gettext`, `envsubst` (gettext 1.0), `idn2` (libidn2 2.3.8), `gsort`, `gmktemp` (coreutils 9.12;
  gcat'le aynı yapı, gcat dışındaki programlar); gnulib'siz taze Mach-O: `xz` 5.8.4. Hepsi `/usr/bin/strip`'li kopya,
  GT özgün kopyanın `nm`'inden (`macho_f1.py gt`). Taban ürün koşuları (B, cce2e8c'nin dondurulmuş kopyası) bu kayıt
  yazılırken arka planda koşuyor; çıktılarına bu kayıttan önce bakılmadı.
- coreutils `sort`'ta `full_write` (P-S3 yeniden oynatması): `FUN_001079e0`, GT'ye göre yanlış (P-S3: `strlen`, `write`,
  `_exit` ve bir iç fonksiyon çağırıyor).

## Kalem 1 — kural (dondurulmuş)
**A. Yeni modüller** (`GNULIB_PRESENCE_MARKERS`'a; her işaret `vendor/gnulib-ref/lib/<kaynak>`'ta birebir, testle):

| Modül | Kaynak | Tür | İşaret (herhangi biri) | glibc ile ortak |
|---|---|---|---|---|
| getopt | getopt.c | dizgi | `%s: option '%s%s' doesn't allow an argument`, `%s: unrecognized option '%s%s'`, `%s: option '%s%s' requires an argument`, `%s: option '%s%s' is ambiguous` | evet |
| error | error.c | dizgi | `Unknown system error` | evet |

- version-etc işaretine version_etc_arn'ın `Written by %s, %s, and %s.` dizgisi eklenir (aynı modül; modül sayısı değişmez).
- Genel dizgiler (c-stack, xalloc-die, closeout) EKLENMEZ: gnulib'siz programlarda geçiyor (tablo).

**B. Kaçış çözümü:** dizgi işaretleri, değişmezlerin Ghidra kaçışları (`\'` → `'`, `\"` → `"`) çözülmüş metninde aranır.

**C. glibc koşulu:** yeterlilik = en az `MIN_PRESENCE_MODULES` (2, değişmez) bağımsız modül **ve** bunlardan en az biri glibc ile
ortak OLMAYAN (gnulib'e özgü) modül. Yalnız getopt + error = yetersiz (statik glibc'li program gnulib'siz olabilir).

**D.** Platform (ELF / Mach-O) koşul değildir; eşik ve P-S3'ün öbür kuralları (LTO yerleşimi, tekillik) aynı.

## Ölçüm düzeni
1. **Ghidra'sız yeniden oynatma** (P-S3'ün `gnulib_yeniden.py`'sinin uyarlaması; taban `taban_kod/` = cce2e8c ↔ yeni kod):
   geliştirme seti 119 (`urun-yeni2-f30ac9a`), korpuslar (Debian 9.4 ve Ubuntu 9.4: `aday-f893d72` + `~/karadul_olcum/corpus`;
   Ubuntu 9.4 od / pr: `on-ad-onarimi-2026-11-11/ek_kosu`), Mach-O kabul seti (B koşularının `static/`'i) ve gcat
   (P-S3 A koşusunun `static/`'i). Hüküm: ELF `ks1_olc.capa_degerlendir`; Mach-O `macho_f1` GT'si + aynı hüküm.
2. **/usr/bin** (640 Mach-O): ürünün `presence_evidence`'ı, dosyanın yazdırılabilir ASCII dizileri (≥ 4 karakter) üstünde.
3. **Ürün koşusu** (en çok 10 ikili; burada 6): B (taban) ve A (bütün kalemlerden sonraki kod) — gettext, envsubst, idn2,
   gsort, gmktemp, xz. `PYTHONHASHSEED=0`, sıralı (paralel 1), koşu başına `KARADUL_CACHE_DIR`.

## Kalem 1 — beklentiler
| # | Ölçü | Önce | Beklenti | Tutmadı sayılır |
|---|---|---|---|---|
| H1 | Yeniden oynatma, geliştirme seti coreutils dışı 13: gnulib yazımı | 0 | **0**; 13'ünde yetersiz | > 0 |
| H2 | Yeniden oynatma, geliştirme seti coreutils: doğru / yanlış | 620 / 1 | doğru ≥ 620, yanlış ≤ 1 | doğru < 620 ya da yanlış > 1 |
| H3 | /usr/bin 640 Mach-O: varlık kanıtı yeterli | — | **0** | > 0 (vuran ikili GNU gnulib programı değilse) |
| H4 | Taze gnulib'li Mach-O (5): varlık kanıtı yeterli | B'de ölçülecek | **≥ 4 / 5**; gcat de yeterli (ayrı satır) | < 4 / 5 |
| H5 | Taze gnulib'li Mach-O (5), yeniden oynatma, GT: kanalın doğru adı / yanlış oranı | B'de ölçülecek | doğru **> 0**, yanlış / (doğru + yanlış) **≤ %30** | doğru 0 ya da oran > %30 |
| H6 | xz (gnulib'siz Mach-O, taze): gnulib adı | B'de ölçülecek | **0**, yetersiz | > 0 |
| H7 | Korpuslar (Debian 9.4, Ubuntu 9.4, od / pr): doğru / yanlış | P-S3 sonrası | aynı | değişir |

- %30 sınırının gerekçesi: kanalın üründeki ölçülmüş güven etiketi 0,706 (`naming_labels.MEASURED_PRE_NAME_PRECISION`);
  yanlış oranı %29,4'ü aşan bir yerde etiket analisti yanıltır.
- Karar: H1, H2, H3, H6 ya da H7 tutmazsa kalem 1 commit'lenmez. H4 / H5 tutmazsa "tutmadı" yazılır, kural değiştirilmez;
  gnulib'siz programlarda ve geliştirme setinde doğru ad kaybı / yeni yanlış yoksa commit'lenir.

## Kalem 3 — `full_write` çağrı şeklinde `_exit` dışlaması
- Kural: `GnulibCallShape`'e `excluded_callees` (hiçbiri çağrılmamalı); `full_write` için `("_exit",)`. Gerekçe: gnulib
  `full-write.c` / `safe-write.c` `_exit` çağırmaz (testle: kaynakta `_exit` geçmez). Öbür çağrı şekilleri değişmez.
- H8: geliştirme seti coreutils yanlış 1 → **0**, doğru 620 aynı. Tutmadı: yanlış > 0 ya da doğru azalır.
- H9: korpuslarda ve Mach-O kabul setinde `full_write` doğru adı kaybolmaz; değişen öbür ad 0.

## Kalem 2 — `usage` gelenek kanalı
- Önce ayrı ölçüm satırı: `usage` önerilerinin hepsi (kanal, karar, GT hükmü), gruba göre (geliştirme gnulib'li / gnulib'siz,
  korpus, Mach-O kabul).
- Aday kural (gnulib varlık kanıtı OLMAYAN programlar için; gnulib'li programlarda kanal bugünkü gibi): `usage` adı ancak iki
  bağımsız kanıt birlikteyse yazılır: (i) "Usage: %s" dizgi parmak izi ikilide tek fonksiyonda (bugünkü tekillik); (ii) bu
  fonksiyonu, ürünün entry'den kurtardığı `main` doğrudan çağırıyor (çağrı çizgesi). Biri yoksa aday kayıtta kalır.
  Kural `stages.py`'nin `_offer`'ında → `yamalar/P-S3b__stages.py.patch` (P-S4 uygular; burada dalda uygulanıp ölçülür,
  commit'lenmez).
- H10: geliştirme seti gnulib'siz 13'te yazılan `usage`: yanlış **0**; doğru ≥ 1 (zstd `usage`, P-S3'te kayıp).
  Tutmadı: yanlış > 0 (yama bırakılmaz) ya da doğru 0 (yama bırakılmaz, neden yazılır).
- Not: örneklem küçük (geliştirme setinde gnulib'siz `usage` ateşlemesi 1); kesinlik iddiası yapılmaz, yalnız sayı yazılır.

## Kalem 4 — LTO'suz yapıda iç adlar (yalnız ölçüm; kural bu pakette değil)
- `lto_yerlesimi` ile tutulan adayların GT adı sayılır (geliştirme seti 216: version_etc 104, hard_locale 104, full_write 8;
  korpuslar; Mach-O kabul): katı (`capa_degerlendir`) ve gevşek (`function_f1.match_lenient`) ölçütle, iç ad adayları
  `version_etc_arn` (version-etc.c), `setlocale_null_r` (setlocale_null.c, 2023 pini), `safe_write` (safe-write.c).
- H11: bir iç adın GT'de karşılığı ≥ %90 ise (katı ya da gevşek, hangisi olduğu yazılır) kural önerisi + yama; değilse neden +
  aday kaydı. Sürüme bağlı adlar (`setlocale_null_r` ↔ `setlocale_null_r_unlocked`) ayrı satırda.

## Kalem 5 — aday kaydının rapora görünmesi
- `static/gnulib_candidates.json` varsa raporda "gnulib adayları (ad yazılmadı)" bölümü: yazılmayan aday sayısı, nedenlere
  göre kırılım ve her adayın kanıt satırı; varlık kanıtı satırı. Dosya yoksa bölüm "veri yok" der (0 yazmaz).
- H12: A ürün koşusunda 6/6 raporda bölüm var ve sayı `gnulib_candidates.json`'daki `withheld` sayısına eşit.

## Aykırı öncüller (sınanacak)
1. "getopt / error iletileri gnulib'siz Mach-O'da da bulunur (BSD / Apple kodu aynı metni taşır)" → H3, H6.
2. "Taze Mach-O gnulib programları (gettext, libidn2) coreutils'le aynı modülleri kullanmaz; kanıt yine yetmez" → H4.
3. "Varlık kanıtı geri gelince kanal Mach-O'da yanlış ad yazar (LTO'suz yerleşim, sürüm farkı); doğru ad yanlışları geçmez" → H5.
