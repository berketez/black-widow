# KARŞI hattı — itirazlar ve doğrulananlar (2026-11-19)

- Görev: `HAT_KARSI.md`. Denetlenen: KİMLİK, ÖZ KOD, ÖLÇÜ, ÜST VERİ (`BULGULAR.md`, `PLAN.md`, `DEFTER.md`, `BERKE.md`),
  ÖLÇEK (`PLAN.md`, `BERKE.md`, defter kapanışı 13:08), yayın kapısı §4–§5, onarımın kalanı (`OKU.md`, `P12d`, `P24`,
  `P10b`, `P08b`, `P03b`, `P23`, `P18`). **HIZ: içerik denetlenmedi** (`hiz/PLAN.md` 13:17'de geldi; bitiş işareti
  yok; yalnız dosya taraması `CAKISMA.md`'ye girdi; §6'da not).
- Bitiş çizgisi ana oturumun 13:0x düzeltmesiyle okundu (KARARLAR A-7): erken yayın yok; kullanıcı tek kişi (Berke);
  hedef onun önüne gelen gerçek uygulamalar (Go / Swift / C++ / C karışık, 50 MB – birkaç GB).
- Betikler `scripts/arge/karsi/` (aşağıda `B/`), çıktılar `~/karadul_olcum/runs/arge-2026-11-19/karsi/` (`$V`).
  Komutlar depo kökünden `PYTHONDONTWRITEBYTECODE=1 python …`. Hat betikleri içe aktarılmadı; Wilson aralığı
  `B/ortak.py` (kendi gerçeklemem). Ghidra koşulmadı; kilitli setlere ve kör nüfusa bakılmadı.
- Her itiraz: **İddia** (hat ne diyor), **Kanıt** (betik + komut + sayı), **Düzeltme** (hangi belge / paket).

## 0. Kısa hüküm

1. Dört hattın sayıları büyük ölçüde **doğru**: yeniden türettiğim 28 iddia satırının 27'si tuttu ya da tanım
   farkıyla açıklandı; biri (K1'in sınama düzeyi) yön olarak tuttu, düzeyi gruplamaya duyarlı (§5; tablolar
   `DEFTER.md` §2). Sınama öncesi kural değiştirme izi bulamadım (§4).
2. Çatlaklar sayılarda değil, **okumada ve sırada**: (a) geliştirme seti hedefi temsil etmiyor ve planların ağırlığı
   yanlış nüfusta; (b) bitiş çizgisinin tek çaresi olan paket (ÖL-10) planın en az belirlenmiş paketi; (c) karar
   eşiği iki ayrı sayı ve iki ayrı birimle yazılı; (d) KİMLİK'in bir güven satırı çift sayımla eşiği geçiyor; (e) ÖLÇÜ
   planı KARARLAR A-1 ile çelişiyor; (f) üç hat aynı ikili okuyucuyu üç kez yazacak; (g) `config.py`'yi 17,
   `ghidra/headless.py`'yi 12 paket değiştirecek.

## 1. İtirazlar (önem sırasıyla)

### İ-1. Geliştirme seti hedefi temsil etmiyor; planların ağırlığı yanlış nüfusta (yön)

- **İddia:** `YON.md` §2 kapsamı artıracak hatları KİMLİK, ÖZ KOD, ÖLÇÜ diye seçti; ÜST VERİ "nüfusu yok" diye
  ertelenmişti (§3–§4); ÖLÇEK ve HIZ sonradan eklendi. HIZ dışındaki 63 paketin 29'u bu üç hattın (KİMLİK 11,
  ÖZ KOD 9, ÖLÇÜ 9; `python B/plan_tara.py`).
- **Kanıt:**
  - `python B/set_profili.py` (`$V/set_profili.txt`): 119 ikili, toplam 66 983 fonksiyon, ikili başına ortanca **312**,
    en büyük 5 697; bütün setin fonksiyon gövdesi toplamı **10,4 MiB**; nüfusun 18 229'u Debian ELF, 3 142'si Mac (2 ikili).
    Hedef tarafı (hatların kendi sayıları): Ollama dilimi 13 559 fonksiyon / 5,5 MB kod; `mlir-transform-opt`
    163 141 fonksiyon / 54 MiB kod; iTerm2 109 608 fonksiyon. Tek bir hedef ikili bütün setten büyük.
  - `python B/turet_taban.py` (`$V/turet_taban.txt`): nüfus içi doğru ad coreutils 847 + tmux 341; **öbür altı programda
    24 / 4 258** (redis-tools 0 / 1 458, htop 0 / 819, sqlite3 1 / 389, zstd 4 / 919, tree 1 / 110, openssl 18 / 563).
    1 681 doğru adın 733'ü 10 tekil ad (gnulib), 458'i 30 tekil ad (ELF önyükü), 110'u `main`.
  - ÜST VERİ `BULGULAR.md` §7 (bağımsız doğruladığım kısmı §5.4): Go taşıyan hedeflerde fonksiyonların %83–%100'ünün
    adı ikilide yazılı, ürün 0–2'sini okuyor.
  - Gösteri koşusu bitti (`python B/gosteri_oku.py` → `$V/gosteri_oku.txt`): 11:10:50 → 13:20:12, **7 761,6 sn
    (2 sa 9 dk)**, çıkış 3 "kısmi" (hata bildiren aşama `static`: "Go analizcisi … şişman dosyayı açmıyor"); 13 160
    fonksiyon; ad haritasında **17 fonksiyon adı** (`string_context/oz_ad` 9, `on_ad:faz1` 8; 17'si de "doğrulanmadı"
    etiketli). Aynı dilimin `pclntab`'ında 10 601 giriş adıyla yazılı (§5.4). Günlükte ayrıca "Ghidra'da bulunmayan
    çözümleyici adı (kapatılamadı): ['Objective-C Message']" ve "Pipeline iteration 1 took 1311s (> 600s timeout),
    skipping remaining 2 iteration(s)". Yani hedef türünden ilk gerçek koşuda ürün 13 160 fonksiyonun 17'sine ad verdi.
- **Okuma:** hedef nüfusta (karışık dilli, 10⁴–10⁶ fonksiyon) ad kazancını belirleyen sıra: (1) koşunun bitmesi (ÖLÇEK,
  HIZ), (2) yazılı adın okunması (ÜST VERİ), (3) gömülü açık kaynak kitaplığın tanınması (KİMLİK'in ölçülmemiş kolu,
  İ-6), (4) C'ye özgü kurallar (ÖZ KOD). Planların iş yükü bu sıranın tersine yakın.
- **Düzeltme:**
  1. `YON.md` §2'ye bir satır: "ölçünün ana nüfusu hedef setidir"; ÜST VERİ P-ÜV8'in ölçüm seti (sembollü ikiliden GT;
     Go / ObjC / Swift / C++) 119'un yanına **ikinci zorunlu ölçüm** olarak yazılsın; her ad paketi iki sette sayı versin.
  2. Dalga sırası `CAKISMA.md` §3'teki gibi: ÖLÇEK ölçümü + ÖL-1 / ÖL-2 + P-ÜV0 / 1 / 2 / 5 önce; KİMLİK ve ÖZ KOD'un
     ürünleştirme paketleri (PK-2, 3, 4, 7, 8, 9, 10; ÖK-3, 4b, 6) genelleme ölçümlerinin (PK-6, PK-11, ÖK-5) hükmüne bağlansın.
  3. ÖK-5'e bir sayım eklensin: K1 / G1 / R1'in **hedef setindeki** erişimi (Ollama'nın Go dışı 1 676 fonksiyonu, btop,
     llama-server): kayıt çifti olan fonksiyon payı. Bugün yalnız C programlarında ölçülü (İ-7).

### İ-2. Bitiş çizgisinin tek çaresi (ÖL-10 tembel derinlik) planın en az belirlenmiş paketi

- **İddia:** ÖLÇEK `BERKE.md` madde 9: 100 MB üstü tek dosya için "tek gerçek çözüm" tembel derinlik (ÖL-10) + önbellek
  (ÖL-9); ikisi de `PLAN.md` §4 "yayından sonra" başlığında.
- **Kanıt:** `olcek/PLAN.md` satır 346–352: ÖL-10 altı adım, seçim kuralı "ör. ilk 5 000 fonksiyon; kural ön kayıtlı"
  (kural yazılı değil), dosya listesi dört ortak dosya (`headless.py`, `macho.py`, `stages.py`, `config.py`), mutasyon
  tanımı yok. Aynı planın tahmini (ÖLÇ-1 ön kaydı): T100'de köprü 14,5–39,4 saat, T300'de 77,9–447,5 saat; ÖLÇ-1 ön
  kaydı üç hedefin 8 saatte **bitmeyeceğini** yazıyor. "Yayından önce / sonra" ayrımı A-7 ile geçersiz.
  Ayrıca hiçbir ad planı, kanalının decompile olmadan çalışıp çalışmadığını yazmıyor: ÜST VERİ okuyucuları Ghidra'sız;
  KİMLİK eşleyicisi yalnız `static/` okuyor (`BULGULAR.md` §3.6); `oz_ad` ve K1'in çağrı yeri kolu decompile edilmiş C istiyor.
- **Düzeltme:**
  1. ÖL-10 ayrı bir tasarım turu alsın (Opus paketi olarak bu hâliyle gönderilmesin): seçim kuralı (sayı ve sıra),
     kısmi analizde ad kanallarının sözleşmesi, "decompile edilmedi" sayacı, isteğe bağlı decompile komutu.
  2. Dört ad planına birer satır: "kanal tembel kipte çalışır mı (evet / hayır / kısmen)". PK-4, P-ÜV6 ve ÖK-4b'nin
     kabul ölçümüne tembel kip kolu eklensin.
  3. ÖLÇ-1 duvarları kısalsın (T100 / T300 / PAKET 8 sa yerine 2 sa): ön kayıt sonucu zaten "bitmez" diyor; 27 saatlik
     tek Ghidra kuyruğu (ÖLÇ-2 ile 54) öbür bütün ölçümleri bekletir (İ-10).

### İ-3. Karar eşiği iki ayrı sayı, ölçülmemiş bir parametre ve yanlış birimle yazılı

- **İddia:** KARARLAR A-2: "Wilson alt sınırı ≥ 0,909 olan kanal ad yazar". KİMLİK ve ÜST VERİ planları 0,909'u sabit
  alıyor (`grep -c "0,909"`: `kimlik/PLAN.md` 16 satır, `ustveri/PLAN.md` 3 satır; PK-1 `AD_ESIGI`).
- **Kanıt:**
  - ÖLÇÜ'nün kuralı `p > 1 − e / L` (`olcu/BULGULAR.md` §5 madde 4; `scripts/arge/olcu/karar.py:49`). L = 10, e = 1 → **0,900**.
    0,909 = L / (L + 1) başka bir kayıp modelinin eşiği. e (kanıt satırının değeri) ölçülmedi; e = 0,5 → 0,95.
  - Aradaki bantta kanal var: tekil dizgi çapası yön başına 0,904 / 0,901 (İ-4); `ks1:func_aktarma` 0,896
    (`$V/turet_taban.txt`).
  - Birim: A-2 örnek düzeyi sayılarla uygulanıyor. `python B/turet_taban.py`: tekil düzeyde gnulib 10 / 10 (alt 0,722),
    ELF önyükü 30 / 30 (0,886), `main` 6 / 6 (0,610): **hiçbir ön ad kanalı** eşiği geçmiyor (ÖLÇÜ §7 ile aynı sayılar).
    Kararın hangi birimle verileceği hiçbir belgede yazılı değil.
  - Sabit üç ayrı yerde tanımlanacak: PK-1 `kimlik/yontem_kapisi.py` (`AD_ESIGI`), P-ÜV6 (`MEASURED_METADATA_PRECISION`
    okuması), ÖK-4b (`naming_labels`). CLAUDE.md §11 (tek kaynak) ihlali adayı.
- **Düzeltme:** `KARARLAR.md` A-2'ye üç şey yazılsın: formül (`1 − e / L` ya da `L / (L + 1)`; biri), e'nin değeri, sayım
  birimi (öneri: bağımsız birim = program; kanal en az 3 programda ölçülmediyse "ölçülmedi" sayılır). Sabit tek yerde
  (`karadul/core/naming_labels.py`) tanımlansın; PK-1, P-ÜV6, ÖK-4b içe aktarsın (`CAKISMA.md` §2 "ön paket").

### İ-4. KİMLİK: iki yön havuzu aynı çifti iki kez sayıyor; bir güven satırı eşiği yalnız böyle geçiyor

- **İddia:** `kimlik/BULGULAR.md` §3 tabloları "iki yön havuzlu"; PK-4 adım 4 `naming_labels` satırı `basvuru:dizgi`
  (737, 791, 0,912) ≥ 0,909 → ad yazar.
- **Kanıt:** hattın kendi `yayilim_v2_hepsi.json` `yonler` alanından (`python B/yon_basina.py` → `$V/yon_basina.txt`): debian/tmux → mac/tmux tekil
  dizgi çapası 362 / 388 = 0,933 [**0,904**–0,954]; mac → debian 375 / 403 [**0,901**–0,951]. Eşleme karşılıklı en iyi
  olduğu için iki yön aynı çiftlerdir; havuz n'yi ikiye katlıyor. Bağımsız gerçeklemem (`python B/turet_kimlik.py`):
  363 / 26 ve 375 / 29. Ürün tek yönde çalışır (hedef → başvuru). Yayılım aşaması yön başına 0,928 (geçiyor);
  `derleyici` çifti yön başına 1 919 / 1 936 [0,986–0,995] (hüküm değişmiyor).
- **Düzeltme:** PK-3 `hukum` / raporu ve PK-4 adım 4'teki dört satır **yön başına** (hedef → başvuru) sayılsın;
  `basvuru:dizgi` satırı (362, 388, 0,904) olur ve İ-3'teki eşik kararına göre ad ya da kanıt satırıdır.
  `BULGULAR.md` §3.1 ve §3.6 tablolarına yön başına aralık sütunu.

### İ-5. ÖLÇÜ planı KARARLAR A-1 ile çelişiyor; model hakem paketi kendi ölçümüne göre bilgi taşımıyor

- **İddia:** A-1: P-Ö3, P-Ö4, P-Ö9 "model hakem paketi" olarak uygulanır (iki bağımsız hakem, mümkünse ayrı model ailesi).
- **Kanıt:** `olcu/PLAN.md` güncellenmemiş: satır 23 "İnsan etiketini model üretmez" (değişmez kural); P-Ö3 başlığı
  "İnsan etiket paketi İ-1", adımları insan değerlendirici dizinleri ve süre pilotu; P-Ö4 hipotez 2 "insan–vekil kappa
  ≥ 0,80"; `olcu/BERKE.md` hâlâ iki insan değerlendirici istiyor. "Planı olduğu gibi uygula" denen ajan çelişen iki
  talimat alır. Hattın kendi ölçümü (`BULGULAR.md` §2.1): iki model hakemin birbirini öngörmesi 0,96–0,99, kappa 0,88;
  KARARLAR "dürüst sınır" bölümü bu uyumun doğruluk göstermediğini yazıyor. T2 tabakasının 182 öğesi zaten model
  etiketli; ayrı model ailesi yok (A-5: Astra kotası bitti).
- **Düzeltme:** `olcu/PLAN.md` P-Ö3 / P-Ö4 / P-Ö9 yeniden yazılmadan gönderilmesin. Öneri: üçü tek küçük pakete insin —
  yalnız T3 (ikiz: tanım gereği yanlış) ve T4 (biçim: tanım gereği doğru) tabakaları hakemin **denetim öğesi** olarak
  kalsın; T1 / T2'de model hükmü ikincil satır. P-Ö4'ün "insan–vekil" hipotezi silinsin (ölçülemez). `BERKE.md` madde
  "Senden beklenen kararlar" güncellensin.

### İ-6. KİMLİK: "taze, bağımsız sınama" program düzeyinde bağımsız değil; ölçülen senaryo değeri en düşük olan

- **İddia:** `BULGULAR.md` §0 madde 1, §3.6: aynı sürüm, GCC ↔ clang, "ön kayıtlı, taze veri" 0,990 [0,987–0,993],
  kapsam %80,1; v2 için "ilk bağımsız sınama; ikinci bakış kaydı bu çiftte geçerli değil" (G6).
- **Kanıt:**
  - Çiftler (`scripts/arge/kimlik/ciftler.py`): `derleyici` = macgcc/tmux ↔ **mac/tmux**; mac/tmux 10:46'da sayılan
    `sinama_tmux` çiftinin başvurusu (`stat`: `yayilim_sinama_tmux.json` 10:46:01, `hata_dok_kural.json` 10:51:32,
    `yayilim_gcc.json` 12:30:25). `-O3` / `-O0` çiftleri tmux'un başka derlemeleri; `derleyici_htop` ayar programı.
    Üçüncü program yok. v2'nin kanıtı (tablo yuvası) kaynak düzeyinde bir yapı: aynı programın her derlemesinde aynı.
  - G1 eşiği (≥ 0,95) yazılmadan önce aynı çiftin tavan içi kesinliği biliniyordu: 2 276 / 2 310 = 0,985 (§3.3).
  - Ölçülen senaryo "kaynağı ve sürümü elde, bütün program ↔ bütün program". Kapalı bir ikiliye gömülü açık kaynak
    kitaplık (hedefte değeri olan senaryo) için hattın tek ölçümü: coreutils ↔ Homebrew `gnulib` sınıfı 129 / 20 = 0,866
    [0,802–0,911] (§3.4; sürüm farkı karışık) — eşik altı. PK-11 (gömülü kitaplık) ve PK-6 (başka program / mimari)
    sıralamada PK-2 → PK-3'ten sonra; PK-4'ün açılma koşulu PK-6'ya bağlı ama PK-2 / 3 / 4 / 7'nin yazılması bağlı değil.
  - Hattın §9 "Sınırlar" bölümü tek program sınırını yazıyor; itiraz sayıya değil sıraya ve "bağımsız" sözcüğüne.
- **Düzeltme:**
  1. `BULGULAR.md` §3.5 / §3.6: "bağımsız sınama" → "aynı programın görülmemiş derlemesi; program düzeyinde bağımsız değil".
  2. Sıra: PK-1 hemen (ölçülmüş kusur onarımı; bağımsız). PK-6 ve PK-11, ÖZ KOD'un ÖK-5'i gibi **araştırma betikleriyle**
     (`scripts/arge/kimlik/`) öne alınsın; PK-2 / 3 / 4 / 7 / 8 / 9 / 10 o hükme bağlansın (durma ölçütü (a) zaten bunu söylüyor).
  3. PK-11'e C++ kolu: hedef uygulamaların Go dışı kodu C++ (ÜST VERİ §7); eşleyici yalnız C'de ölçüldü.
  4. PK-6'ya ölçek satırı: eşleyicinin 10⁵ fonksiyonlu çiftte süresi ve belleği (bugün 2,5 bin fonksiyonda 1,0–2,5 sn).

### İ-7. ÖZ KOD K1: 843 doğru adın 688'i tmux'un iki derlemesi; iki programda kuruldu, üçünde sınandı

- **İddia:** `BULGULAR.md` §0: K1 kâhin çapayla keşif 740 / 754 (%98,1), sınama 103 / 126 (%81,7); "843 doğru ad, hepsi
  bugün adsız".
- **Kanıt:** hattın `ek_kurali_kesif.txt` dökümü: debian/tmux 316 + mac/tmux 372 + openssl 52 = 740; tmux'un iki
  derlemesi aynı tabloları iki kez sayıyor (örnek düzeyi). Sınama: redis-tools 65 / 71, htop 17 / 26 ve 13 / 17
  (aynı program iki platform), sqlite3 8 / 12 → üç program; ikisinde oran %65–%77.
  Bağımsız gerçeklemem (`python B/turet_ozkod.py`; tablo = sabit adımlı yuva koşusu, kâhin çapa): keşif 475 / 484 = %98,1
  (hepsi tmux), sınama 140 / 155 = %90,3 [%84,6–%94,0]. Yani **oran doğrulandı**; sınama düzeyi gruplama biçimine
  duyarlı (%81,7 ↔ %90,3; ben htop'un sınıf nesnelerini gruplamıyorum).
  Ürünün bugünkü çapasıyla 95 ad, tek tablo (Mac tmux) — hat bunu açıkça yazıyor; kâhin sayı ürün sayısı gibi sunulmamış.
- **Düzeltme:** `ozkod/BULGULAR.md` §2.3'e program düzeyi satır (tmux bir kez; sınamada program başına oran ve makro).
  ÖK-5 ön kaydına: hüküm program düzeyinde makro kesinlikle verilir; ÖK-4b'nin açılma koşulu en az 3 **yeni** programda
  ölçüm. K1'in erişimi hedef setinde sayılsın (İ-1 düzeltme 3).

### İ-8. KİMLİK A1: "nüfusun %82,5'inin kodu set içinde başka yerde" setin kuruluşunun ürünü

- **İddia:** `kimlik/BULGULAR.md` §7 "Okuma"; `YON.md` §1.4'ün sorusuna cevap olarak okunabilir.
- **Kanıt:** `python B/turet_kimlik.py`: örnek düzeyi sayılar doğru (kopya 13 472 = coreutils 12 107 + redis 1 365; öbür
  platform 4 171). Tekil (program, GT adı) düzeyinde (7 172 tekil): set içi kopya %22,8 (+ yalnız ad %4,7), öbür
  platform %31,8, **başvurusuz %40,7**. coreutils'siz örnek düzeyi (n 8 654): kopya %19,6, öbür platform %48,2
  (tmux ve htop bilerek iki platformda), başvurusuz %28,3. Hattın "Sınır" paragrafı coreutils etkisini yazıyor; tekil
  satırı ve "öbür platform" payının set seçiminden geldiğini yazmıyor.
- **Düzeltme:** §7 tablosuna tekil ve coreutils'siz satırlar; "Okuma" cümlesi "geliştirme setinde" kaydıyla. A1
  bütçesinin hedef nüfustaki karşılığı ölçülmedi diye yazılsın (PK-11'in işi).

### İ-9. Üç hat aynı ikili okuyucuyu üç kez yazacak

- **Kanıt:** P-ÜV0 `karadul/analyzers/ustveri/goruntu.py` (zincirli düzeltme, ELF yeniden konumlama, gösterici çözme);
  ÖK-4a `karadul/reconstruction/tarif/veri_sozcukleri.py` (N4 betiğinden `elf_oku`, `macho_oku`); PK-2
  `karadul/reconstruction/kimlik/olgu.py` (`isaretci_yuvalari`, `lief` ile). `grep -n "P-ÜV0\|goruntu.py" ozkod/PLAN.md
  kimlik/PLAN.md` → 0 satır; `grep -n "ÖK-4a\|veri_sozcukleri\|PK-2" ustveri/PLAN.md` → 0 satır. Yalnız PK-2 "önce ÖK-4a'yı
  ara" diyor. OLGU'nun `olgu_ikili.py`'si dördüncü kopya (araştırma betiği).
- **Düzeltme:** P-ÜV0 ilk dalgada tek başına; ÖK-4a `veri_sozcukleri.py`'yi `Goruntu.gosterici` üstüne yazsın; PK-2
  yuva listesini oradan alsın (`lief` bağımlılığı düşer). `ozkod/PLAN.md` ÖK-4a ve `kimlik/PLAN.md` PK-2 adım 2'ye bu satır.

### İ-10. Ortak dosyalar ve tek Ghidra kuyruğu gerçek darboğaz; planlar bunu hat içinde çözüyor, hatlar arasında değil

- **Kanıt:** `python B/cakisma_tablo.py` (`$V/cakisma_tablo.md`): `karadul/config.py`'yi 17 paket anıyor (HIZ HZ-5
  dahil; + 5 onarım paketi yama bırakıyor); `ghidra/headless.py` 12 paket (ÖLÇEK 5, HIZ 6, KİMLİK PK-8); `c_namer.py`
  6 paketlik zincir (P12d → ÖK-1 → ÖK-2 → ÖK-3 → ÖK-6 → P-ÜV6); `stages.py` 5; `naming_labels.py` 4. Her plan kendi içinde sıra veriyor, hatlar arası sırayı "ana oturum
  kurar" diye bırakıyor (`ustveri/PLAN.md` satır 48, `olcek/PLAN.md` §1). Ghidra: "aynı anda en çok 1 koşu" her planda;
  ÖLÇ-1 tek başına 27 saat duvar istiyor ve "makine boşken" şartı var; ad paketlerinin çoğu 119'luk birleşik ölçüm
  (taban koşusu 70 dk) ya da çift koşu istiyor.
- **Düzeltme:** `CAKISMA.md` §2–§3: (1) **bayrak ön paketi** — bütün planların `config.py` alanları tek pakette, kapalı
  öntanımla eklenir; 17 yazma 1'e iner. (2) Ghidra kuyruğu tek listede, ana oturumda; kısa ölçümler önce. (3) hatlar
  arası sıra o belgedeki dalga tablosu.

### İ-11. ÜST VERİ: doğrulayıcı iki Go ikilisi ve ikisi de Go ≤ 1.24; "kesin ad" payının çoğu kitaplık adı

- **İddia:** `BULGULAR.md` §0: Go `pclntab` adı 125 125 / 125 125; Ollama'da üst veriden kesin %83,0.
- **Kanıt:** bağımsız okuyucum (`python B/go_bagimsiz.py`, `$V/go_bagimsiz.txt`) iki sembollü ikilide aynı sonucu verdi
  (§5.4): iddia **doğru**. Sınırlar hattın kendi metninde var ama planın kabulünde kayboluyor: hedef 11 dilimin 9'u
  Go ≥ 1.26 (`textStart` = 0; doğruladım), bu sürümlerde ad ↔ adres bire bir doğrulama yok; P-ÜV1 kabul ölçütü H1
  "araştırma betiğinin çıktısıyla aynı" (döngüsel: okuyucu okuyucuyla karşılaştırılıyor). Ollama'nın 10 751 "kesin"
  adının 1 257 Go + 151 ObjC'si programın kendi kodu: **1 408 / 12 952 = %10,9** (hattın §7 ikinci tablosundan [hesap]).
  Ghidra'nın o adreslerde fonksiyon açıp açmadığı ve ürün hattının adı uygulayıp uygulayamadığı ölçülmedi (§8 madde 5).
- **Düzeltme:** P-ÜV1 kabulüne Go ≥ 1.26 için sembolden bağımsız ikinci denetim şart koşulsun (K6 / K7 / K8 zaten var:
  "9 dilimde K6 ve K7 ihlali 0, K8 çapaları beklenen adda" kabul satırı olarak yazılsın) ve `BERKE.md` madde 10'daki Go
  derleyicisi kararı beklenmeden paket kapanabilsin. `BERKE.md` madde 2'ye "kendi kodu %10,9" satırı. P-ÜV9'un "Ghidra
  fonksiyon sınırı" ölçümü P-ÜV6'dan **önce** yapılsın (gösteri çıktısı yeter; ürün etkisinin ön koşulu).

### İ-12. Makro yanlış hedefi 12–55 adlık paydalarla ölçülüyor

- **Kanıt:** `python B/turet_taban.py`: makro %31,08 altı programın ortalaması; paydalar sqlite3 12 (7 yanlış; Wilson
  %32–%81), redis-tools 15, openssl 26, zstd 55. Biçim satırıyla %19,17 (ÖLÇÜ %19,1 yazmış; yuvarlama).
- **Düzeltme:** `sonuc.md` / P-Ö1 raporu makro satırının yanına program başına Wilson aralığı ve "n < 30 program
  sayısı" yazsın; hedef (≤ %10) bu setle karara bağlanamaz diye not düşülsün. Küçük.

### İ-13. Küçük düzeltmeler (uygulayan ajan takılmasın)

| Belge | Yer | Düzeltme | Kanıt |
|---|---|---|---|
| `kimlik/PLAN.md` PK-5 | "`add_k4_channels`'ın çağrıldığı yer" `_feedback_naming_merger.py` | çağrı `_feedback_naming_candidates.py:90`; merger'daki yer `k4_inputs` (satır 295–305); alıntılanan `flags = {…}` satırı doğru | `grep -rn add_k4_channels karadul` |
| `kimlik/PLAN.md` PK-1 adım 3 | `_match_against_db` `matches` listesinden okur | bugün `naming_map` ile çalışıyor (`grep -c "\.matches" …_refdiff.py` → 0); plan geçişi tarif ediyor, "bugün böyle" notu eklensin | aynı |
| `olcek/PLAN.md` §3–§4 | "yayından önce / sonra" başlıkları | A-7 ile geçersiz; ÖL-7 … ÖL-11 de zorunlu | `KARARLAR.md` / `YAYIN_KAPISI.md` §2 |
| `olcu/BULGULAR.md` §4 | makro %19,1 | %19,2 (0,1917) | `$V/turet_taban.txt` |
| `YAYIN_KAPISI.md` Y6 | "51,8 MB, arm64 dilimi" | dosya 54 300 560 B; analiz edilen dilim 26 627 984 B | `ls -l …/ustveri/hedef/` |
| gösteri `gosteri.yaml` / G3 | çözümleyici adı | 'Objective-C Message' adı Ghidra'da bulunamadı ("kapatılamadı"); G3 ölçümü doğru adla yapılmalı | `$V/gosteri_oku.txt` |
| Ön kayıt metni olmayan paketler | ÖK-7, ÖL-8, ÖL-11, P24, P03b, P23 | ÖK-7 açık ölçüm listesi (doğal); P24 / P03b / P23 sınama listeli, sayısal eşik yok; ÖL-8 ve ÖL-11'e ön kayıt cümlesi yazılsın | `python B/plan_tara.py` |

## 2. Yön kararına itiraz (kalem 4; A-7 gözüyle)

- **Boşa gitme riski en yüksek hat: ÖLÇÜ'nün kalan paketleri.** Hattın ana sonucu olumsuz ve sağlam ("sözcük ölçüsü
  amaçça doğru adı sayamaz"); geriye kalan P-Ö3 / 4 / 9 model hakemle bilgi üretmiyor (İ-5), P-Ö6 / 7 / 8 tabakaları
  yine düz C programları (x86-64, başka GCC): hedef nüfusa (Mach-O, karışık dil) bir adım yaklaştırmıyor. Kalması
  gereken: P-Ö1 (biçim satırı), P-Ö2 / P-Ö5 (ortak ölçüme taşıma) ve tekil / örnek çift raporu.
- **Değeri hedefe en uzak hat: ÖZ KOD'un K1 / G1 ürün paketleri.** Kurallar C programlarının ad geleneğine dayanıyor
  (tablodan mekanik ad, `__func__`); hedefte erişimi ölçülmedi. ÖK-1 (harf koruma) ve ÖK-2 ölçülmüş kusur onarımı: kalır.
- **Seçilmeyenlerden daha çok kazandıracak olanlar:** (1) ÜST VERİ (sonradan eklendi; Go'da %83–%100 hazır ad);
  (2) E1–E5 / ÖLÇEK (koşu bitmeden hiçbir ad görünmez); (3) I2 (`main`, tek paket, 1 169 / 1 169); (4) D3 / C4
  (okunurluk): analistin 13 559 fonksiyonluk çıktıda işine yarayan şey ad kadar gezinme ve kanıt satırıdır — hiçbir hat
  ölçmüyor.
- **Sav ("hatlar yanlış nüfusu iyileştiriyor"): büyük ölçüde doğru.** Kanıt İ-1. Karşı kanıt da var: hedef
  uygulamaların Go dışı kısmı (Ollama 1 676, btop 1 759, Rectangle 1 765 fonksiyon adsız kalıyor; ÜST VERİ §7) tam da
  C / C++ hesaplamasına muhtaç; KİMLİK ve ÖZ KOD orada işe yarayabilir, ama orada **ölçülmediler**.

## 3. Bitiş çizgisini en çok tehdit eden risk (kalem 7)

Bitiş çizgisinin son koşulu "gerçek büyük bir uygulamada uçtan uca çalışmış" bugün 26,6 MB'lık tek dilimde ancak
kısmen sağlanıyor (gösteri: ilk deneme takıldı; ikincisi 2 sa 9 dk'da "kısmi" bitti ve 13 160 fonksiyonun 17'sine ad
verdi) ve bunu düzeltecek işler planların en zayıf yeri:
ÖL-10 (tembel derinlik) belirlenmemiş, ÖL-9'a bağlı, sıranın sonunda; ölçek tahminleri 119 küçük ikiliden dışa
uzatma (xref / CFG adımları gösteride modelin 8,6 / 9,7 katı çıktı); her doğrulama tek Ghidra kuyruğundan geçiyor ve
tek bir ölçek ölçümü 27 saat istiyor. Aynı anda 63 paketin 29'u, hedefte hiç ölçülmemiş ad kurallarını düz C setinde
inceltiyor. Risk şu: bütün paketler "kabul ölçütü tuttu" diye kapanır, 119'luk ölçüm iyileşir, ama Berke'nin önüne
gelen ilk büyük uygulama yine bitmez ya da bugünkü gibi bitince adların kaynağı (üst veri) bağlanmamış olur. Karşı önlem: bitiş
ölçümünü (hedef seti + T25 uçtan uca) ilk dalgada "önce" sayısı olarak almak ve her dalganın sonunda yeniden koşmak;
119'luk ölçümü yalnız geriye gitme denetimi olarak tutmak.

## 4. Kalem 2 — aşırı uyum ve sızıntı: bulamadıklarım

Baktığım yerler ve sonuç (ayrıntı `DEFTER.md` §3):
- Dosya zamanları üç hatta da "keşif → dondur → sınama" sırasıyla tutarlı; ÖZ KOD'un kural dosyası sınamadan önce
  son kez değişmiş (10:43:53 → 10:45:49). KİMLİK `esle.py` 11:46'da değişmiş (ilk sınamadan sonra); `sinama_tmux` kural
  sayısı iki çıktıda aynı (2 276 / 158), ama eşleyiciyi kendim koşmadığım için "v1 çıktısı birebir aynı" iddiasını
  bağımsız doğrulamadım.
- Aynı kaynağın iki derlemesi bölmenin iki yanına düşmemiş (ÖZ KOD: tmux ikisi keşifte, htop ikisi sınamada). ÖLÇÜ'de
  AYAR ve SINAMA C aynı ikilinin (Mac tmux) farklı öğeleri; eşik seçilmediği ve sonuç olumsuz olduğu için zarar yok.
- "Ölçüm sonrası tanım" olan sayılar (ÖZ KOD R1 + harf 28 / 31; nesne gevşek 152 / 175; KİMLİK "tek taraflılar hüküm
  dışı" 0,975) belgelerde işaretli; bulgu gibi sunulmamış.
- Sınama tarafının kaç kez görüldüğü üç hatta da yazılı (ÖZ KOD 1 + 1 işaretli değişke; ÖLÇÜ 3; KİMLİK v1 1, v2 "ikinci bakış").
- Tek gerçek bulgu İ-6'daki program düzeyi bağımsızlık.

## 5. Doğrulanan iddialar (kalem 1)

Tam tablolar `DEFTER.md` §2. Özet (hattın sayısı = benim sayım, aksi yazılmadıkça):

### 5.1 Taban ve ÖLÇÜ (`B/turet_taban.py`)
nüfus 21 371; ad 1 800; doğru 1 681; yanlış 119; nüfusta doğru 1 212 · 119 yanlışın 40'ı biçim farkı (37 zstd) ·
makro %31,0 → %19,2 · 535 tekil ad, 422 doğru, 40 biçim · gnulib kanalı 733 ad = 10 tekil ad · tekil nüfus 9 257 ·
`oz_ad` güven sınıfları (0,80 → 22 / 76; 0,85 → 71 / 121) · ikiz yoğunluğu F1 ≥ 0,8: %32,7 (≥ 0,5: benim %78,3, hattın %76,3).

### 5.2 KİMLİK (`B/turet_kimlik.py`, `$V/yon_basina.txt`)
taban ürün tmux 341 / 4 396, htop 0 / 819 · A1 set içi kopya 13 472 · tekil dizgi çapası tmux 737 / 54 (benim bağımsız
gerçeklemem 738 / 55), htop 104 / 2 · envanter tavanları (fark ≤ 8 fonksiyon; takma ad). Taze derleme sayıları
(3 908 / 38 vb.) **yeniden türetilmedi**: çıktılarda eşleme çifti yok; yalnız yön başına tutarlılığı denetlendi.

### 5.3 ÖZ KOD (`B/turet_ozkod.py`)
nüfus 20 747 · `oz_ad` keşif 141 / 92, sınama 55 / 1 · harf korumayla 40 yanlış doğruya döner (kanıt dizgisi yolundan
39, biçim yolundan 40) · pencere çifti olan nüfus 1 196 · K1 keşif oranı %98,1 (bağımsız gerçekleme) · doğrudan dizgi
tavanı %12,1 / %5,4 · "bugün" tavanı program kodunda %48,0 / %12,7 (hattın %52,1 / %13,4; belirteçleme farkı) ·
modül öneki: adres komşuları %96,5, çağrı çoğunluğu %54,4 (hattın %96,4 / %55,2).

### 5.4 ÜST VERİ (`B/go_bagimsiz.py`)
docker-cli 35 049 girişin 35 049'unda ad sembolle aynı (34 711 + `.abi0` 328 + nokta yazımı 10); docker-compose
90 078 / 90 078 · `nfunc` Ollama 10 601, gh 40 384, limactl 40 321, colima 13 082 · Go ≥ 1.26 başlığında `textStart` 0 ·
`LC_MAIN` girişi = `_main`: Homebrew tmux, htop, xz, gsort, btop 5 / 5 (`zsh B/lc_main.sh` → `$V/lc_main.txt`) · `_recover_main_from_entry` `stages.py:1816`'da
ve canlı. ObjC / Swift / RTTI sayıları, bozma deneyi ve bütçe tablosu **yeniden türetilmedi**.

### 5.5 Planların uygulanabilirliği (kalem 5)
- `python B/plan_tara.py`: 63 paket tarandı. "Var" denen dosyaların hepsi var. Elle `grep` ile denetlediğim, planların
  "bugün var" dediği 59 sembol ve 14 dosyanın 2 sembolü dışında hepsi yerinde (`zsh B/sembol_denet.sh` →
  `$V/sembol_denet.txt`: sembol 57 var / 2 yok, dosya 14 / 14; iki sapma İ-13'te).
- Kabul ölçütü sayısal ve ön kayıt metni hazır: KİMLİK PK-1 … PK-11, ÖZ KOD ÖK-1 … ÖK-6, ÜST VERİ P-ÜV0 … P-ÜV9,
  ÖLÇEK ÖLÇ-0 … ÖL-7, ÖL-9, ÖL-10 (metin olarak; ÖL-10'un içeriği İ-2). Eksikler: İ-13 son satır, İ-5 (ÖLÇÜ P-Ö3 / 4 / 9
  yeniden yazılmalı), İ-2 (ÖL-10).
- ÜST VERİ ve KİMLİK planları yazanı olmadan uygulanabilir düzeyde (dosya, işlev, adım, mutant, ön kayıt metni);
  en iyi yazılmış iki plan bunlar.

## 6. Denetlenmeyenler

- **HIZ:** `hiz/PLAN.md` 13:17'de yazıldı (11 paket: HZ-0 … HZ-9); 13:20'de `## PAKET BİTTİ` işareti ve `BERKE.md` yok →
  içerik (sayılar, kabul ölçütleri, sembol varlığı) **denetlenmedi**. Yalnız dosya taraması yapıldı ve `CAKISMA.md`'ye
  eklendi: `ghidra/headless.py`'de 6 HIZ paketi ÖLÇEK'in 5 paketiyle çakışıyor. HZ-7'nin metni boş ("Profil bitince
  yazılacak", `hiz/PLAN.md` satır 230): plan bu hâliyle gönderilemez.
- ÖLÇEK'in ölçek tahminleri (BULGULAR §3) yeniden türetilmedi; yalnız plan ve gösteri günlüğü okundu.
- Onarım paketlerinden `P10b`, `P08b`, `P18` yalnız dosya düzeyinde tarandı (içerik denetimi yok).
