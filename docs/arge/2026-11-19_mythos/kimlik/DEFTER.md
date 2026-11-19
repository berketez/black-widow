# KİMLİK hattı — defter (tur 1, 2026-11-19)

Yazan: KİMLİK hattı araştırma ajanı (Mythos). Sıra zamana göredir; sonraki ajan buradan sürdürür.
Betikler: `scripts/arge/kimlik/`. Ara çıktılar: `~/karadul_olcum/runs/arge-2026-11-19/kimlik/`.

## 0. Okunanlar

- `ORTAK_BRIF.md`, `HAT_KIMLIK.md`, `YON.md`.
- `2026-11-18_arge_soru_listesi.md` §1, §1.1, §2, A1–A6, C5, E5, H3, I1.
- `2026-11-19_birlesik_olcum/sonuc.md` (taban: 1 800 ad, 1 681 doğru; nüfus 21 371; doğru ad kapsamı %5,7).
- `scripts/measurement/ks1_olc.py`: `gt_elf`, `gt_mac`, `GtBirimi`, `oran`, `klon_tabani`, `platform_adi`.

## 1. Elde ne var (sayılara bakmadan, yalnız dosya düzeni)

| Çift | Sorgu / başvuru koşuları (var olan Ghidra çıktısı) | GT |
|---|---|---|
| htop | `urun-onarim-a62f15e/debian/htop/htop`, `…/mac/htop` | Debian dbgsym (`downloads/debian13`), `workspaces/olcum_mac/corpus/htop/gt` (Homebrew 3.5.3) |
| tmux | `urun-onarim-a62f15e/debian/tmux/tmux`, `…/mac/tmux` | Debian dbgsym, `olcum_mac/corpus/tmux/gt` (Homebrew 3.8) |
| coreutils Debian ↔ Homebrew | Debian: `urun-onarim-a62f15e/debian/coreutils/{cat,sort,mktemp}`; Mac: `onarim-2026-11-18/P-S3/A/macgnu/gcat`, `P-S3b/A/macgnu/{gsort,gmktemp}` | Debian dbgsym; `P-S3/mac_gnulib/corpus/gcat/gt`, `P-S3b/mac_kabul/corpus/{gsort,gmktemp}/gt` |
| coreutils içi (gnulib, aynı derleyici) | `urun-onarim-a62f15e/debian/coreutils/*` (106 ikili) | Debian dbgsym |
| korpus 9.4 | `runs/aday-f893d72/{debian-9.4-3,ubuntu-9.4-3ubuntu6}/{cat,cut,wc,expr,comm}` (eski Karadul sürümü; çıktı alanları denetlenecek) | `corpus/*/gt/*.gt.json` |

Koşu çıktısında fonksiyon başına hazır olgu: `ghidra_functions.json` (ad, thunk, boyut),
`ghidra_call_graph.json` (kenarlar), `ghidra_strings.json` (dizgi → fonksiyon xref), `ghidra_cfg.json`
(blok, kenar, komut adları), `ghidra_output/pcode.jsonl` (P-code işlemleri, sabitler), `ghidra_bsim.json`
(BSim eşleşmeleri; depoda o an hangi ikililer varsa onlara karşı).

Yeni Ghidra koşusu gerekmiyor görünüyor: bu turda **hiç Ghidra koşulmayacak**.

## 2. Bölme kararı (sayılara bakılmadan yazıldı, 2026-11-19)

- **Keşif (ayar) birimi: htop çifti** (debian/htop ↔ mac/htop, iki yön). Yöntemin bütün parametreleri burada,
  GT'ye bakılarak ayarlanır: içe aktarım adı normalleştirmesi, en kısa dizgi boyu, çapa için en az oy,
  yayılım puanı eşiği, fark (marj) eşiği, kanıt ağırlıkları, tur sayısı, ad ailesi kuralı.
- **Sınama birimleri (dondurulmuş parametrelerle, tek sayım):**
  1. tmux çifti (debian/tmux ↔ mac/tmux, iki yön);
  2. coreutils Debian ↔ Homebrew (cat ↔ gcat, sort ↔ gsort, mktemp ↔ gmktemp; iki yön); tek birim sayılır;
  3. coreutils içi gnulib (aynı derleyici, farklı program): başvuru = bir ikili, sorgu = öbürü; çiftler aşağıdaki
     kuralla seçilir, sonuç tek birim (ortak kod) olarak raporlanır;
  4. korpus (9.4 Debian / Ubuntu ↔ Debian 13) — öncül 3 (sürüm ↔ derleyici) için; çıktı alanları yetiyorsa.
- **Coreutils içi çift seçimi (sayılara bakmadan):** ada göre sıralı 106 ikiliden sorgu olarak her 10.'su
  (0, 10, 20, … indisli; 11 ikili), her sorgunun başvurusu sıradaki bir sonraki ikili (indis + 1). Böylece
  seçim GT'ye ya da sonuca bağlı değil.
- htop'ta görülen her şey (örnek adlar dahil) kural kurmada kullanılabilir; sınama birimlerinde yöntemin
  çıktısına bakıp parametre değiştirmek yok. Sınama birimlerinde bir kusur (ör. yükleyici hatası) çıkarsa
  düzeltme deftere "sapma" diye yazılır ve htop sayıları yeniden üretilir.
- Kilitli setler: `targets/test_seti`, `targets/dogrulama_seti` ve koşu çıktıları açılmadı, listelenmedi.
  `~/karadul_olcum/downloads/debian13` yalnız `gt_elf`'in build-id kalıbıyla (tek dosya) okunuyor; dizin listelenmedi.

## 3. Ölçü tanımları (sayılardan önce)

- **Yön:** sorgu Q = soyulmuş ikili (ad bekleyen), başvuru R = aynı kaynağın öbür derlemesi (adları GT'den).
  İki taraf için de var olan *soyulmuş* koşunun Ghidra çıktısı kullanılır; R'nin adları yalnız GT'den gelir
  (gerçek kullanımda R sembollü analiz edilir; bizimki R için daha kötü fonksiyon sınırı demek, yani tutucu).
- **Q'da bilinen sayılan:** Ghidra'nın soyulmuş ikilide kendi verdiği jenerik olmayan adlar (içe aktarım
  thunk'ları, dinamik simge tablosundan gelen dışa aktarımlar, `entry`). GT'den Q'ya hiçbir şey sızmaz.
- **Nüfus (N_Q):** `ks1_olc.GtBirimi.nufus` (Ghidra'da adsız, GT'de program sınıfı adı olan, CRT / export /
  klon olmayan). Ürün ölçümüyle aynı payda.
- **Tavan:** N_Q içinde, normalleştirilmiş GT adı R'nin GT adları arasında da bulunanlar.
- **Hüküm:** eşleme q → r önerirse, r'nin GT adları (Mach-O'da baştaki `_` soyulur; derleyici klonu eki
  `klon_tabani` ile tabana iner) ile q'nun GT adları kesişiyorsa **doğru**; kesişmiyorsa **yanlış**;
  r'nin GT adı yoksa öneri **adsız** (ad verilmez, paydaya girmez, ayrı sayılır); q'nun GT'si yoksa **hükümsüz**.
- **Kesinlik** = doğru / (doğru + yanlış), nüfus içinde; Wilson %95 (`ks1_olc.oran`). **Kapsam** = doğru / |N_Q|;
  ayrıca doğru / tavan.
- **Hedef:** kesinliğin Wilson alt sınırı ≥ 0,95.

## 4. Ön kayıt (ölçümden önce; tutmayan silinmez)

Yöntem: (A) tekil çapa — yalnız bir fonksiyonda geçen dizgi (iki tarafta da tekil), tekil içe aktarım çağrı
kümesi; (B) çağrı grafiği yayılımı — eşlenmiş komşular + dizgi + içe aktarım kanıtının ağırlıklı örtüşmesi,
belirsizlik kapısı (en iyi aday ikinciden marj kadar ayrılmıyorsa ad yok); (C) kapıda kalan eşit adaylar için
ad ailesi.

| # | Beklenti (yazıldığı an: kod yazılmadan) | Eşik: tuttu / tutmadı |
|---|---|---|
| Ö1 | Tekil dizgi çapası tek başına, tmux (dondurulmuş): kesinlik noktası ≥ 0,95, ama kapsam düşük (nüfusun ≤ %25'i) | kesinlik Wilson alt ≥ 0,90 **ve** kapsam ≤ %25 → "tuttu" |
| Ö2 | Çapalı yayılım, tmux, dondurulmuş: kesinlik Wilson alt sınırı ≥ 0,95 (aykırı öncül 1) | Wilson alt ≥ 0,95 → öncül tuttu; < 0,95 → tutmadı |
| Ö3 | Aynı noktada kapsam (doğru / nüfus) ≥ %40 | ≥ %40 → tuttu |
| Ö4 | coreutils Debian ↔ Homebrew, dondurulmuş: kesinlik Wilson alt ≥ 0,95 | aynı eşik; n küçükse (alt sınır n yüzünden düşükse) "sayı yetmedi" yazılır |
| Ö5 | coreutils içi (aynı derleyici, farklı program): çapalı yayılım kesinliği P11'in CFG-iso ham 0,882'sinden yüksek | nokta > 0,882 ve Wilson alt ≥ 0,90 → tuttu |
| Ö6 | Ad ailesi (öncül 2): kapıda kalan fonksiyonlarda GT adı aday kümesinin içinde, oran Wilson alt ≥ 0,95 | ≥ 0,95 → tuttu |
| Ö7 | Öncül 3: derleyici / platform farkı (GCC ↔ clang, ELF ↔ Mach-O) sürüm farkından pahalı; ölçüt: aynı yöntemle kapsam kaybı | korpus çıktısı yetiyorsa sayılır; yetmezse "ölçülemedi" |
| Ö8 | BSim çıplak (var olan `ghidra_bsim.json`, Mac → Debian): en iyi adayın ad kesinliği < 0,95 (Wilson alt) | < 0,95 → beklenti tuttu (BSim tek başına yetmiyor) |

Kendi tahminim (bağlayıcı değil, kayıt için): Ö2 sınırda (nokta 0,93–0,98); Ö3 belirsiz (address-taken
fonksiyonlar çağrı grafiğinden ulaşılmaz); Ö6 tutar ama aile boyu büyük çıkabilir.

## 5. Günlük

### 5.1 Yükleyici ve envanter (kalem 1)

- `scripts/arge/kimlik/veri.py`: var olan koşuların `static/` çıktısından fonksiyon başına olgu (dizgi, içe
  aktarım, çağıran / çağrılan, P-code sabitleri, CFG) + GT (`ks1.gt_elf` / `gt_mac`; korpus için aynı mantık
  hazır GT JSON'undan). Ghidra koşulmadı.
- Kuşak farkı: P-S3 / P-S3b Mach-O koşularında ve korpus koşularında (`aday-f893d72`) `ghidra_strings.json`
  içinde dizgi → fonksiyon bağı yok (GHIDRA-16 öncesi). Dizgi kanıtı iki kaynağın birleşimi yapıldı
  (`ghidra_xrefs.json` `strings_used` ∪ `ghidra_strings.json` `xrefs`); bu, eşleme parametresi değil, yükleme
  tanımıdır ve htop'ta eşleme sayısı üretilmeden önce yapıldı.
- Envanter: `python scripts/arge/kimlik/envanter.py kesif_htop sinama_tmux sinama_cu_mac sinama_cu_ic surum derleme
  --json ~/karadul_olcum/runs/arge-2026-11-19/kimlik/envanter.json` (sayılar BULGULAR §1'de).
- Sürümler (GT künyesinden): htop Debian 3.4.1-5 (GCC 14, `-rdynamic`: 367 fonksiyonun adı dinamik simge
  tablosundan Ghidra'da hazır) ↔ Homebrew 3.5.3 (clang); tmux Debian 3.5a-3 ↔ Homebrew 3.8. Yani iki ana
  çiftte derleyici / platform farkı ile sürüm farkı **birlikte**; ayrıştırma korpus çiftleriyle (öncül 3).
- Ubuntu 9.4 korpusu LTO'lu: fonksiyon sayısı 26–42 (Debian 9.4'te 97–122). "Aynı sürüm, başka derleme"
  kolunda fark derleyici sürümü değil LTO.

### 5.2 Yöntem (prototip): `scripts/arge/kimlik/esle.py`

- Çapalar: (a) ad çapası — Q'da Ghidra'nın bildiği ad (htop Debian'da dinamik simgeler) R'de tek fonksiyonun
  adıysa; (b) tekil dizgi — iki tarafta da tek fonksiyonda geçen dizgi, oylar çelişmiyorsa.
- Yayılım: kanıt = dizgi + içe aktarım çağrısı + P-code sabiti (16 ≤ c < 2^40) + eşlenmiş çağrılan + eşlenmiş
  çağıran. Ağırlık 1 / log2(1 + df), df = kanıtı taşıyan **eşlenmemiş** fonksiyon sayısı (eşleme ilerledikçe
  tekillik artar). Puan = ağırlıklı Jaccard. Kapı: puan ≥ T, ortak kütle ≥ `kutle`, en iyi − ikinci ≥ `marj`,
  karşılıklı en iyi (R tarafında da marj). Öğrenme yok; bütün sayılar sayım.
- İçe aktarım adı normalleştirmesi htop'ta okundu: baştaki `_`, `_chk`, `$DARWIN_EXTSN`, `isocNN_` soyulur;
  `__errno_location` ≡ `__error`; derleyicinin birbirine çevirdiği yerleşikler (printf ↔ puts, memset ↔ bzero,
  str* / mem*) ve çalışma zamanı gürültüsü (`__stack_chk_fail` …) kanıt sayılmaz.
- htop'ta kanıt türlerinin kararlılığı (gerçek çiftlerde ortalama Jaccard ↔ rastgele çiftte): dizgi 0,51 ↔ 0,00;
  sabit ≥ 16: 0,50 ↔ 0,03; sabit ≥ 256: 0,27 ↔ 0,02; çağrılan sayısı eşit %84; blok sayısı eşit %52.
  Yani CFG biçimi derleyiciler arasında tutmuyor, çağrı yapısı ve sabitler tutuyor. (Tek seferlik keşif kodu;
  sayılar yön gösterici, betiği yok.)

### 5.3 Ayar (yalnız htop) ve dondurma — sınama birimlerine bakılmadan

- Izgara: `python scripts/arge/kimlik/ayar.py --json ~/karadul_olcum/runs/arge-2026-11-19/kimlik/ayar_htop_1.json`
  (T × marj × kütle × sabit çarpanı × komşu şartı = 750 nokta; iki yön havuzlanır; 3 dk).
- Seçim kuralı ızgaradan önce betiğin başına yazıldı: Wilson alt ≥ 0,95 olanlar içinde en yüksek kapsam.
- **Birincil nokta ("kural")**: T 0,3; marj 0,1; kütle 0,5; sabit çarpanı 1,0; komşu şartı yok.
  htop havuzu: 515 doğru / 16 yanlış, kesinlik 0,970 (Wilson alt 0,952), kapsam %62,9 (515 / 819).
  Uyarı: nokta ızgaranın kenarında (en düşük T, en düşük kütle) ve alt sınır eşiğe çok yakın; aşırı uyum riski
  yüksek. Bu yüzden ikinci bir nokta da **şimdi** donduruluyor.
- **İkincil nokta ("tutucu")**: aynı, kütle 1,0. htop havuzu: 468 / 9, kesinlik 0,981 (alt 0,965), kapsam %57,1.
  Gerekçe (htop'tan): kural noktasındaki 16 yanlışın 7'sinin ortak kanıt kütlesi < 1,0.
- htop yanlış türleri (kural noktası): sürümler arası yeniden adlandırma (`DiskIOMeter_display` ↔
  `DiskIORateMeter_display`, tekil dizgi çapasında bile); satır içine alma farkı (çağrılan, bir derleyicide
  çağıranın içine girince kanıtı çağırana taşınıyor: `Vector_resizeIfNecessary` ↔ `xReallocArrayZero`,
  `Table_delete` ↔ `ProcessTable_delete`); ince sarmalayıcı çiftleri (`Platform_gettime_monotonic` ↔
  `Generic_gettime_monotonic`); R'deki CRT fonksiyonu (`_start`) aday olabiliyor.
- htop'ta eşlenmeyenler (kural noktası; Debian → Mac 94, Mac → Debian 194): tavan dışı 41 / 74; adayı var ama
  kapıda kalan 41 / 100; hiç kanıtı olmayan (yalıtık, dizgisiz, içe aktarımsız, komşusuz) 9 / 12. Kalanların
  ortanca boyutu 56–64 bayt (eşlenenlerde 120–176): küçük yaprak fonksiyonlar.
- **Ad ailesi kuralı** (`ikiz.py`, htop'ta ayarlandı, donduruldu): en iyi aday puanı ≥ 0,3 ve kütle ≥ 0,5;
  aile = en iyi puandan 0,2 içinde kalan adaylar; en çok 8 üye; tek üyeli küme aile sayılmaz (ayrı satır).
  htop: küme isabeti Debian → Mac 20 / 21, Mac → Debian 29 / 30. htop ikizleri ortak **önek** taşımıyor,
  ortak **sonek** taşıyor (`CommandScreen_delete` ↔ `EnvScreen_delete`) ya da seçenek çifti
  (`actionNextScreen` ↔ `actionPrevScreen`); bu yüzden aile etiketi önek + sonek olarak ölçülecek.
- Dondurma anı: bu satır yazıldığında tmux, coreutils ve korpus çiftlerinde eşleme hiç koşulmadı
  (yalnız envanter sayıları görüldü: fonksiyon, nüfus, tavan).
- Dondurmadan sonra, sınamadan önce tek kod değişikliği: aday listesi boyu 8 → 12 (`esle.ADAY_LISTE`; aile
  kuralı "8'den çok üye → aile yok" diyebilsin diye). htop yeniden koşuldu: kural noktası aynı (515 / 16),
  tutucu 468 / 9 → 467 / 9. Betik: `yayilim_olc.py kesif_htop --egri` → `yayilim_kesif_htop.json`.

### 5.4 Sınama birimleri — dondurulmuş parametrelerle tek sayım

Komutlar (hepsi depo kökünden, `PYTHONDONTWRITEBYTECODE=1`; çıktılar `~/karadul_olcum/runs/arge-2026-11-19/kimlik/`):
- `python scripts/arge/kimlik/yayilim_olc.py sinama_tmux --egri --json …/yayilim_sinama_tmux.json`
- `python scripts/arge/kimlik/yayilim_olc.py sinama_cu_mac sinama_cu_ic surum derleme --json …/yayilim_sinama_coreutils.json`
- `python scripts/arge/kimlik/ciplak.py kesif_htop sinama_tmux sinama_cu_mac sinama_cu_ic surum derleme --json …/ciplak.json`
- `python scripts/arge/kimlik/hata_dok.py <aynı gruplar> --nokta kural|tutucu --json …/hata_dok_<nokta>.json` (metin: `hata_dok_<nokta>.txt`)

Dondurulmuş sayım (kural noktası; nüfus içi, iki yön havuzlu; [Wilson %95]):

| Birim | doğru / yanlış | kesinlik | kapsam (doğru / nüfus) | tavanın |
|---|---|---|---|---|
| htop (keşif; ayar burada yapıldı) | 515 / 16 | 0,970 [0,952–0,981] | %62,9 | %74,1 |
| tmux | 2 276 / 158 | 0,935 [0,925–0,944] | %51,8 | %65,7 |
| coreutils Debian ↔ Homebrew | 316 / 47 | 0,871 [0,832–0,901] | %32,6 | %42,8 |
| coreutils içi (aynı derleyici) | 1 026 / 13 | 0,987 [0,979–0,993] | %36,4 | %48,6 |
| sürüm (9.4 ↔ 9.7, Debian) | 481 / 26 | 0,949 [0,926–0,965] | %48,4 | %52,1 |
| derleme (9.4 Debian ↔ Ubuntu LTO) | 119 / 23 | 0,838 [0,769–0,890] | %21,7 | %65,7 |

Tutucu nokta: tmux 2 040 / 130 → 0,940 [0,929–0,949], kapsam %46,4; coreutils ↔ Homebrew 270 / 33 → 0,891;
coreutils içi 942 / 5 → 0,995 [0,988–0,998]. Tutucu nokta da tmux'ta 0,95'i geçmiyor.

**Ön kayıt hükümleri:**
- Ö1 (tekil dizgi, tmux): 737 / 54 → 0,932, Wilson alt 0,912 ≥ 0,90 ve kapsam %16,8 ≤ %25 → **tuttu**
  (ama kesinlik nokta beklentim "≥ 0,95" idi; nokta 0,932: beklentinin o parçası tutmadı).
- Ö2 (çapalı yayılım, tmux, Wilson alt ≥ 0,95): alt sınır 0,925 → **tutmadı**. Aykırı öncül 1, dondurulmuş
  hâliyle ve tam ad eşitliği ölçüsüyle derleyici + sürüm farkında tutmuyor.
- Ö3 (tmux kapsamı ≥ %40): %51,8 → **tuttu**.
- Ö4 (coreutils ↔ Homebrew, Wilson alt ≥ 0,95): 0,832 → **tutmadı**.
- Ö5 (coreutils içi > 0,882 ve alt ≥ 0,90): 0,987, alt 0,979 → **tuttu**.
- Ö6 (ad ailesi küme isabeti, Wilson alt ≥ 0,95): tmux 212 / 259 = 0,819 [0,767–0,861] → **tutmadı**;
  coreutils içi 592 / 598 = 0,990 [0,978–0,995] → orada tuttu. Öncül 2 aynı derleyicide tutuyor, derleyici +
  sürüm farkında tutmuyor.
- Ö7 (öncül 3): aşağıdaki hata dökümü.
- Ö8 (BSim çıplak, Mac → Debian; en iyi aday ≥ 0,7): htop 129 / 46 = 0,737; tmux 303 / 127 = 0,705
  [0,660–…]; "tek en iyi" kapısıyla tmux 276 / 60 = 0,821 → **tuttu** (BSim tek başına < 0,95).

**Neden olmadı — hata dökümü (dondurulmuş sayımdan SONRA bakıldı; bundan sonra tmux / coreutils ↔ Homebrew
keşif birimi sayılır, bunlarda ayarlanan hiçbir şey "sınama" diye raporlanamaz):**

| Birim (kural) | yanlış | adı R'de yok: tek taraflı (yeniden adlandırma adayı) | adı R'de yok: satır içi | komşu (satır içi kayması) | aile | diğer | tavan içi kesinlik |
|---|---|---|---|---|---|---|---|
| tmux | 158 | 99 | 25 | 17 | 10 | 7 | 2 276 / 2 310 = 0,985 [0,980–0,989] |
| coreutils ↔ Homebrew | 47 | 30 | 7 | 10 | 0 | 0 | 316 / 326 = 0,969 [0,945–0,983] |
| coreutils içi | 13 | 11 | 0 | 0 | 2 | 0 | 1 026 / 1 028 = 0,998 |
| sürüm | 26 | 24 | 1 | 1 | 0 | 0 | 481 / 482 = 0,998 |
| derleme (LTO) | 23 | 2 | 14 | 7 | 0 | 0 | 119 / 126 = 0,944 |

- "Tek taraflı": q'nun GT adı R'de yok **ve** seçilen r'nin adı da Q'da yok. tmux'ta bunlar gözle açıkça
  3.5a → 3.8 yeniden adlandırmaları: `notify_*` → `events_fire_*`, `status_prompt_*` → `prompt_*`,
  `control_notify_*` → `control_*_cb`, `popup_editor` → `spawn_editor`, `window_pane_visible` →
  `window_pane_is_visible`. 52 tekil çiftin 47'si iki yönde de aynı çift olarak çıkıyor. coreutils'te gnulib'in
  platforma göre ad değiştirmesi (`fpurge` ↔ `rpl_fpurge`, `reallocarray` ↔ `rpl_reallocarray`) ve sürüm
  yeniden adlandırması (`setlocale_null` → `setlocale_null_unlocked`, `hash_find_entry` → `find_entry`).
  Yani eşleme doğru fonksiyonu buluyor; **başvurunun sürümündeki adı** veriyor. Tam eşitlik ölçüsü bunu yanlış
  sayıyor. Mekanik doğrulaması yok (kaynak geçmişi gerekir) → bu sınıf çıkarılarak hesaplanan kesinlik
  (tmux 2 276 / 2 335 = 0,975 [0,968–0,980]) yalnız **yön gösterici**.
- "Satır içi" + "komşu": derleyici farkının asıl bedeli. Bir derleyici çağrılanı çağıranın içine alınca kanıt
  (dizgi, içe aktarım) bir basamak kayıyor; tekil dizgi çapası bile yanılıyor (`control_write` ↔
  `control_write_line`, `print_errno_message` ↔ `error_tail`, `version_etc_arn` ↔ `version_etc`).
  LTO çiftinde yanlışların 21 / 23'ü bu.
- **Öncül 3:** tam ad kesinliğini sürüm farkı derleyici farkından daha çok bozuyor (tmux: 99 yeniden adlandırma
  adayı ↔ 42 satır içi türü; coreutils ↔ Homebrew: 30 ↔ 17), ama sürümün bozduğu şey çoğunlukla **ad**
  (aynı fonksiyon, yeni ad), derleyicinin bozduğu şey **kimlik** (yanlış fonksiyon). Ayrı ayrı ölçmek için
  aynı sürümün iki derleyiciyle derlemesi gerekir; elde yok (PLAN'da veri isteği).
- Ad ailesi (öncül 2), tavan içi küme isabeti: tmux 212 / 233 = 0,910 [0,866–0,940]; coreutils ↔ Homebrew
  110 / 114 = 0,965 [0,913–0,986]; coreutils içi 592 / 598. Tavan dışı (isabet olanaksız) 26 / 2 / 0.

**Çıplak ölçümler (kalem 2; `ciplak.json`):**
- Tekil dizgi çapası: htop 104 / 2; tmux 737 / 54 (0,932); coreutils ↔ Homebrew 53 / 6; coreutils içi 248 / 0;
  sürüm 108 / 0; derleme 30 / 7. Kapsam nüfusun %5–17'si.
- CFG yapısı tekil (blok ≥ 3; blok, kenar, WL özeti): derleyiciler arası çöküyor: tmux 20 / 27 (kapsam %0,5),
  htop 7 / 5. Komut adı çoklu kümesiyle (P11 bankasının karşılığı): derleyiciler arası **0 eşleşme**;
  Debian 9.4 → Debian 13 (9.7) arasında da **0 eşleşme** (GCC sürümü + bayrak farkı; olası neden Debian 13'ün
  AArch64 dal koruması komutları — doğrulanmadı). Aynı derleyici, aynı sürüm (coreutils içi): 1 020 / 2
  (0,998 [0,993–…], kapsam %36,2). H3'ün cevabı: banka derleyici sürümleri arasında genelleşmiyor.
- BSim (var olan `ghidra_bsim.json`; depoda başvuru varsa): yukarıda (Ö8). Aynı derleyici (coreutils içi,
  depoda başvurusu olan yönler): 198 / 19 = 0,912; tek en iyi kapısıyla 193 / 10 = 0,951 [0,912–…].
  Uyarı: BSim sorgusu fonksiyon başına sınırlı sayıda aday döndürür ve depoda başka programlar da vardı;
  kapsam alt sınırdır.

### 5.5 Başka hat için notlar

- **ÖLÇÜ:** tam ad eşitliği, başvuru derlemesi başka sürümse "aynı fonksiyon, yukarı akışta yeniden adlandırılmış"
  durumunu yanlış sayıyor (tmux'ta yanlışların %63'ü). Benzerlik ölçüsü tanımlanırken bu sınıf için mekanik
  doğrulayıcı (kaynak deposundaki yeniden adlandırma geçmişi ya da sürümü eşlenmiş başvuru) düşünülmeli.
- **ÖZ KOD:** nüfusun büyük bir kısmı "çağıransız" (adresi alınan, tablo üstünden çağrılan) fonksiyon:
  Debian htop 184 / 222, Mac htop 217 / 597, Debian tmux 628 / 1 851, Mac tmux 761 / 2 545 (`envanter.json`). Bunlara çağrı grafiğinden
  ulaşılmıyor; veri tablosundaki sıra / komşuluk (kayıt çiftleri) ikisinin de ortak kanıtı olabilir.

### 5.6 Ek ölçümler (a1, OLGU çapraz denetimi, ürünün var olan eşleyicisi)

- `python scripts/arge/kimlik/a1_pay.py --json …/a1_pay.json` (metin `a1_pay.txt`): nüfus 21 371 (taban ölçümüyle
  aynı). Set içi kopya (aynı birimin başka ikilisinde aynı ad + aynı boyut) 13 472 (%63,0); yalnız ad 138;
  aynı programın öbür platform derlemesinde 4 161 (%19,5); set içinde başka kaynağı yok 3 600 (%16,8).
- Ana oturum OLGU ara teslimini bildirdi (`olgu.jsonl.gz`, `SEMA.md`, `BUTCE.md`). Çapraz denetim:
  `python scripts/arge/kimlik/olgu_capraz.py --json …/olgu_capraz.json`. OLGU nüfus satırı 21 371, benim nüfusumla
  birebir (eksik 0). OLGU `gnulib` 11 393 → 11 294'ü bende `kopya_ad_boyut`, 2 `kopya_ad`, 97 `set_ici_yok`
  (tek ikilide geçen gnulib fonksiyonu). OLGU `ucuncu_taraf` 881 → 878 kopya (redis-tools'un 4 ikilisi).
  İki bağımsız sayım tutarlı.
- Kaynak sınıfı başına eşleme (kural noktası, sorgu Debian ELF): coreutils içi `gnulib` 966 / 11 = 0,989
  [0,980–0,994], kapsam %39,5; Debian ↔ Homebrew `gnulib` 129 / 20 = 0,866 [0,802–0,911], %35,4; sürüm
  `gnulib` 208 / 15 = 0,933, %42,6; tmux `program` 1 081 / 72 = 0,938 [0,922–0,950], %61,6; tmux `uyumluluk`
  37 / 4.
- **Ürünün var olan başvuru eşleyicisi** (`karadul/analyzers/bindiff.py` `BinaryDiffer.compare`; ürün
  `reference_binary` ayarıyla bunu çağırıyor: `_feedback_naming_bindiff._config_source`). Ürün kodu
  değiştirilmeden, başvuru adları GT'den yazılarak ölçüldü:
  `python scripts/arge/kimlik/urun_bindiff.py kesif_htop sinama_tmux sinama_cu_mac sinama_cu_ic surum --json …/urun_bindiff.json`.
  tmux, `config` kipi: toplam 328 / 174 = 0,653 [0,611–0,694], kapsam %7,5; yöntem başına `string_refs`
  326 / 16 (0,953), `size_params` 2 / 116 (0,017), `cfg_fingerprint` 0 / 42. `refdb` kipinde `call_pattern`
  91 / 56 (0,619). coreutils ↔ Homebrew: 10 / 154 (0,061). Aynı derleyicide bile toplam 0,744
  (`size_params` 23 / 127). Yani analist bugün `reference_binary` verirse yanlış ad alıyor; öntanımda yol boş
  (`reference_binary = ""`), `~/.cache/karadul/ref_db` yoksa çalışmıyor.
  Not: P-S3 / P-S3b Mach-O ve korpus koşularında `ghidra_strings.json` dizgi → fonksiyon bağı taşımadığı için
  `string_refs` o çiftlerde 0 eşleşme veriyor (koşu kuşağı farkı; yöntemin kendisi değil).

### 5.7 Ana oturumun yönergesi (2026-11-19): "zaman kısıtı yok, bütün kalemleri eksiksiz ölç"

Bu yüzden aşağıdaki ek ölçümler yapılacak. Kurallar sayılardan önce yazıldı:

1. **Var olan öbür ürün eşleyicisi** (`reference_differ.ReferenceDiffer.match_direct`) aynı çiftlerde çıplak ölçülür.
2. **Aynı derleyici birleşimi (coreutils içi, taze çiftler).** İlk seçimde kullanılmayan çiftler: ada göre
   sıralı listede 5, 15, …, 95. indisli ikili sorgu, bir sonraki ikili başvuru (10 çift, iki yön). Ölçülecekler:
   (a) dondurulmuş kural noktası; (b) `cfg_komut` tekil eşleşmesi; (c) birleşim: ikisi aynı fonksiyon için
   farklı başvuru fonksiyonu gösteriyorsa ad verilmez, biri susuyorsa öbürü geçerli. Parametre yok.
   Ön kayıt: birleşimin kesinliği Wilson alt ≥ 0,95; kapsamı (a) ve (b)'nin her birinden büyük.
3. **Çok başvurulu gnulib** (A2'nin asıl sorusu: 11 393 gnulib kopyasının ne kadarı başka ikiliden tanınır):
   aynı 10 taze sorgu için başvuru = listede sorgudan sonraki 5 ikili (dairesel). Her başvuruyla (c) birleşimi
   ayrı koşulur; fonksiyon başına öneriler oylanır: bütün öneren başvurular aynı adı veriyorsa ad, çelişki
   varsa ad yok. Kaynak sınıfı (OLGU) başına raporlanır. Ön kayıt: `gnulib` sınıfında kesinlik Wilson alt
   ≥ 0,95 ve kapsam ≥ %60.
4. **Tablo yuvası kanıtı (çağıransız fonksiyonlar için).** İkilinin veri bölümlerindeki işaretçi yuvaları
   (ELF `R_AARCH64_RELATIVE`, Mach-O zincirli düzeltmeler; `lief` ile, Ghidra koşusu yok) okunur. Yeni kanıt
   türleri: aynı kayıtta (yuva penceresi içinde) duran dizgi ve eşlenmiş fonksiyon, göreli yuva farkıyla.
   Parametreler (pencere, çarpan) **yalnız htop'ta** ayarlanır. tmux ve coreutils ↔ Homebrew artık kör değil
   (v1 sayıları ve hata sınıfları görüldü); bu yüzden v2'nin oradaki sayıları **"ikinci bakış"** etiketiyle
   yazılır, ön kayıtlı sınama sayılmaz. Bağımsız sınama taze çift ister (PLAN, veri isteği).
5. **Satır içi kapısı (keşif).** Kabul edilen eşlemede kanıt kapsaması tek yönlüyse (q'nun kanıtı r'de var,
   r'nin kanıtının çoğu q'da yok) ad yerine kanıt satırı. Eşik htop'ta ayarlanır; tmux / coreutils ↔ Homebrew
   sayıları yine "ikinci bakış".

### 5.8 Ek ölçüm sonuçları (§5.7'deki kurallarla)

**1. `ReferenceDiffer.match_direct`** (`urun_bindiff.py`, kip `refdiffer`; `urun_bindiff.txt`): tmux toplam
366 / 769 = 0,322 [0,296–0,350]; `cfg_similarity` 58 / 725 (0,074), `string_fingerprint` 304 / 12 (0,962),
`size_constant` 0 / 24. Aynı derleyicide (coreutils içi) toplam 1 197 / 185 = 0,866.

**2–3. Aynı derleyici, taze çiftler** (`python scripts/arge/kimlik/ayni_derleyici.py --json …/ayni_derleyici.json`):
- Tek başvuru (10 çift × 2 yön, nüfus 2 552): yayılım 964 / 14 = 0,986 [0,976–0,992], kapsam %37,8;
  `cfg_komut` 930 / 0 = 1,000 [0,996–1], %36,4; **birleşim 1 217 / 11 = 0,991 [0,984–0,995], kapsam %47,7**;
  çelişen 3. Ön kayıt (Wilson alt ≥ 0,95; kapsam ikisinden büyük) → **tuttu**.
- Çok başvuru (5 ikili; 10 sorgu): `gnulib` 660 / 9 = 0,987 [0,975–0,993], kapsam 660 / 1 180 = %55,9
  (tavan 1 027), çelişki 6; `program` 23 / 2; toplam 686 / 11, %52,7. Ön kayıt: kesinlik **tuttu**,
  kapsam ≥ %60 **tutmadı** (%55,9).

**4. Tablo yuvası kanıtı (v2).** `veri.isaretci_yuvalari` / `yuva_komsulari` (lief; Ghidra yok). htop'ta
çağıransız nüfusun yuvası olanı: Debian 127 / 184, Mac 133 / 217 (`python scripts/arge/kimlik/veri.py debian/htop mac/htop`).
Kalanı kod içinden adresi alınanlar (geri çağrı argümanı); yer değiştirme tablosunda görünmez, Ghidra'nın
veri / kod xref dökümü ister (bugünkü `ghidra_xrefs.json`'da yok).
- htop ayarı (pencere 2 / 4 / 8 / 16 × çarpanlar; tek seferlik ızgara, çıktısı bu defterde): v1 515 / 16 →
  pencere 8, t 0,5, k 1,0: 583 / 19 (kesinlik 0,968, Wilson alt 0,951, kapsam %71,2). Aynı seçim kuralı
  (alt ≥ 0,95 içinde en yüksek kapsam). Yalnız `k` (eşlenmiş tablo komşusu) 582 / 18; yalnız `t` (kayıttaki
  dizgi) katkı vermiyor (535 / 18): htop'ta kazanç tablo komşuluğundan geliyor.
- Dondurulan v2 noktaları: `esle.DONUK_V2` (kural + t, k) ve `DONUK_V2_TUTUCU` (kütle 1,0).
- v2, bütün gruplar (`python scripts/arge/kimlik/yayilim_olc.py kesif_htop sinama_tmux sinama_cu_mac sinama_cu_ic surum derleme --json …/yayilim_v2_hepsi.json`;
  v1 satırları öncekiyle birebir aynı çıktı → belirlenimcilik denetimi). **İkinci bakış** (ön kayıtlı sınama değil):
  - tmux kural_v2: 2 566 / 172 = 0,937 [0,927–0,946], kapsam %58,4 (tavanın %74,0'ı); v1'e göre +290 doğru,
    +14 yanlış. Debian → Mac yönünde kapsam %60,4 → %68,2. tutucu_v2: 2 420 / 152 = 0,941, %55,0.
  - coreutils ↔ Homebrew kural_v2: 310 / 51 (v1 316 / 47): kazanç yok, hafif kayıp (coreutils'te tablo az).
  - coreutils içi, sürüm, derleme: değişim yok ya da ±4.
  - Hata dökümü (`hata_dok_kural_v2.txt`): tmux 172 yanlış = tek taraflı 99 + satır içi 28 + komşu 15 +
    aile 23 + diğer 7; tavan içi kesinlik 2 566 / 2 611 = 0,983 [0,977–0,987]. Tablo kanıtı "aile" türü
    yanlışı artırıyor (10 → 23): aynı tablonun komşu yuvaları birbirine karışıyor.

**5. Satır içi kapısı (keşif) — OLUMSUZ.** `python scripts/arge/kimlik/satir_ici.py kesif_htop sinama_tmux sinama_cu_mac derleme --nokta kural --json …/satir_ici_kural.json`.
Kanıt kütlesi dengesi (`Esleme.denge`) satır içi türü yanlışları seçmiyor:
- htop: denge ≥ 0,5 kapısı 14 doğru düşürüp 4 yanlış kaldırıyor (satır içi türü 1 / 9); ≥ 0,6: 34 doğruya
  karşı 6 yanlış (2 / 9). Hiçbir eşikte kabul edilebilir takas yok → eşik seçilmedi.
- tmux (ikinci bakış): ≥ 0,5: 83 doğruya karşı 20 yanlış (satır içi türü 5 / 42); derleme (LTO): ≥ 0,6:
  20 doğruya karşı 13 yanlış (11 / 21). LTO çiftinde bir miktar işe yarıyor, derleyiciler arasında yaramıyor.
- Neden olmadı: satır içine alınan fonksiyon çoğu kez küçük; içeren fonksiyonun kanıt kütlesini belirgin
  değiştirmiyor. Kütle oranı yerine yapısal tanık gerekir (PLAN: "iki adımlı çağrı tanığı", açık ölçüm).

**İkiz ayırma (H3'ün sorusu; aynı derleyici, taze çiftler; `ayni_derleyici.txt`):** CFG yapısı + komut kümesi
aynı olduğu için CFG-iso'nun ayıramadığı nüfus fonksiyonu 508 (nüfusun %19,9'u, 2 552'de). Sabit + çağrılan
kimliği taşıyan yayılım bunların yalnız 69'una ad veriyor (66 doğru, 0,957 [0,880–0,985]); 394'ü ad ailesi
(küme) düzeyinde kalıyor, isabet 385 / 394 = 0,977 [0,957–0,988]; 45'i sessiz. Yani işlenen bilgisi ikizlerin
%13,6'sını ayırıyor; çoğu için dürüst cevap ad ailesi.

**Eğriler (kalem 3; `yayilim_sinama_tmux.json`, `yayilim_egri_coreutils.txt`):** T × kütle ızgarasında tmux'ta
hiçbir nokta Wilson alt 0,95'e çıkmıyor (en iyi T 0,7 / kütle 0,5: 1 285 / 64 = 0,953, alt 0,940, kapsam
%29,2): kalan yanlışların 54'ü tekil dizgi çapasından, eşik onlara dokunmuyor. coreutils ↔ Homebrew'da en iyi
nokta 0,912 (alt 0,821). coreutils içinde her nokta ≥ 0,987.

**6. Temiz BSim koşuları (kalem 2'nin eksiği).** Taban koşusunun BSim deposunda başka programlar da vardı ve
Debian → Mac yönü yoktu (Debian önce koşulmuştu). `scripts/arge/kimlik/kos_bsim.sh`: depo başına yalnız iki
ikili (önce başvuru, sonra sorgu), ürün ağacı ve komut taban koşusuyla aynı, sıralı (aynı anda tek Ghidra
koşum; makinede başka oturumun `karadul analyze` koşuları da vardı, 2 dk beklenip başlandı). Sayım:
`python scripts/arge/kimlik/bsim_temiz.py --json …/bsim_temiz.json`. Sonuç aşağıda (koşular bitince).

### 5.9 Yalnız derleyici farkı: aynı sürümün GCC derlemesi (ön kayıt; ölçümden ÖNCE yazıldı)

Öncül 3'ü ve "sürümü eşlenmiş başvuruyla 0,95 tutar mı" sorusunu temiz ayırmak için aynı sürümün iki derleyiciyle
derlemesi gerekiyordu. Diskte var: tmux 3.8 ve htop 3.5.3 kaynak ağaçları
(`workspaces/2026-10-15_oturum_scratchpad/src/`; Homebrew şişeleriyle aynı sürüm), Homebrew GCC 16.2.0
(`/opt/homebrew/bin/gcc-16`), libevent / ncurses / utf8proc kurulu. İndirme yok.

- **Yapılacak:** kaynaklar `~/karadul_olcum/runs/arge-2026-11-19/kimlik/gcc/src/`'ye kopyalanır (özgün ağaçta
  derleme yok), `CC=gcc-16 CFLAGS=-O2` ile derlenir (`scripts/arge/kimlik/derle_gcc.sh`); `/usr/bin/strip` ile
  soyulur, GT sembollü ikilinin `nm` çıktısından (`scripts/measurement/macho_measure.py prepare`, kendi korpus
  dosyam ve veri dizinimle); ürün koşusu taban komutuyla, sıralı (`kos_gcc.sh`). Kimlik: `macgcc/tmux`, `macgcc/htop`.
- **Gruplar** (`ciftler.py`):
  - `derleyici` = (macgcc/tmux ↔ mac/tmux): aynı kaynak sürümü (3.8), aynı platform (Mach-O arm64), GCC 16 ↔ Apple clang.
  - `derleyici_htop` = (macgcc/htop ↔ mac/htop): aynısı htop 3.5.3 (htop ayar programıydı; ayrı satır).
  - `surum_gcc` = (debian/tmux ↔ macgcc/tmux): aynı derleyici ailesi (GCC 14 ↔ 16), sürüm 3.5a ↔ 3.8 ve platform farkı.
- **Dondurulmuş noktalar:** `esle.NOKTALAR`'ın dördü de (kural, tutucu, kural_v2, tutucu_v2); hiçbir parametre değişmez.
  Bu çiftler hiç görülmedi → **ön kayıtlı sınama** (v2 için de: v2 htop'ta ayarlandı, bu ikililer yeni).
- **Hipotezler ve eşikler:**

| # | Beklenti | Tuttu / tutmadı |
|---|---|---|
| G1 | `derleyici` (tmux 3.8, GCC ↔ clang), v1 kural: tam ad kesinliğinin Wilson alt sınırı ≥ 0,95 (sürüm eşlenince yeniden adlandırma sınıfı kalkar) | alt ≥ 0,95 → tuttu |
| G2 | Aynı çiftte "tek taraflı" (yeniden adlandırma adayı) yanlış sayısı ≤ 10 (sürüm farklıyken 99'du) | ≤ 10 → "tek taraflı sınıf sürüm kaynaklı" okuması tuttu |
| G3 | Aynı çiftte satır içi + komşu türü yanlış > 0 kalır (derleyici farkının kendi bedeli); sayı raporlanır | > 0 → tuttu |
| G4 | v1 kural kapsamı (doğru / nüfus) ≥ %50 | ≥ %50 → tuttu |
| G5 | `surum_gcc` çiftinde (aynı derleyici ailesi, sürüm farkı) satır içi + komşu türü yanlış, `sinama_tmux`'takinden (42) az | < 42 → tuttu |
| G6 | v2 kural, `derleyici`: kapsam v1'den büyük, kesinlik Wilson alt ≥ 0,95 | ikisi de → tuttu |
| G7 | Ad ailesi küme isabeti, `derleyici`, v1 kural: Wilson alt ≥ 0,95 | → tuttu / tutmadı |

- Derleme başarısız olursa (GCC + macOS başlıkları) ya da yapılandırma Homebrew şişesinden farklı özellik kümesi
  veriyorsa bu deftere yazılır; ölçüm "açık" kalır. Derleme seçenekleri Homebrew formülüne yaklaştırılır
  (tmux: `--enable-utf8proc --enable-sixel`); fark fonksiyon kümesinde görünürse envanter satırında raporlanır.

### 5.10 Ek koşular: aynı kuşak coreutils ↔ Homebrew ve sembollü başvuru (ön kayıt; ölçümden ÖNCE)

- **Neden:** (i) coreutils ↔ Homebrew çiftlerinde Mach-O tarafı eski kuşak koşu (dizgi → fonksiyon bağı yalnız
  `ghidra_xrefs.json`'dan); dizgi kanıtı iki tarafta eşit zenginlikte değil. (ii) Bu turda başvuru da soyulmuş
  analiz edildi; gerçekte başvuru sembollü analiz edilir.
- **Koşular** (`scripts/arge/kimlik/kos_ek.sh`; ürün ağacı a62f15e, taban komutu; BSim ve GCC koşularından sonra,
  sıralı): gcat, gsort, gmktemp (kimlik `macgnu2/<ad>`); Mac tmux 3.8'in sembollü özgün ikilisi (kimlik
  `macsym/tmux`; yalnız başvuru olarak; GT adresleri soyulmuş kopyayla aynı, özgün sha256 denetlenir).
- **Ölçümler ve beklentiler** (dondurulmuş noktalar; parametre değişmez):
  - `sinama_cu_mac2` (aynı kuşak): E1: kapsam (kural) eski kuşaktaki %32,6'dan büyük. E2: tam ad kesinliği
    raporlanır; eşik yok (sürüm farkı 9.7 ↔ 9.12 sürüyor). coreutils ↔ Homebrew çifti artık kör değil;
    bu "ikinci bakış"tır.
  - Sembollü başvuru (Debian tmux → `macsym/tmux`; ayrıca `macgcc/tmux` → `macsym/tmux`): E3: doğru sayısı
    soyulmuş başvuruyla elde edilenin ±%5'i içinde; E4: kesinliklerin Wilson aralıkları örtüşür. Tutmazsa
    "başvurunun soyulmuş analizi tutucu bir vekildir" varsayımı geri çekilir ve PK-4'ün beklentisi düzeltilir.
- Ayrıca: `tek_tarafli_kaynak.py` (ölçüldü): tmux'un 52 tek taraflı çiftinin 47'sinde eski ad 3.8 kaynağında hiç
  geçmiyor ve yeni ad orada fonksiyon tanımı (yeniden adlandırmayla tutarlı); 5'inde eski ad 3.8 kaynağında hâlâ
  var (`cmd_resize_pane_mouse_update`, `grid_reflow_move`, `tty_keys_find1` …: yeniden adlandırma değil, satır içi
  / başka fonksiyon). 3.5a kaynağı diskte olmadığı için ters yön denetlenemedi.

### 5.11 İyileştirme düzeyi etkisi (A4'ün üçüncü etkeni; ön kayıt, ölçümden ÖNCE)

- **Yapılacak:** tmux 3.8, GCC 16, `-O0` ve `-O3` (`scripts/arge/kimlik/derle_gcc_duzey.sh`); GT ve soyma §5.9'daki
  gibi (`macho_measure.py prepare`, korpus adları `tmuxO0`, `tmuxO3`); ürün koşusu `kos_duzey.sh` (öbür koşulardan
  sonra, sıralı). Kimlik `macgcc/tmuxO0`, `macgcc/tmuxO3`.
- **Grup `iyilestirme`:** (macgcc/tmuxO0 ↔ macgcc/tmux), (macgcc/tmuxO3 ↔ macgcc/tmux): aynı kaynak sürümü, aynı
  derleyici, yalnız iyileştirme düzeyi farklı. Dondurulmuş dört nokta; hiç görülmemiş ikililer → ön kayıtlı sınama.
- **Beklentiler:** I1: `-O3` ↔ `-O2`, v1 kural: tam ad kesinliği Wilson alt ≥ 0,95. I2: `-O0` ↔ `-O2`: satır içi +
  komşu türü yanlış sayısı `-O3` ↔ `-O2`'dekinden fazla (`-O0` hiçbir şeyi satır içine almaz). I3: `-O0` ↔ `-O2`
  kesinliği raporlanır; eşik: Wilson alt ≥ 0,909 → "ad yazabilir". I4: iki çiftte de "tek taraflı" yanlış ≤ 10
  (sürüm aynı).
- ÖLÇÜ hattının P-Ö6'sı (clang, altı düzey) aynı etkeni ürün kanalları için ölçecek; buradaki ölçüm kimlik
  eşlemesi içindir ve GCC iledir. Çakışma yok; PK-6 P-Ö6 verisini clang tarafı için ayrıca kullanır.

### 5.12 Belirlenimcilik denetimi

- Eşleyicideki kanıt ağırlığı toplamları küme dolaşım sırasına bağlıydı (kayan nokta toplama sırası). `math.fsum`'a
  çevrildi (sıradan bağımsız, tam yuvarlanmış). Altı grubun dört noktadaki çıktısı öncekiyle birebir aynı
  (`yayilim_v2_hepsi.txt` ↔ `yayilim_v2_hepsi_fsum.txt`, süre sütunu dışında fark 0); `PYTHONHASHSEED=1` ile htop ve
  tmux çıktısı da aynı (`yayilim_tohum1.txt`). Ürüne taşırken aynı kural (PLAN PK-2 adım 5).

### 5.13 Koşu kuyruğu ve sapma: `--stage static`

- Makine yükü çok yüksek (12:00'de yük ortalaması ~40; başka oturumların koşuları). Tam ürün koşusu tmux için
  15+ dk sürüyor; eşleyici yalnız `static/` çıktılarını (Ghidra aşaması) okuyor.
- **Sapma (ölçüm sonucu görülmeden):** §5.9–§5.11'deki ek koşular tam boru hattı yerine `--stage static` ile
  koşuluyor (`scripts/arge/kimlik/kos_kuyruk.sh`; `kos_gcc.sh`, `kos_ek.sh`, `kos_duzey.sh` bekleme döngüsündeyken,
  hiçbir koşu başlatmadan durduruldu; dosyaları duruyor ama kullanılmadı). Temiz BSim koşuları (`kos_bsim.sh`)
  tam boru hattıyla sürüyor (başlamıştı; dokunulmadı).
- **Denetim:** kuyruğun ilk adımı Debian htop'un `--stage static` koşusu; `static/` dosyaları taban koşusununkilerle
  karşılaştırılır (eşleyicinin okuduğu altı dosya: fonksiyon, çağrı grafiği, dizgi, xref, CFG, `pcode.jsonl`).
  Fark çıkarsa ek koşuların sayıları "tam koşuyla aynı değil" notuyla yazılır.
- Sıra önemine göre: GCC tmux (§5.9) → GCC htop → sembollü Mac tmux (§5.10) → `-O3`, `-O0` (§5.11) →
  Homebrew coreutils üçlüsü (§5.10).

### 5.14 Temiz BSim kuyruğunun yeniden düzenlenmesi

- `kos_bsim.sh`: htop depoları (4 koşu) ve tmux_md'nin ilk adımı (Mac tmux; 1 479 sn, çıkış 0) tam boru hattıyla
  bitti. Makine yükü (~35–40) yüzünden tmux tam koşusu 25 dk sürdü; kalan üç tmux koşusu en önemli ölçümü
  (§5.9) bir saatten fazla geciktirecekti. `kos_bsim.sh` bu noktada durduruldu (ikinci adımın dizini boş açılmıştı,
  koşu başlamamıştı).
- Kalan üç BSim koşusu `scripts/arge/kimlik/kos_bsim2.sh` ile, `--stage static` ile ve §5.13 kuyruğundan SONRA
  koşulur (BSim eklemesi ve sorgusu statik aşamada; `ghidra_bsim.json` o aşamada yazılıyor: tmux_md/1_mac'te
  `ingested_functions` 2 588, `known_executables` 1).
- Tam koşu ↔ taban koşusu statik çıktı denetimi (`python scripts/arge/kimlik/static_denetim.py debian/htop K/bsim/htop_md/2_debian`,
  çıktı `K/static_denetim_tam_kosu.txt`): `ghidra_call_graph.json`, `ghidra_xrefs.json` ve `pcode.jsonl` dosya
  düzeyinde farklı (bilinen döküm sırası sorunu, P16d), ama eşleyicinin okuduğu olgu 609 fonksiyonun 609'unda
  aynı (fark 0). Yükleyici sıradan bağımsız (kümeler).

### 5.15 Sonuç: yalnız derleyici farkı (§5.9'un ön kayıtlı sınaması)

- Derleme: `bash scripts/arge/kimlik/derle_gcc.sh` (tmux 3.8 ve htop 3.5.3, GCC 16.2.0 `-O2`; ikisi de çıkış 0).
  GT: tmux 2 422 fonksiyon (clang şişesi 2 572), htop 597. Koşu: `kos_kuyruk.sh` (`--stage static`; tmux 457 sn,
  htop 101 sn). `--stage static` denetimi: Debian htop'ta eşleyicinin okuduğu olgu taban koşusuyla 609 / 609 aynı
  (`K/static_denetim_static_asama.txt`).
- Komut: `python scripts/arge/kimlik/yayilim_olc.py derleyici surum_gcc --egri --json K/yayilim_gcc_tmux.json`;
  tam küme `bash scripts/arge/kimlik/son_olcum.sh gcc` (`K/yayilim_gcc.*`, `K/hata_gcc_<nokta>.*`, `K/ciplak_gcc.*`,
  `K/envanter_gcc.*`).
- **`derleyici` (tmux 3.8, GCC 16 ↔ Apple clang; aynı sürüm, aynı platform), iki yön havuzlu:**

| Nokta | Doğru / yanlış | Kesinlik [Wilson] | Kapsam |
|---|---|---|---|
| kural (v1) | 3 908 / 38 | 0,990 [0,987–…] | 3 908 / 4 880 = %80,1 |
| tutucu (v1) | 3 709 / 28 | 0,993 [0,989–…] | %76,0 |
| kural_v2 | 4 281 / 36 | 0,992 [0,989–…] | %87,7 |
| tutucu_v2 | 4 170 / 26 | 0,994 [0,991–…] | %85,5 |

  Tekil dizgi çapası 1 085 / 0. Ad ailesi küme isabeti (kural) 271 / 288 = 0,941 [0,907–0,963].
- **`surum_gcc` (Debian tmux 3.5a GCC 14 ↔ Mac tmux 3.8 GCC 16):** kural 2 369 / 150 = 0,940 [0,930–…], kapsam %56,6;
  tekil dizgi çapası 745 / 54.
- **Hükümler:** G1 (derleyici, v1 kural, Wilson alt ≥ 0,95) → **TUTTU** (0,987). G4 (kapsam ≥ %50) → **tuttu** (%80,1).
  G6 (v2: kapsam v1'den büyük ve alt ≥ 0,95) → **tuttu** (%87,7; 0,989): v2'nin ilk bağımsız sınaması.
  G7 (ad ailesi küme isabeti alt ≥ 0,95) → **tutmadı** (0,907). G2, G3, G5 hata dökümünden (aşağıda).
- **Okuma:** aykırı öncül 1, başvuru **aynı sürümse** derleyici farkına rağmen tutuyor (GCC ↔ clang, 0,990, kapsam
  %80–88). Sürüm farklıysa derleyici ailesi aynı olsa bile (GCC 14 ↔ GCC 16) 0,940'ta kalıyor: tam ad kesinliğini
  bozan etken sürüm. Tekil dizgi çapasının yanlışları (tmux'ta 54) sürüm eşlenince 0'a iniyor: onlar satır içi
  değil, sürüm kaynaklıymış.
- Hata dökümü (kural; `K/hata_gcc_kural.txt`):

| Çift | Yanlış | tek taraflı | satır içi | komşu | aile | diğer |
|---|---|---|---|---|---|---|
| `derleyici` (tmux 3.8, GCC ↔ clang) | 38 | 4 | 13 | 16 | 3 | 2 |
| `surum_gcc` (tmux 3.5a GCC 14 ↔ 3.8 GCC 16) | 150 | 105 | 20 | 9 | 7 | 9 |
| `sinama_tmux` (3.5a GCC 14 ↔ 3.8 clang; önceki) | 158 | 99 | 25 | 17 | 10 | 7 |
| `derleyici_htop` (htop 3.5.3, GCC ↔ clang) | 16 | 0 | 6 | 6 | 1 | 3 |

- G2 (tek taraflı ≤ 10) → **tuttu** (4; sürüm farklıyken 99–105): "tek taraflı sınıf sürüm kaynaklıdır" okuması
  bağımsız veride doğrulandı. G3 (satır içi + komşu > 0) → **tuttu** (29). G5 (`surum_gcc`'de satır içi + komşu < 42)
  → **tuttu** (29).
- `derleyici_htop` (htop ayar programıydı; ikili yeni): kural 972 / 16 = 0,984 [0,974–…], kapsam %82,4; kural_v2
  1 070 / 17 = 0,984 [0,975–…], %90,8.
- **Öncül 3'ün temiz cevabı (tmux, kural):** aynı sürüm + GCC ↔ clang: 0,990, kapsam %80,1, yanlış 38.
  Sürüm farkı + aynı derleyici ailesi: 0,940, %56,6, yanlış 150. İkisi birden: 0,935, %51,8, yanlış 158.
  Sürüm farkı ~100 yeniden adlandırma yanlışı ve ~25 puan kapsam kaybı getiriyor; derleyici farkı ~29 satır içi
  türü yanlış. **Sürüm farkı derleyici farkından pahalı** (hat metnindeki "ya da tersi" değil).
- Çıplak ölçüm aynı çiftte (`K/ciplak_gcc.txt`): tekil dizgi 1 085 / 0; CFG yapısı tekil 48 / 24; CFG + komut
  kümesi 54 / 2 (kapsam %1,1): aynı sürümde bile GCC ↔ clang arasında CFG bankası neredeyse hiç eşleşmiyor.

### 5.16 Sonuç: sembollü başvuru (§5.10 E3, E4)

- Koşu: `ek/macsym/tmux` (Mac tmux 3.8 özgün, sembollü; `--stage static`, 291 sn). Ghidra sembollü ikilide 2 579
  fonksiyon buluyor (soyulmuşta 2 588), 2 562'sinin adı Ghidra'da hazır.
- Komut: `python scripts/arge/kimlik/yayilim_olc.py sembollu --json K/yayilim_sembollu.json` (`.txt`).

| Sorgu → başvuru | Nokta | Soyulmuş başvuru (adlar GT'den) | Sembollü başvuru |
|---|---|---|---|
| Debian tmux → Mac tmux | kural | 1 118 / 76 | 1 121 / 76 |
| | tutucu | 1 001 / 63 | 1 003 / 63 |
| | kural_v2 | 1 263 / 83 | 1 267 / 83 |
| GCC tmux → Mac tmux | kural | 1 919 / 17 | 1 919 / 18 |
| | tutucu_v2 | 2 050 / 11 | 2 055 / 11 |

- E3 (doğru sayısı ±%5 içinde) → **tuttu** (fark en çok +5 doğru, %0,4). E4 (kesinlik aralıkları örtüşür) → **tuttu**.
  Bu turda başvurunun soyulmuş analizini kullanmak sonuçları değiştirmedi; PK-4'ün ürün ölçümü için beklenti aynı
  sayılardır.

### 5.17 Satır içi tanığı ("çağıranın çağrılanı") — keşif; sonra dondurulmuş sınama

- Sürüm eşlenince kalan yanlışların çoğu satır içi türü (`derleyici`: 29 / 38). Kütle dengesi kapısı tutmamıştı
  (§5.8 madde 5). İkinci deneme, yapısal tanık (`scripts/arge/kimlik/tanik.py`):
  K1: q'nun bir çağıranının çağırıp q'nun çağırmadığı eşlenmiş bir fonksiyonu r çağırıyor; K2: simetriği.
  Tanığı olan eşlemeye ad verilmez. Tek parametre `kmax` (tanık sayılan fonksiyonun en çok çağıran sayısı).
- **Keşif** (hepsi daha önce görülmüş gruplar; `python scripts/arge/kimlik/tanik.py kesif_htop sinama_tmux sinama_cu_mac derleme derleyici derleyici_htop surum_gcc --nokta kural --json K/tanik_kesif_kural.json`):
  - htop (ayar çifti): `kmax` 1–5 hiçbir yanlışı düşürmüyor; `kmax` ∞ (süzgeçsiz): 8 doğru, 5 yanlış düşüyor
    (satır içi türü 3 / 9). Seyreklik süzgeci zararlı → `kmax` = ∞ seçildi (htop'ta).
  - `derleyici` (tmux 3.8, GCC ↔ clang): 139 doğru, 21 yanlış düşüyor (satır içi türü 19 / 29); kalan
    3 769 / 17 = 0,996 [0,993–0,997], kapsam %80,1 → %77,2. `derleyici_htop`: 16 doğru, 8 yanlış (8 / 12).
  - Sürüm farklı çiftlerde zayıf: tmux 148 doğruya karşı 21 yanlış (16 / 42); coreutils ↔ Homebrew 13 doğru, 0 yanlış.
- **Keşifteki okuma:** tanık satır içi türü yanlışların üçte ikisini buluyor (sürüm eşliyken) ama düşürdüklerinin
  %87'si doğru (139 / 160): kapı olarak pahalı. PLAN'da yazdığım eşikler (düşenlerde yanlış oranı ≥ %50; düşen
  doğru / düşen yanlış ≤ 1,0) keşifte bile tutmuyor (oran 6,6). Tanığı taşıyan eşlemelerde yanlış oranı %13,
  taşımayanlarda %0,4 (17 / 3 786): **kapı değil, şüphe işareti** olarak anlamlı.
- **Dondurulan:** `kmax` = ∞, nokta kural. **Sınama (ön kayıt):** `iyilestirme_o0`, `iyilestirme_o3` (koşuları
  sürüyor; hiç görülmedi). T1: tanığı taşıyan eşlemelerde yanlış oranı, taşımayanlardakinin ≥ 5 katı (işaret
  ayırt edici). T2: düşen doğru / düşen yanlış ≤ 1,0 (kapı olarak kullanılabilir) — keşfe göre tutması beklenmiyor.
  T3: satır içi türü yanlışların ≥ %50'si tanığı taşıyor.

### 5.18 Sonuç: iyileştirme düzeyi (§5.11), tanığın dondurulmuş sınaması (§5.17), aynı kuşak coreutils (§5.10)

- Derleme: `bash scripts/arge/kimlik/derle_gcc_duzey.sh` (tmux 3.8, GCC 16, `-O0` 3 265 fonksiyon, `-O3` 2 335; `-O2` 2 422).
  Koşular `kos_kuyruk.sh` (`-O3` 319 sn, `-O0` 312 sn). Ölçüm: `bash scripts/arge/kimlik/son_olcum.sh duzey` →
  `K/envanter_duzey.*`, `K/yayilim_duzey.*`, `K/hata_duzey_<nokta>.*`, `K/ciplak_duzey.*`.

| Çift (aynı sürüm, aynı derleyici) | Nokta | Doğru / yanlış | Kesinlik | Kapsam | tek taraflı / satır içi / komşu / aile / diğer |
|---|---|---|---|---|---|
| `-O3` ↔ `-O2` (nüfus 4 582) | kural | 3 575 / 68 | 0,981 [0,976–0,985] | %78,0 | 10 / 19 / 31 / 6 / 2 |
| | kural_v2 | 3 980 / 67 | 0,983 [0,979–…] | %86,9 | 10 / 17 / 31 / 7 / 2 |
| `-O0` ↔ `-O2` (nüfus 5 600) | kural | 3 547 / 110 | 0,970 [0,964–…] | %63,3 | 0 / 48 / 45 / 16 / 1 |
| | kural_v2 | 3 943 / 98 | 0,976 [0,971–…] | %70,4 | 0 / 42 / 37 / 18 / 1 |

- Hükümler: I1 (`-O3` ↔ `-O2`, alt ≥ 0,95) → **tuttu** (0,976). I2 (`-O0` çiftinde satır içi + komşu daha çok) →
  **tuttu** (93 ↔ 50). I3 (`-O0` ↔ `-O2`, alt ≥ 0,909) → **tuttu** (0,964; 0,95'i de geçiyor). I4 (tek taraflı ≤ 10) →
  **tuttu** (10 ve 0). Not: aynı sürümde de 10 "tek taraflı" çıkabiliyor (iki tarafta farklı fonksiyonların satır
  içine alınması); sınıf yalnız yeniden adlandırma değil, taban düzeyi ~0–10.
- Çıplak yöntemler aynı çiftlerde (`K/ciplak_duzey.txt`; GCC önbelleğindeki BSim deposunda `-O2` derlemesi vardı):
  `-O3` ↔ `-O2`: CFG + komut kümesi 1 216 / 2 (kapsam %26,5), BSim ≥ 0,7: 1 328 / 365 = 0,784, tek en iyi kapısıyla
  1 219 / 37 = 0,971; `-O0` ↔ `-O2`: CFG + komut 0 eşleşme, BSim 293 / 202 = 0,592. İyileştirme düzeyi değişince
  CFG bankası ve BSim çöküyor; çapalı yayılım 0,970'te kalıyor.
- **Tanık, dondurulmuş (`kmax` ∞; `python scripts/arge/kimlik/tanik.py iyilestirme_o3 iyilestirme_o0 … --nokta kural --kmax 1000000000 --json K/tanik_sinama_kural.json`):**
  `-O3` çifti: 197 doğru, 36 yanlış düşüyor (satır içi türü 31 / 50); kalan 3 378 / 32 = 0,991 [0,987–0,993].
  `-O0` çifti: 243 doğru, 53 yanlış (48 / 93); kalan 3 304 / 57 = 0,983 [0,978–0,987].
  T1 (tanıklılarda yanlış oranı, tanıksızlardakinin ≥ 5 katı) → **tuttu** (%15,5 ↔ %0,9; %17,9 ↔ %1,7).
  T2 (düşen doğru / düşen yanlış ≤ 1,0) → **tutmadı** (5,5 ve 4,6). T3 (satır içi türünün ≥ %50'si tanıklı) →
  **tuttu** (%62, %52).
  Tanığı taşıyan eşlemelerin ("tanıklı alt kanal") kesinliği: `-O3` 0,845 [0,793–0,886], `-O0` 0,821 [0,773–0,860],
  `derleyici` 0,869 [0,808–0,912], tmux (sürüm farklı) 0,876 [0,818–0,917]: her çiftte Wilson alt < 0,909 →
  karar kuralına (A-2) göre bu alt kanal ad değil kanıt satırı yazmalı. Tutucu_v2 noktasında aynı tablo:
  `K/tanik_sinama_tutucu_v2.txt` (ör. `derleyici` 4 170 / 26 → tanıksız 4 035 / 13 = 0,997 [0,995–0,998], kapsam
  %85,5 → %82,7; tanıklı alt kanal 0,912 [0,856–0,948]).
- **Aynı kuşak coreutils ↔ Homebrew** (`ek/macgnu2/*`; `python scripts/arge/kimlik/yayilim_olc.py sinama_cu_mac2 --json K/yayilim_cu_mac2.json`):
  kural 316 / 47, kural_v2 310 / 51: eski kuşak koşularla **birebir aynı**. E1 (kapsam %32,6'dan büyük) → **tutmadı**.
  Koşu kuşağı farkı bu çiftlerin sayısını etkilemiyormuş (dizgi kanıtı `ghidra_xrefs.json`'dan zaten tamdı);
  düşük kesinliğin nedeni sürüm farkı (9.7 ↔ 9.12; yanlışların 30 / 47'si tek taraflı) ve küçük kanıt.
  Ürünün `BinaryDiffer`'ı aynı kuşakta: 18 / 157 (`string_refs` 10 / 0; `K/urun_bindiff_cu_mac2.txt`).

### 5.19 Sonuç: temiz BSim (§5.8 madde 6, §5.14)

- Koşular: `kos_bsim.sh` (htop_md, htop_dm, tmux_md/1_mac; tam boru hattı) + `kos_bsim2.sh` (tmux_md/2_debian 163 sn,
  tmux_dm/1_debian 161 sn, tmux_dm/2_mac 256 sn; `--stage static`). Hepsi çıkış 0; her depoda `known_executables` 2.
- `python scripts/arge/kimlik/bsim_temiz.py --json K/bsim_temiz.json` (`K/bsim_temiz.txt`):
  tmux (iki yön havuzlu) en iyi aday ≥ 0,7: 621 / 397 = 0,610 [0,580–0,639], kapsam %14,1; ≥ 0,9: 343 / 317;
  = 1,0: 213 / 167; tek en iyi kapısıyla 544 / 95 = 0,851 [0,822–0,877]. htop: 187 / 108 = 0,634; kapıyla
  155 / 23 = 0,871.
- Ö8 (BSim tek başına < 0,95) temiz depoda da **tuttu**; kalabalık depodaki 0,705 temiz depoda 0,610'a indi
  (iki yönün havuzu; Debian → Mac 0,651, Mac → Debian 0,574). Eşik yükseltmek kesinliği artırmıyor.

## 6. Tur sonu

### 6.1 Ön kayıtların dökümü (hiçbiri sonradan değiştirilmedi)

| Ön kayıt | Hüküm |
|---|---|
| Ö1 tekil dizgi, tmux (alt ≥ 0,90; kapsam ≤ %25) | tuttu (0,912; %16,8) |
| Ö2 yayılım, tmux sürüm farklı (alt ≥ 0,95) | **tutmadı** (0,925) |
| Ö3 tmux kapsam ≥ %40 | tuttu (%51,8) |
| Ö4 coreutils ↔ Homebrew (alt ≥ 0,95) | **tutmadı** (0,832) |
| Ö5 coreutils içi > 0,882 ve alt ≥ 0,90 | tuttu (0,987; 0,979) |
| Ö6 ad ailesi küme isabeti alt ≥ 0,95 | tmux **tutmadı** (0,767); coreutils içi tuttu (0,978) |
| Ö7 öncül 3 | ölçüldü: sürüm farkı daha pahalı (§5.15) |
| Ö8 BSim tek başına < 0,95 | tuttu (0,705 kalabalık depo; 0,610 temiz depo) |
| §5.7-2 birleşim (aynı derleyici) alt ≥ 0,95, kapsam ikisinden büyük | tuttu (0,984; %47,7) |
| §5.7-3 çok başvuru gnulib: kesinlik alt ≥ 0,95; kapsam ≥ %60 | kesinlik tuttu (0,975); kapsam **tutmadı** (%55,9) |
| G1 aynı sürüm GCC ↔ clang alt ≥ 0,95 | **tuttu** (0,987) |
| G2 tek taraflı ≤ 10 | tuttu (4) |
| G3 satır içi + komşu > 0 | tuttu (29) |
| G4 kapsam ≥ %50 | tuttu (%80,1) |
| G5 `surum_gcc` satır içi + komşu < 42 | tuttu (29) |
| G6 v2 kapsam > v1, alt ≥ 0,95 | tuttu (%87,7; 0,989) |
| G7 ad ailesi (aynı sürüm) alt ≥ 0,95 | **tutmadı** (0,907) |
| E1 aynı kuşakta kapsam > %32,6 | **tutmadı** (%32,6; birebir aynı) |
| E3, E4 sembollü başvuru ±%5, aralıklar örtüşür | tuttu |
| I1 `-O3` ↔ `-O2` alt ≥ 0,95 | tuttu (0,976) |
| I2 `-O0` çiftinde satır içi türü daha çok | tuttu (93 ↔ 50) |
| I3 `-O0` ↔ `-O2` alt ≥ 0,909 | tuttu (0,964) |
| I4 tek taraflı ≤ 10 | tuttu (10; 0) |
| T1 tanıklılarda yanlış oranı ≥ 5 kat | tuttu |
| T2 düşen doğru / düşen yanlış ≤ 1,0 | **tutmadı** (5,5; 4,6) |
| T3 satır içi türünün ≥ %50'si tanıklı | tuttu (%62; %52) |
| Kütle dengesi kapısı (keşif; eşik seçilemedi) | olumsuz |

### 6.2 Yaratıcılık protokolü: dört kural uygulandı mı?

1. **Denetlenebilir soru:** uygulandı. Her iddia iki tarafı GT'li çiftte tam ad eşitliğiyle sayıldı; eşikler önceden
   yazıldı. Doğrulayıcısı olmayan tek iddia ("tek taraflı sınıf aynı fonksiyondur") yön gösterici diye etiketlendi,
   sonra iki bağımsız ölçümle (3.8 kaynağı 47 / 52; sürüm eşlenince 99 → 4) desteklendi.
2. **Uzlaşıyı kır:** uygulandı. Yasak cevaplar ("öğrenilmiş gömme", "BSim eşiği") sonuç olarak getirilmedi;
   BSim'in eşik ayarıyla düzelmediği ölçüldü (0,610 → 0,561). Aykırı öncül 1 taze veride tuttu (aynı sürüm), öncül 2
   yalnız aynı derleyicide, öncül 3'ün yönü "sürüm daha pahalı" çıktı. Tek model ailesi çalıştı (alt ajan / başka
   model çağrılmadı: brif kuralı).
3. **Tek hatta kal:** uygulandı. Başka hatların konusuna girilmedi; görülenler §5.5'e "başka hat için not" yazıldı.
   Olumsuz denemeler (kütle dengesi kapısı, `t` kanıtı, seyreklik süzgeci, kuşak varsayımı) "neden olmadı" ile kayıtlı.
4. **Seçimi insan uzman yapsın:** uygulanmadı (bu turda dış uzman yok; KARARLAR A-1). Hangi paketin önemli olduğuna
   ben karar vermedim; PLAN ölçüt ve kanıtı veriyor, açılma kararları ana oturuma bırakıldı.

### 6.3 Sonraki ajan için

- Betikler `scripts/arge/kimlik/`; her birinin başında amaç ve komut var. Giriş noktaları: `veri.py` (yükleyici),
  `esle.py` (eşleyici; `NOKTALAR`), `ciftler.py` (gruplar), `yayilim_olc.py`, `hata_dok.py`, `tanik.py`,
  `son_olcum.sh` (ek koşuların ölçüm seti).
- Veri `~/karadul_olcum/runs/arge-2026-11-19/kimlik/`: `gcc/` (derlemeler, GT, statik koşular), `ek/` (sembollü tmux,
  Homebrew coreutils yeniden koşusu), `bsim/` (temiz depolar), `denetim/`, `*.json` / `*.txt` (ölçüm çıktıları).
- Kullanılmayan dosyalar (silinmedi; kural): `kos_gcc.sh`, `kos_ek.sh`, `kos_duzey.sh` (yerlerine `kos_kuyruk.sh`);
  `bsim/tmux_md/1_mac` tam koşu, öbür tmux BSim koşuları `--stage static`.
- tmux, htop, coreutils ↔ Homebrew ve bu turun GCC derlemeleri artık **görülmüş** çiftlerdir; bunlarda ayarlanan hiçbir
  şey sınama diye raporlanamaz. Taze veri: ÖLÇÜ P-Ö6 / P-Ö7 çıktıları ve PLAN §4'teki V1, V5.
- Son denetim: bütün düzenlemelerden sonra `yayilim_olc.py kesif_htop derleyici` yeniden koşuldu; sayılar aynı
  (htop kural 515 / 16; `derleyici` kural 3 908 / 38, kural_v2 4 281 / 36).
- `scripts/arge/kimlik/__pycache__/` bir kez bayraksız içe aktarmadan kaldı (silme yok kuralı; commit'e alınmamalı).
- Veri dizini 1,6 GB (çoğu temiz BSim'in tam koşuları ve koşu önbellekleri: `bsim/`, `gcc/cache`, `ek/cache`).
  Disk kuralı (CLAUDE.md §28): dizin Spotlight dışındaki `~/karadul_olcum` altında; ana oturum isterse `bsim/*/…/out`
  ve önbellekleri silebilir (ölçüm çıktıları `*.json` / `*.txt` ve `gcc/corpus`, `gcc/kosu`, `ek/` kalmalı).
- Git: izlenen hiçbir dosya değişmedi (`git status --short`: yalnız izlenmeyen `docs/arge/2026-11-19_mythos/kimlik/`
  ve `scripts/arge/kimlik/`; öbür izlenmeyen dizinler başka hatların).
