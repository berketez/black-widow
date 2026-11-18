# P-S3 ön kaydı — gnulib ön ad kanalı kanıta bağlanır (AD-03, B-A3) + veri akışı belirlenimciliği

Yazıldığı an: 2026-11-18, kod değişmeden ÖNCE (taban **097fdff**, yerel `main` ucu). Bu dosya kalem 1 ve 2'nin
kod commit'lerinden önce commit'lenir; sonradan değiştirilmez. Tutmayan madde sonuç dosyasına (`P-S3.md`)
"tutmadı" diye yazılır, kural sonradan gevşetilmez.

## Bu kayıttan önce görülenler (serbest; karar verilmeden önce bakıldı)
- Taban ürün çıktısı (`~/karadul_olcum/runs/urun-yeni2-f30ac9a`, 119 ikili) ve GT hükümleri: `on_ad:gnulib` uygulanan 843 ad, 621 doğru / 222 yanlış. Kanalın Ghidra'sız yeniden oynatması (`P-S3/gnulib_yeniden.py`, taban kodu `taban_kod/` = 097fdff'in `git archive` kopyası, gnulib'den önceki ön adlar köken kaydından): 119/119 ikilide köken kaydındaki gnulib adlarıyla anahtar ve ad olarak aynı (sadakat); 844 ateşleme (843 + htop'ta Ghidra'nın zaten `full_write` adını verdiği fonksiyon, `same_as_original`). Kırılım: coreutils 620 doğru / 217 yanlış (217'nin hepsi `version_etc` 104, `hard_locale` 104, `full_write` 9); coreutils dışı 2 doğru (zstd `usage`, htop `full_write` uygulanmayan) / 5 yanlış (`close_stdout` debian/tmux, mac/tmux, zstd; `full_write` openssl, redis-cli).
- GT'siz özellik dökümü (`P-S3/ozellik_dok.py` → `ozellik_dok.txt`): aşağıdaki varlık işaretlerinin dizgi kısmı geliştirme seti, Debian / Ubuntu 9.4 ve od/pr saklı çıktılarında. Çağrı işaretleri (`__fpending`, `__freading`) dökümde çağrı şekli adayları üzerinden görüldü, ayrı sayılmadı.
- 2026-11-11 keşfi (`docs/arge/2026-11-11_on_ad_onarimi/sonuc.md` §2, `yapi_ozellik.txt`): "çağıranların hepsi ince (≤ 2 çağrı)" özelliği geliştirme seti DIŞINDAKİ 25 ateşlemede 11 yanlışın 11'ini, 14 doğrunun 1'ini (Ubuntu expr `hard_locale`) ayırıyor. Bu özellik geliştirme setinde (Debian 13 coreutils 9.7) GT'yle hiç sınanmadı; bu kayıttan önce de sınanmadı (geliştirme setinde yalnız taban hükümleri biliniyor: üç girdinin 217 ateşlemesinin hepsi yanlış; yapı özelliğinin dağılımı hesaplanmadı).
- Veri akışı: `P-S3/veri_akisi_kenar.py` taban koduyla htop (P-S2 A1b çalışma alanı, `reconstructed/commented`, 6 tekrar: 4 286 ×2, 4 273 ×4) ve tree (P-S2 B0a, 6 tekrar: 123 ×2, 131 ×4). Oynayan kenarların hepsi aynı adı birden çok dosyanın tanımladığı fonksiyona varıyor (htop: `thunk_FUN_10000a0f8` üç dosya, 13 `struct_field` kenarı; tree: 63 çakışan ad, 8 `allocation_chain` kenarı).

## Kalem 1 — kural (dondurulmuş)
**A. gnulib varlık kanıtı (AD-03).** Kanal (dizgi parmak izi, çağrı şekli, ayrıştırma; hepsi) yalnız ikilide en az **2 bağımsız gnulib modülünün** işareti bulunduğunda ad yazar. Modül işaretleri (her biri gnulib upstream `vendor/gnulib-ref/lib/<kaynak>`'ta birebir geçer; testle denetlenir):

| Modül | Tür | İşaret (herhangi biri) |
|---|---|---|
| progname.c | dizgi | `A NULL argv[0] was passed through an exec system call` |
| version-etc.c | dizgi | `General help using GNU software`, `License GPLv3+: GNU GPL version 3 or later <%s>`, `Packaged by %s` |
| argmatch.c | dizgi | `invalid argument %s for %s`, `ambiguous argument %s for %s`, `Valid arguments are:` |
| closein.c | dizgi | `error closing file` |
| xstrtol-error.c | dizgi | `invalid suffix in %s%s argument '%s'`, `%s%s argument '%s' too large` |
| close-stream.c | çağrı | ikilide `__fpending` çağrılıyor |
| freading.h | çağrı | ikilide `__freading` çağrılıyor |

- Dizgi işaretleri ikilinin decompile edilmiş BÜTÜN `.c` dosyalarındaki dizgi değişmezlerinde aranır (kanalın zaten okuduğu girdi); çağrı işaretleri çağrı çizgesindeki çağrılan adlarında.
- Genel dizgiler (`write error`, `memory exhausted`, `Usage: %s`) varlık kanıtı SAYILMAZ (bison, başka programlar da taşır). Platform (ELF / Mach-O) koşul değildir.
- Eşik `MIN_PRESENCE_MODULES = 2`, sonradan değişmez.

**B. LTO yerleşimi (B-A3).** `version_etc`, `hard_locale`, `full_write` girdileri ateşlendiği fonksiyonun çağıranlarının HEPSİ ince sarmalayıcıysa (çağrı çizgesinde `callee_count ≤ 2`; en az bir çağıran) ad yazmaz: LTO'suz yapıda dizgi / çağrı iç fonksiyonda (`version_etc_arn`, `setlocale_null_r`, `safe_write`) kalır, dış ad onu çağıranındır. Çağıranı olmayan ateşlemede kural karar veremez; eski davranış (ad yazılır). Eşik `THIN_CALLER_MAX_CALLEES = 2`. İç ad bu pakette ÜRETİLMEZ (gnulib sürümüne bağlı: 2024 sonrası `setlocale_null_r_unlocked`; ayrı ölçüm gerekir).

**C. Sürüm.** `EXPECTED_COREUTILS = "9.4"` denetimi eklenmez: geliştirme seti coreutils 9.7 (gnulib 2025) ve öbür yedi girdi orada doğru; üç girdinin doğruluğu aynı sürümde (9.4) LTO'ya göre değişiyor (Debian 0/11, Ubuntu 14/14). Ayrım sürümle değil yerleşimle.

**D. Kanıt kaybolmaz (K-2).** Yazılmayan her aday, kanıt satırıyla `static/gnulib_candidates.json`'a yazılır (anahtar, katalog adı, alt kanal, karar `withheld`, neden `gnulib_kaniti_yetersiz` / `lto_yerlesimi`, kanıt satırı, yerleşimde çağıranların çağrı sayıları); uygulananlar da (`applied`) kanıt satırıyla. Varlık kanıtının modülleri ve yeterliliği aynı dosyada ve `stats["gnulib_evidence"]`'da. Biçimin gerekçesi `P-S3.md`'de.

## Kalem 1 — ölçüm düzeni
1. **Ghidra'sız yeniden oynatma** (`gnulib_yeniden.py`, taban `taban_kod/` ↔ yeni worktree commit'i): geliştirme seti 119 (`urun-yeni2-f30ac9a`), Debian 9.4 (5) ve Ubuntu 9.4 (5) (`aday-f893d72` + `~/karadul_olcum/corpus` GT'si), Ubuntu 9.4 od / pr (`on-ad-onarimi-2026-11-11/ek_kosu`). Hüküm `ks1_olc.capa_degerlendir` (tam eşitlik).
2. **Ürün koşusu** (8 ikili): geliştirme setinden debian/tmux, mac/tmux, redis-cli, openssl, zstd, cat, expr (`urun_kos.py` / aynı komutla dondurulmuş kopyadan), ve geliştirme seti DIŞINDAN Mach-O gnulib doğrulama ikilisi: Homebrew coreutils 9.12 `gcat` (`/usr/bin/strip`'li kopya; GT özgün `nm`'den, `macho_f1.build_gt`; test seti kilidinde değil). `PYTHONHASHSEED=0`, `--paralel 1`, koşu başına `KARADUL_CACHE_DIR`. Gürültü: taban iki kez (B0a, B0b); yeni kod bir kez (A).
3. Ad ölçüsü: `out/naming_map.json` (`channel == on_ad:gnulib`) ve köken kaydı; GT hükmü yeniden oynatmadakiyle aynı araç; gcat için `macho_f1` GT'si.

## Kalem 1 — önceden yazılan beklentiler
| # | Ölçü | Önce (taban) | Beklenti | Tutmadı sayılır |
|---|---|---|---|---|
| H1 | Yeniden oynatma, geliştirme setinin coreutils DIŞI 13 ikilisi: gnulib yazımı | 7 (5 yanlış) | **0**; 13'ünde varlık kanıtı yetersiz | > 0 |
| H2 | Yeniden oynatma, geliştirme seti coreutils: doğru gnulib adı | 620 | **620** (eşit ya da fazla) | < 620 |
| H3 | Yeniden oynatma, geliştirme seti coreutils: yanlış gnulib adı | 217 | ≤ 21 (en az %90 düşüş) | > 21 |
| H4 | Yeniden oynatma, Debian 9.4 (LTO'suz): yanlış / doğru | 11 / (öbür girdiler) | yanlış **0**, doğru aynı | yanlış > 0 ya da doğru azalır |
| H4b | Yeniden oynatma, Ubuntu 9.4 + od/pr (LTO'lu): üç girdinin doğrusu | 14 | 13 (expr `hard_locale` bilinen kayıp; keşiften, sınama değil) | < 13 |
| H5 | gcat (Mach-O, gnulib'li; taze): varlık kanıtı | — | yeterli (≥ 2 modül); kanal ≥ 1 ad üretir | yetersiz ya da 0 ad |
| H6a | Ürün koşusu: tmux ×2, redis-cli, openssl, zstd'de `on_ad:gnulib` uygulanan ad | 5 | **0** | > 0 |
| H6b | Ürün koşusu: cat, expr'de `on_ad:gnulib` doğru ad | B0a'daki | aynı | azalır |
| H6c | Ürün koşusu: A ↔ B0a'da değişen global anahtarlar | — | yalnız tabanda gnulib adı taşıyıp şimdi tutulan anahtarlar (+ B0a ↔ B0b gürültüsündekiler) | başka anahtar değişir ve açıklanamaz |
| H6d | `static/gnulib_candidates.json` | yok | 8/8 koşuda var; tutulan adaylar = tabandaki gnulib adı − uygulanan | eksik |

Karar: H1, H2 ya da H6a tutmazsa kalem 1 commit'lenmez, fark açıklanana kadar durulur. H3 / H4 tutmazsa yapı kuralı yanlış ad kalıyor demektir: doğru ad kaybı yoksa commit'lenir, "tutmadı" yazılır. H5 tutmazsa varlık kuralı Mach-O gnulib'i tanımıyor demektir: kural commit'lenmeden önce yeniden düşünülür ve bu yazılır (eşik sonradan değiştirilmez; yeni kural yeni ön kayıt ister).

## Kalem 2 — veri akışı belirlenimciliği
- Kural: `InterProceduralDataFlow.analyze` iş parçacığı sonuçlarını girdi sırasıyla (sıralı dosya listesi) birleştirir; aynı fonksiyon adını birden çok dosya tanımlıyorsa İLK dosyanın gövdesi tutulur (sıralı listede eksiz `ad.c` önce gelir; P16a'dan beri eksiz dosya adres sırasında ilk olandır). Kenar listesi girdi sırasıyla birleşir.
- H7: aynı girdiyle 10 tekrar → `total_edges` tek değer (htop A1b `commented`, tree B0a `commented`). Tutmadı: > 1 değer.
- H8: htop'ta yeni değer **4 286** (eksiz dosyanın gövdesi, hedef fonksiyonun tam gövdesi; 13 kenarın varlığı gövdeden okunur); tree'de iki eski değerden biri (123 ya da 131). Hangi sayının doğru olduğu kenarlar tek tek gösterilerek gerekçelendirilir.
- H9: veri akışını okuyan adım (`deep_tracing` → bileşim çözümleyicisi): ürün koşusunda A'nın `data_flow_edges` / `compositions` değerleri, B0a ↔ B0b farkı dışında açıklanır.

## Aykırı öncüller (sınanacak)
1. "Varlık işaretleri coreutils'e özgü; gnulib'li başka bir yapıda (Mach-O, clang, gnulib 2025+) bulunmaz ve kanal gereksiz yere susar" → H5 (gcat).
2. "İnce çağıran kuralı 9.4'ün yapıtı; 9.7'de (geliştirme seti) tutmaz" → H3.
3. "Tutulan (yazılmayan) gnulib anahtarına c_namer başka bir yanlış ad yazar; yanlış ad sayısı düşmez, yer değiştirir" → H6c: tutulan anahtarlarda ürünün yeni adı GT'ye karşı ayrıca sayılır.
