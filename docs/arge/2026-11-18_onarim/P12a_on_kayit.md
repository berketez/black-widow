# P12a ön kayıt — ad çekirdeği: ölçülmüş güven (AD-07), fonksiyon başına yerel ad numarası (AD-08), rol adı (AD-02)

- **Tarih:** 2026-11-18. **Durum:** KESİN; kod değişikliğinden önce commit'lenir. Taban `d025ff9` (= `main` `27ba5b9` + P12a kalem 1 belgesi; ürün kodu `27ba5b9` ile aynı).
- **Şablon:** `docs/arge/2026-11-10_n1_adim3/urun_olcumu_onkayit_taslak.md` (kollar, hüküm, kararlar önceden yazılır).
- **Kalem 1 (belirlenimcilik)** ad davranışını değiştirmez (yalnız eşit adayların sırası; yama P13a dosyasına, `808a7f8` gelene kadar etkisiz); bu ön kayda yalnız uçtan uca doğrulama ölçüsü olarak girer (U1).

## 1. Değişiklikler (ölçümden önce tanımlı)

| Kalem | Değişiklik | Dosya |
|---|---|---|
| AD-07 | Ön ada sabit 0,95 yerine kanalın ölçülmüş kesinliğinin Wilson %95 alt sınırı; ölçülmemiş kanal (`on_ad:faz1`, `on_ad:elle`, …) → `null`. Tablo kaynağı: `urun_olcumu_yeni2.md` "Kanal başına" (119 ikili, HEAD `2be12ed`, tam eşitlik). Değerler (k/n → alt sınır, 3 basamak): `on_ad:gnulib` 621/843 → 0,706; `on_ad:elf_onyuk` 458/458 → 0,992; `on_ad:main_giris` 110/110 → 0,966; `ks1:func_kalibi` 246/259 → 0,916; `ks1:func_aktarma` 33/33 → 0,896; `ks1:func_kalibi+func_aktarma` 3/3 → 0,438; `ks1:assert_ust` 5/7 → 0,359. Ad seçimi değişmez: c_namer'ın ön ad kararı güvene bakmıyor. | `core/naming_labels.py` (tablo), `c_namer.py` (ön ad dalı) |
| AD-08 | Yerel adlar (anahtar `fonksiyon::ad`, `fonksiyon ≠ ad`) fonksiyon başına tekilleştirilir: kullanılmış küme = o fonksiyonun yerel adları ∪ bu koşuda verilen genel adlar (ön adlar + genel harita). Genel adlar önce, yerel adlar sonra karara bağlanır (genel adın eki artık yerel adlara bakmaz). | `c_namer.py` (seçim döngüsü) |
| AD-02 | `api_param_reverse` adayı fonksiyon adı olmaz. Rol (`compare_func`, `event_callback` …) köken kaydında fonksiyonun **rol kanıtı** olarak yazılır (`naming_provenance.json` → `role_evidence`: API, argüman sırası, çağıran fonksiyon). "Rol + öğe" adı yalnız öğe kanıtı varken verilir; geliştirme setinde öğe kanıtı kaynağı tanımlanmadı (aşağı §4), dolayısıyla bu değişiklikle rol adı ad üretmez. | `c_namer.py` (strateji + köken kaydı) |

## 2. Kollar ve girdi

- **Yeniden oynatma kolları (karar kolları):** genel-tarama-2026-11-18'in 14 workspace'i (`~/karadul_olcum/runs/genel-tarama-2026-11-18`; Ghidra çıktısı 1.23.1, iki kolda aynı) yalnız `ReconstructionStage` ile, `PYTHONHASHSEED=0`:
  - taban: ağaç `27ba5b9` (`git archive`, `~/karadul_olcum/runs/onarim-2026-11-18/P12a/agac_taban`) → `yeniden_taban/`;
  - sonra: P12a'nın son commit'i (aynı yöntemle dışa aktarılmış ağaç) → `yeniden_sonra/`.
  - İkililer: debian tmux, openssl, zstd, pzstd (C++; tam eşitlikte dışarıda), redis-cli, sqlite3, htop, tree, coreutils ls / sort / cat / expr; mac tmux, htop.
- **Ürün kolu (uçtan uca, Ghidra dahil):** `urun_kos.py`, `--paralel 1`, her kök kendi `KARADUL_CACHE_DIR`'i; en çok 14 ikili (paket sınırı). U1 için 3 ikili × 2 tohum.
- **Ölçüm:** `urun_olc.py olc --eksik-izinli` (iki kol) + `karsilastir --eksik-izinli` (hüküm tam eşitlik, mevcut tanımlar); ek sayımlar `p12a_say.py` (depo dışı, kökte).

## 3. Ölçüler ve hipotezler

| # | Ölçü | Önce (beklenti/bilinen) | Hipotez (sonra) |
|---|---|---|---|
| H1 | `naming_map.json` / köken kaydında `on_ad:*` ve `ks1:*` adlarının güveni | hepsi 0,95 | Her kayıtta güven = §1 tablosundaki kanal değeri ya da `null`; 0,95 sabiti 0 kayıt |
| H2 | Yerel adlarda sayısal ek (`_\d+$`) taşıyan adın, aynı fonksiyonda eksiz biçimi ya da aynı tabanlı başka bir yerel ad / genel ad bulunmayan oranı ("açıklanamayan ek") | Debian htop'ta 2 442 / 2 626 yerel adın eki var; fonksiyon içi çift 0 (AD-08) | 14 ikilinin hepsinde açıklanamayan ek **0** |
| H3 | Fonksiyon içinde aynı yeni yerel adı alan iki anahtar | 0 | 0 (kalır) |
| H4 | Yerel adın bir genel adla (bu koşuda verilen) aynı olması | 0 (ortak küme) | 0 (kalır) |
| H5 | Genel ad farkı taban ↔ sonra (yeniden oynatma, aynı girdi) | — | Değişen genel adlar yalnız (a) `api_param_reverse` adlarının düşmesi, (b) eki değişen genel adlar (eskiden bir yerel ad tabanı tüketmişti); başka değişim 0 |
| H6 | Kaybedilen doğru genel ad (tam eşitlik, `karsilastir`) | — | ≤ 1 (bilinen: openssl'de `api_param_reverse` adının 1 / 85'i doğruydu; o kaybolur). Eki düşen genel adlar yalnız kazanç yönünde değişebilir |
| H7 | `api_param_reverse` kanallı genel ad | yeni2: 85 (1 doğru) | 0; köken kaydında `role_evidence` girdisi sayısı ≥ tabanda bu stratejiyle aday olmuş anahtar sayısı |
| U1 | Aynı ikili, iki `PYTHONHASHSEED` (0 ↔ 1), ürün koşusu | — | `out/naming_map.json`, `out/src/**` ve `reconstructed/src/naming_map.json` bayt bayt aynı (3 / 3 ikili) |

## 4. Önceden yazılan kararlar ve yorum

- H1, H2, H7 tutmazsa kalem onarılmamış sayılır (kodda kusur var); düzeltip yeniden ölçülür, sonuç ve tekrar sayısı yazılır.
- H5'te beklenmeyen bir genel ad değişimi çıkarsa tek tek dökülür; AD-08'in genel adları etkilememesi beklenir (yalnız ek).
- H6 tutmazsa (kaybedilen doğru > 1) geri alınmaz ama ana oturuma karar olarak bildirilir.
- **Aykırı öncül (yazılı):** "Rol adı doğru bilgi taşır, yanlış olan yalnız ek numaradır" öncülü doğru olsaydı GT adlarının çoğu rol sözcüğünü (`cmp`, `compare`, `callback`, `timer`, `handler`) taşırdı. Geliştirme setinde (urun-yeni2) 85 adın GT'leri, sözcük deseniyle sayıldı: `timer` / `callback` / `cb` 45, `cmp` / `compar` / `sort` 26, `handl` / `sig` / `term` / `alarm` / `interrupt` 5, öbür 9; yani rol sözcüğü GT'de sık ama ÖĞE (ön ek: `tty_`, `window_tree_`, `server_client_`) her zaman başka bir kaynaktan geliyor ve stripped ikilide çağıranın adı da `FUN_`. Bu yüzden öğe kanıtı yoksa ad verilmez; rol kanıtı analiste köken kaydında gider. Öğe kanıtı kaynağı (çağıranın kendi adı, karşılaştırıcının argüman tipi) bu pakette tanımlanmadı ve ölçülmedi: P12b / sonraki iş.
- **[seçim]** Güven için nokta tahmini değil Wilson %95 alt sınırı: geliştirme setindeki tek ölçümün belirsizliğini taşır; 3/3 gibi küçük n'li kanal yüksek görünmez. Gerekçe: brif §1 "sahte güven değeri" en ağır kusurlardan.
- **[seçim]** Ölçülmemiş kanal `null` (0 değil, 0,95 değil). c_namer'ın iç `confidence_map`'ine de yalnız ölçülmüş değer yazılır; NameMerger (P13a) eksik anahtarda kendi öntanımlısını (0,70) kullanıyor — bu P13a'ya not.
- **Bilinen sınır:** gnulib kanalının kesinliği P-S3 (AD-03) onarımıyla değişecek; tablo o zaman yeniden ölçülmeli (tablo ölçüm kaynağını ve HEAD'i taşır).
