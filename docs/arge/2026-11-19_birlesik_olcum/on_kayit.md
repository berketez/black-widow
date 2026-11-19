# Birleşik ürün ölçümü (onarım sonrası, a62f15e) — ön kayıt

- **Tarih:** 2026-11-19.
- **Durum:** KESİN ön kayıt. Bu belge, yeni koşunun (`urun-onarim-a62f15e`) hiçbir çıktısı okunmadan yazıldı ve commit'lendi (körlük kaydı §0).
- **Amaç:** onarım paketlerinin (2026-11-18 / 19, 40 paket) ürün düzeyindeki birleşik etkisini 119 ikilide ölçmek. Sonuç, Mythos'un ARGE planlarının tabanı olacak.
- **Yazan:** OLCUM ajanı (Opus), ana oturumun görevlendirmesiyle. Eşikler ve beklentiler bu belgede önerilir; masum kapı eşik dosyasını yalnız ana oturum yazar.
- **Biçim:** `docs/arge/2026-11-10_n1_adim3/urun_olcumu_onkayit.md` ve `urun_olcumu_onkayit_ek1.md` (yeni2 kolu). Oradaki hüküm, ölçüler, makro kuralı, (a)–(d) kararları ve sabitlenen dosyalar aynen geçerlidir. Bu belge yalnız yeni kolu, beklentileri ve ek denetimleri tanımlar. Çelişki olursa bu belge geçerlidir.
- Bu belgede GT'den fonksiyon adı geçmez. Kanallar ve paketler adlarıyla anılır.

## 0. Körlük kaydı (bu belge yazılırken)

**Bakıldı:**
- Yeni koşunun künyesinden (`kosu_kunyesi.json`) yalnız `agac` bloğu: commit `a62f15ee6e64bc1f55ecd856136185de3cb46bb8`, kirli dosya yok, `karadul` `~/karadul_olcum/urun-a62f15e/karadul/__init__.py`'den yükleniyor, sürüm 1.24.1. Künyenin öbür alanlarına bakılmadı; anahtar adları listelendi, değerleri okunmadı.
- Ürün ağacı `~/karadul_olcum/urun-a62f15e` (koşu çıktısı değil): ölçüm araçlarının sha256'sı (§2.2) ve `signatures.lmdb` bağı (→ `~/karadul_olcum/sigdb/s2-20261118/signatures.lmdb`).
- Taban kol `urun-yeni2-f30ac9a` (çıktılar ve künye) ve onun ölçüm belgeleri. Bütünlük betiği (`butunluk.py`) yalnız bu taban kökte, kendisine karşı sınandı.
- Paket kayıtları (`docs/arge/2026-11-18_onarim/DURUM.md`, `P*.md`). Rapor alanlarının yeri, P15c'nin ürün koşusunda doğrulandı (`~/karadul_olcum/runs/onarim-2026-11-18/P15c/Y`).

**Bakılmadı:** yeni koşunun `naming_map.json`, `naming_provenance.json`, `out/`, `ws/`, `BITTI` dosyaları, `kos.log` ve künyedeki süreler ve durumlar. Yeni kökte `urun_olc.py`, `masum_kapi.py`, `saglamlik_denetle.py`, `kol_butunlugu.py`, `p05_olc.py` ve `butunluk.py` koşulmadı.

## 1. Kollar

| | Taban: `yeni2` | Yeni: `onarim` |
|---|---|---|
| Ürün | f30ac9a (`karadul` 1.22.1) | a62f15e (`karadul` 1.24.1; 40 onarım paketi + yamalar) |
| Ağaç | `~/karadul_olcum/urun-f30ac9a` | `~/karadul_olcum/urun-a62f15e` (ayrık git ağacı, kirli değil) |
| Koşu kökü | `~/karadul_olcum/runs/urun-yeni2-f30ac9a` (ilk yarım çağrının künyesi `…-yarim-20261111/kosu_kunyesi.ilk-kosu.json`) | `~/karadul_olcum/runs/urun-onarim-a62f15e` |
| Komut | `scripts/measurement/urun_kos.py --paralel 3` → `python -m karadul analyze <girdi> --skip-dynamic --output-dir <d>/ws --output <d>/out` | aynı |
| `PYTHONHASHSEED` | verilmedi | `0` |
| Önbellek | ortak | koşuya ayrı `KARADUL_CACHE_DIR` |
| İmza VT | `~/.karadul` (şema 1; P15b öncesi) | ağaçtaki `signatures.lmdb` → şema 2, 9 092 473 ad, `s2-b32ee9f65b1a-20261118` |
| Ghidra | 12.1.2 | 12.1.2 |
| Girdi | 119 iş = 117 Debian 13 AArch64 ELF + Mac htop, tmux (ince arm64); `pzstd` C++ → ölçü dışı (118) | aynı dosyalar (sha256 denetimi B3) |

**Kollar arasındaki bilinen ölçüm dışı farklar:**
- Tohum: P12a, bugünkü ürünün ad haritasının tohumdan bağımsız olduğunu gösterdi (6 ikili, Ghidra dahil 3 ikili bayt bayt aynı).
- İmza VT: P15b'nin 6 ikilik ön kayıtlı ölçümünde uygulanan ad farkı 0'dı; P15c'de de adres başına ad farkı 0 / 359.
- Önbellek: ad haritasını değiştirmesi beklenmez.

Bu üç fark ad ölçüsünde etki beklenmeyen farklar olarak kayda geçer; sonuçta ayrıca sınanmaz.

## 2. Kurulum ve bütünlük denetimleri (GT okunmadan önce)

### 2.1 Bütünlük koşulları

Koşullar mekaniktir: `docs/arge/2026-11-19_birlesik_olcum/butunluk.py` (bu commit) ve `kol_butunlugu.py` ile denetlenir.

| # | Koşul | Tutmazsa |
|---|---|---|
| B1 | Yeni kökte 119 ikili dizini, taban kökle aynı anahtarlar. Her dizinde `BITTI` var ve içeriği `0`. Künyede `bitis` var; `sonuclar`'ın hepsi `tamam`; `bitmeyen` boş. | Kısmi koşu (`BITTI` = `3`) ya da `BITTI`'siz dizin listelenir. Nedeni `kosu.log`'dan ve çalışma alanının `reports/pipeline_result.json`'undan okunur. **(i) Neden Ghidra zaman aşımı ya da yükse** (P16c'nin otomatik analiz süre sınırı, `analysis.status = timeout`), ikili ana oturumca aynı ağaçla `--paralel 1 --yalniz <anahtar>` koşulur, sonra ölçülür. **(ii) Sıralı yeniden koşuda da kısmiyse** (belirlenimci ürün hatası), ikili ölçüye girer, kısmi olduğu sonuç belgesinde yazılır ve ayrı bulgu olarak kaydedilir. **(iii) `BITTI`'siz dizin varsa** (zaman aşımı, sıfır dışı çıkış), aynı yeniden koşu kuralı uygulanır. Yine bitmezse ölçüm `--eksik-izinli` ile yapılır, eksik ikili tabloda adıyla yazılır, karar satırları "eksik nüfus" notuyla okunur. |
| B2 | Künye: commit `a62f15ee6e…`, `kirli` boş, `karadul_dosyasi` ağacın içinde, sürüm 1.24.1, `agac_degisti` = false, `PYTHONHASHSEED` = `0`. | Ölçüm yapılmaz (yanlış ürün ölçülürdü). |
| B3 | Her ikilinin `raw/target_info.json` `file_hash`'i taban kolunkiyle aynı. | O ikili ölçülmez. `urun_kos` girdiyi koşudan önce zaten denetler (`girdi_degismis`). |
| B4 | Her ikilinin raporunda (`reports/report.json` → `pipeline.stages.reconstruct.stats`) imza VT künyesi: `sigdb_schema_version` = `"2"`, `sigdb_lmdb_symbol_count` = 9 092 473, `sigdb_build_id` = `s2-b32ee9f65b1a-20261118`, `sigdb_path_source` = `data_root:signatures.lmdb`, `sigdb_schema_warning` ve `sigdb_lmdb_error` boş. | Farklı ikililer listelenir. Şema 2 dışında açılan VT varsa ölçüm yapılmaz (yanlış veritabanı); neden incelenir. |
| B5 | Raporlarda Ghidra 12.1.2, `matches_pinned` = true (119/119). | Ölçüm yapılmaz. |
| B6 | Ghidra zemini (`kol_butunlugu.py`, yeni ↔ yeni2): ikili başına fonksiyon sayısı (`total`) ve sıralı adres kümesi aynı (119/119). Derleme sayaçlarının (`total_attempted`, `success`, `failed`, `skipped`) da aynı olması beklenir. | **Adres kümesi farklıysa:** o ikilinin karşılaştırması geçersiz. Ana karar onunla ve onsuz iki satırda yazılır; neden incelenir. **Yalnız sayaç farklıysa:** fark `failed` / zaman aşımındaysa yük şüphesi → B1 (i) kuralı. Fark bir paketin belgelenmiş davranış değişikliğindeyse paketi ve satırı yazılır, ölçüm sürer. |
| B7 | Kol kimliği (`urun_olc` `kol_kimligi`): `{"genel_esik": 0.7, "koken_var": true, "susturma": true}` × 118. | Ölçüm yapılmaz, neden incelenir. |
| B8 | Geçersiz kılma deposu `~/.karadul/overrides` ölçüm anında boş (`butunluk.py`). Koşudan önceki durumu geriye dönük denetlenemez; ana oturumun beyanı sonuç belgesine yazılır. | Doluysa ölçüm yapılmaz (elle ad, ürünün kendi adı gibi sayılırdı). |
| B9 | Kanal adlandırması: `urun_olc` anahtar sayacında `alt_kanal: uyuşmuyor` = 0. Kanal kırılımında `koken_yok` 0. | Sayılır ve raporlanır; karar değişmez. Uyuşmazlık sınıflayıcı ↔ ürün sürüm farkı demektir: §2.2'deki özetler denetlenir. |

### 2.2 Sabitlenen dosyalar (sha256; ölçümden hemen önce yeniden hesaplanır)

Hepsi ana depo `main` 0984090 (a62f15e + yalnız belge) ile ürün ağacı `~/karadul_olcum/urun-a62f15e`'de **aynı** (bu belge yazılırken denetlendi).

| Dosya | sha256 |
|---|---|
| `scripts/measurement/urun_olc.py` | `06131cdc55f752bcebc7a8bcfd2921ad39a2b63db3f627b9945c3e2c384380ae` (yeni2 ön kaydıyla aynı) |
| `scripts/measurement/ks1_olc.py` | `975c4d1265d8610efd03e5a9c9d55cdd784b1ba9b7720d304ff00e7776418fb9` (aynı) |
| `scripts/measurement/function_f1.py` | `edc782981f98abc6683dec0ee948c7caafcbeaf01759fdc8ddc14dd8586c4bdc` (aynı) |
| `scripts/measurement/macho_f1.py` | `bc48eac6fe1f2879374f17a5ba198672718f43e648df0b84d18b3e21e7705f43` (aynı) |
| `scripts/measurement/macho_measure.py` | `d4d517fd43e835ea1546f51186e7167b732d7b4551826ef3353e6009916667d8` (aynı) |
| `tests/benchmark/metrics.py` | `114456c29af17fb9451a23ede4a2bf071cb02295372b91c25d46878c8240fd09` (aynı) |
| `karadul/core/naming_labels.py` | `a7f69b55e4d1aa9179e1c559a9bf87c244eb3d0b5bb6370f73e2f353995a0260` (yeni2'den beri değişti: P12a AD-07) |
| `karadul/reconstruction/tarif/alt_kanal.py` | `e5afb85f27a80c2f6fe7597c261c261ce6a15f24f69907f7999d31465d671f6d` (değişti: P12b) |
| `scripts/measurement/masum_kapi.py` | `275a28c818518af91192e9f8d50ee0dc623e5344c2367e263f30bf1d75f84ea4` |
| `scripts/measurement/masum_kapi_esik.json` | `f5003cdbe955dc09c1ef892729581b77184129b4b1eefa49c7403cf3dfdfeaef` |
| `scripts/measurement/saglamlik_denetle.py` | `d8d98b89e3f4406f176abb0f62b229ff34f8f42c32c5687776d1a6778097dd64` |
| `scripts/measurement/p05_olc.py` | `08478517690e21deaeab786db4ae1625edcc2326f61a2e42cade87f3727054e9` |
| `docs/arge/2026-11-10_n1_adim3/kol_butunlugu.py` | `a3a8e3e7e339f33c85e7bca49af5675dcecc9f6782d13b8e4daeea50076f57e9` |
| `docs/arge/2026-11-10_n1_adim3/urun_olcumu_yeni2.json` (taban) | `867453d14ac541851c77b199b293fbbc7e06cfc3773b77995eea4f838958a013` |

**Ölçüm hangi ağaçtan koşulur:** `urun_olc.py` ad sınıflayıcısını (`naming_labels.py`, `alt_kanal.py`) betiğin bulunduğu ağaçtan içe aktarır.
- Ölçüm anında ana ağaçta (ya da OLCUM worktree'sinde) bu iki dosyanın ve ölçüm betiklerinin özeti tablodakiyle aynıysa ölçüm oradan koşulur.
- Biri farklıysa (gün içinde ad çekirdeğine paket girmiş olabilir, ör. P12c) ölçüm ürün ağacından koşulur: `PYTHONDONTWRITEBYTECODE=1`, betik `~/karadul_olcum/urun-a62f15e/scripts/measurement/…`, `--mac-veri /Users/apple/Black_Widow/workspaces/olcum_mac` (ürün ağacında `workspaces/` yok).
- Sonuç belgesine hangi ağaçtan koşulduğu ve özetlerin "aynı / farklı" olduğu yazılır.

## 3. Ana ölçüler

Tanımlar yeni2 ön kaydıyla aynıdır (`urun_olcumu_onkayit_taslak.md` + `urun_olcumu_onkayit.md` §1):
- **Hüküm:** tam eşitlik.
- **Sayım:** örnek düzeyi.
- **Kesinlik paydası:** ad verilen bütün fonksiyonlar.
- **Nüfus:** `ks1_olc.GtBirimi.nufus`.
- **Makro:** program düzeyi, `N_MIN` = 10, `EN_AZ_PROGRAM` = 2.
- **Ad haritası:** ilk yineleme `reconstructed/src/naming_map.json`.

Ölçüler:

1. **Havuz:** ad verilen, doğru, yanlış, kesinlik. **Yanlış oranı + Wilson %95.**
2. **Program düzeyi makro yanlış oranı** → karar (a): ≤ %10 (`YANLIS_HEDEFI`).
3. **Kapsam** (nüfusta ad verilen / nüfus) ve **doğru ad kapsamı** (nüfusta doğru / nüfus): havuz + Wilson ve program makrosu.
4. **"kesin" etiketinin kesinliği:** havuz + Wilson ve makro → karar (b): ≥ %95 (`KESIN_ETIKET_ESIGI`); Wilson ihlali yalnız raporlanır.
5. **Kanal kırılımı:** kanal başına ad / doğru / yanlış, kesinlik + Wilson, makro. Ayrıca etiket × kanal ve birim × kanal (JSON'dan).
6. **Kaybedilen / kazanılan doğru ad** (`karsilastir`, yeni2 ↔ onarim; birim, ikili, adresle eşleme).
   - kaybedilen doğru (silinen + yanlışa dönen), kazanılan doğru, giderilen yanlış, yeni yanlış;
   - kayıp ve kazanç kanalı;
   - karar (c): kayıp oranı > %15 → `incele`;
   - yön koşulu: iki kolda da en az 10 ad verilen her birimde yeni kolun yanlış oranı düşük.
7. **Karar (d), dallar:** yeni2 ön kaydı taslağı §7 (d) aynen.

## 4. Beklentiler ve eşikler (ölçümden önce)

### 4.1 Nasıl türetildi

Nokta beklentileri `docs/arge/2026-11-19_birlesik_olcum/beklenti.py` ile hesaplandı (çıktı `beklenti.json`; bu commit).

**Girdi:** yalnız taban kolun ölçülmüş birim × kanal sayıları (`urun_olcumu_yeni2.json`). Betik önce tabanı yeniden hesaplar ve ölçülmüş tabanla aynı çıktığını doğrular: 2 261 / 1 589 / 672, makro %52,8.

Sonra üç kanala paketlerin ölçülmüş etkisi uygulanır; öbür kanallar değişmez varsayılır:

| Kanal | Taban (yeni2, 119) | Beklenti | Kaynak (ölçüm) | 119'a taşıma |
|---|---|---|---|---|
| `on_ad:gnulib` | 843 ad / 621 doğru / 222 yanlış (coreutils 837 / 620; gnulib'siz 6 birimde 6 / 1) | **733 / 733 / 0** (coreutils 732 / 732; debian/zstd 1 / 1) | `docs/arge/2026-11-18_onarim/P-S3.md` §Kalem 1 c tablosu (s. 59–60: 843 → 621, gnulib'siz 7 yazım → 0); `P-S3b.md` §Kalem 3 (`_exit` dışlaması, 620 / 1 → 620 / 0), §Kalem 2 c (gelenek kanalı 1 / 0), §Kalem 4 c (s. 205: "geliştirme seti coreutils 732 doğru / 0 yanlış"; LTO'suz yerleşim iç adları 104 + 8, hepsi doğru); `DURUM.md` s. 54, 67 | Taşıma yok: ölçümler 119'un tamamında Ghidra'sız yeniden oynatma. Ürün koşusu yeniden oynatmayı 7 + 6 ikilide doğruladı (P-S3 "Ürün koşusu", P-S3b "A = yeniden oynatma 6 / 6"). |
| `string_context/kebap_ad` | 239 / 0 / 239 (openssl 2, sqlite3 1, debian/tmux 101, mac/tmux 135) | **0** | `P12b.md`; `DURUM.md` s. 69 ("kebap adı 239 → 0, kebap dışı ad farkı 0, kaybedilen doğru 0 / 441"; 14 ikilide yanlış havuzu 357 / 798 → 118 / 559) | Taşıma yok: 119'daki 239 kebap adının 239'u o 14 ikilide (taban birim × kanal tablosu). |
| `api_param_reverse` | 85 / 1 / 84 (8 birim) | **0** (kaybedilen doğru 1: openssl) | `P12a.md` §Kalem 4 (s. 102–116: 14 ikilide rol adı 70 → 0; 13 C ikilisinde yanlış 439 / 882 → 371 / 813; kaybedilen doğru 1) | **Taşıma var:** 85 adın 70'i ölçülen 14 ikilide. Kalan 15 ad (coreutils 6 ve öbür birimler) için varsayım: kural (rol sözcüğü ad olmaz, kanıt satırı yazılır) ikiliye bağlı değil, aynı biçimde susar. Bant 0–15. |

**Ortak varsayımlar:**
- **V1:** Kanalın kaldırdığı anahtara başka kanal ad yazmaz. Sınandığı yerler: P-S3 H6c, 8 ikili; P12a 13 ikili (ad sayısı tam olarak kaldırılan kadar düştü); P12b 14 ikili (kebap dışı ad farkı 0).
- **V2:** gnulib'in yeni 112 doğru adı nüfustadır. Tabanda kanalın 843 adının 842'si nüfustaydı.
- **V3:** Öbür kanallar değişmez. Kanıt: P13a, P13b, P15b, P15c, P16c, P14, P-S2 ürün koşularında ad haritası farkı 0. Ama bu koşuların hiçbiri tmux / zstd / openssl'i içermiyordu.
  - **En büyük belirsizlik GHIDRA-16'dır** (dizgi → fonksiyon bağı; P13a'da alındı). P13a'nın 10 ikilisinde c_namer'ın kendi dizgi kümesini değiştirip 1 `string_context/oz_ad` adını değiştirdi (yanlıştan yanlışa).
  - `oz_ad`'ın 224 adının büyük kısmı GHIDRA-16 ölçümünde olmayan ikililerde: debian/tmux 51, mac/tmux 64, zstd 51, openssl 7, coreutils'in ölçülmemiş 102 ikilisi. P13a'nın 10 ikilisinden coreutils'te yalnız 4'ü vardı.
  - **Ürüne girmemiş, bilinen belirlenimsizlik (P16d, bu koşuda yok):** `pcode_high_vars` sırası koşudan koşuya değişiyor (`PYTHONHASHSEED=0` ile de; küme aynı). `c_type_recoverer` sözlüğe dökerken son kazanıyor. Fonksiyon adına etkisi ölçülmedi. Bant dışı bir farkın nedeni ararken bu da denetlenir.
  - **Ürüne girmemiş paket (P12c, bu koşuda yok):** c_namer çok satırlı imzanın gövdesini almıyor. 14 alanda fonksiyonların %5,0'ı gövdeye bakan stratejilere görünmez. Bu ölçüm o kusurla birlikte ölçer.
  - KS-1 kanalları da dizgi çapası kullanır; KS-1 adlı birimlerin (openssl, tmux, zstd) hiçbiri GHIDRA-16 ölçümünde yoktu.
  - Bantlar bu belirsizliği taşır: `oz_ad` için ±%10, KS-1 için ±3.

### 4.2 Beklentiler (H) ve "tuttu / tutmadı" eşikleri

Her satır sonuç belgesinde "tuttu / tutmadı" diye okunur. Kural sonradan değiştirilmez (§7).

| # | Ölçü | Taban (yeni2) | Nokta beklenti | Tuttu eşiği | Kaynak |
|---|---|---|---|---|---|
| H1 | Havuz: ad / doğru / yanlış | 2 261 / 1 589 / 672 | **1 827 / 1 700 / 127** | ad 1 780–1 880; doğru 1 650–1 750; yanlış 100–165 | `beklenti.json` `beklenti.havuz` |
| H2 | Havuz yanlış oranı (Wilson %95) | %29,7 (%27,9–%31,6) | **%7,0 (%5,9–%8,2)** | %5,5 ≤ oran ≤ %9,0 | aynı. Bant: `oz_ad` ±22 yanlış, `api_param_reverse` 0–15 kalan |
| H3 | Program düzeyi makro yanlış | %52,8 | **%31,9** (coreutils 0,8; openssl 14,8; redis-tools 20,0; sqlite3 58,3; tmux 12,3; zstd 85,2) | %25 ≤ makro ≤ %38; karar (a) `tutmuyor` (≤ %10 tutması beklenmiyor) | `beklenti.json` `beklenti.makro`. Makroyu zstd ve sqlite3'ün `oz_ad` yanlışları taşır |
| H4 | `on_ad:gnulib` ad / doğru / yanlış | 843 / 621 / 222 | **733 / 733 / 0** | doğru ≥ 725, yanlış ≤ 2, ad ≤ 740 | P-S3, P-S3b (yukarıda) |
| H5 | `string_context/kebap_ad` adı | 239 | **0** | = 0 | P12b |
| H6 | `api_param_reverse` adı | 85 (1 doğru) | **0** | = 0. 1–15 kalırsa tutmadı: kuralın ölçülmemiş ikililere taşınmadığı bulgusu, birim birim yazılır | P12a AD-02 |
| H7 | Değişmez kanallar: `on_ad:elf_onyuk` 458 / 458, `on_ad:main_giris` 110 / 110, `ks1:func_kalibi` 259 / 246, `ks1:func_aktarma` 33 / 33, `ks1:func_kalibi+func_aktarma` 3 / 3, `ks1:assert_ust` 7 / 5 | aynı | aynı | `on_ad:*` tam aynı. KS-1 her satırda ad ve doğru ±3 içinde. Aşan kanal "açıklanamayan fark" sayılır (§4.3) | V3 |
| H8 | `string_context/oz_ad` ad / doğru | 224 / 112 | **224 / 112** | ad 200–246, doğru 100–124 | V3 (GHIDRA-16 belirsizliği) |
| H9 | "kesin" etiketli ad / doğru; makro | 262 / 249 (%95,0; %91,7–%97,1); makro %97,3 | **262 / 249; %97,3** | ad 256–268; karar (b) `tutuyor` | KS-1 kanalları değişmez (H7). `kesin` = `ks1:func_kalibi` + `ks1:func_kalibi+func_aktarma` |
| H10 | Kaybedilen doğru (`karsilastir`) | — | **1** (`api_param_reverse`, openssl) | ≤ 5; karar (c) `beklenen_aralikta` | P12a H6 |
| H11 | Kazanılan doğru | — | **112** (hepsi `on_ad:gnulib`, LTO'suz iç adlar) | 105–120 ve en az %95'i `on_ad:gnulib` kanalından | P-S3b kalem 4 |
| H12 | Giderilen yanlış / yeni yanlış | — | **545** (gnulib 222 + kebap 239 + rol 84) / **0** | giderilen 520–560; yeni yanlış ≤ 10 | yukarıdakilerin toplamı |
| H13 | Yön koşulu (en az 10 adlı 7 birim) | — | 7 / 7 birimde düşer | `beklenen_aralikta`. **Not:** debian/zstd'de pay dar (%86,2 → %85,2; 56 / 65 → 52 / 61). zstd düşmeyen çıkarsa H13 tutmadı yazılır; nedeni `oz_ad` oynaklığıysa ayrıca belirtilir | `beklenti.json` `beklenti.birim` |
| H14 | Kapsam (havuz) | 1 764 / 21 371 (%8,3) | **1 342 / 21 371 (%6,3)** | 1 300–1 390. Kapsamın düşmesi beklenir (yanlış adlar kalktı); gerileme sayılmaz | V2 |
| H15 | Doğru ad kapsamı (havuz) | 1 120 / 21 371 (%5,2) | **1 231 / 21 371 (%5,8)** | ≥ 1 200 | V2 |
| H16 | Program makro kapsam / doğru ad kapsamı | %4,9 / %2,3 | **%3,4 / %2,4** | her biri ±0,5 puan | `beklenti.json` |

Birim başına nokta beklentisi `beklenti.json` → `beklenti.birim`.
- coreutils 1 300 / 1 290 / 10
- debian/tmux 167 / 148 / 19
- mac/tmux 236 / 205 / 31
- zstd 61 / 9 / 52
- openssl 27 / 23 / 4
- redis-tools 15 / 12 / 3
- sqlite3 12 / 5 / 7
- debian/htop 4 / 3 / 1
- tree 5 / 5 / 0
- mac/htop 0

### 4.3 Beklentiden sapma nasıl okunur

- **Açıklanamayan fark.** H4–H8'in bir kanalında bant dışı fark varsa, kanal × birim × ikili düzeyinde (`ogeler` ve `karsilastir` geçiş tablosu) hangi paketin değiştirdiği aranır. Bulunana kadar sonuç "açıklanamayan fark" diye yazılır.
  - Fark yalnız o kanalla sınırlıysa bulgu olarak yazılır, öbür kararlar okunur.
  - Fark birden çok kanala yayılıyorsa, bütünlük koşulları (B1–B9) yeniden denetlenmeden karar okunmaz.
- **V1 tutmazsa** (kaldırılan anahtar başka kanaldan ad almışsa), anahtar ve yeni kanal sayılır, H1–H2'nin farkına katkısı ayrıca yazılır.
- **Yapı.** H1–H3 ve H14–H16 bileşik ölçülerdir. Kanal satırları (H4–H8) tutup bileşik ölçü tutmazsa neden aritmetiktir: hangi kanalın bandı kullanıldığı yazılır.

## 5. İkincil ölçümler

### 5.1 Masum kapı, çıktı kipi (119 çıktı)

- **Komut (§6):** `masum_kapi.py --kosu <yeni kök> --agac ~/karadul_olcum/urun-a62f15e`. Bileşim ve algoritma katmanları (`bilesim_yeniden`, `algoritma_yeniden`) ürün ağacının koduyla yeniden oynatılır.
- **Karşılaştırma:** `~/karadul_olcum/runs/onarim-2026-11-18/P00/taban_cikti_urun_yeni2/masum_kapi.json` (1.22.1, 119).
- **Kapı kuralı (bugünkü eşik dosyası):** eşikler yalnız HEAD 14 ikilisinde (e9d2d08, onarım öncesi). Öbür 105 ikili "eşiksiz" görünür.
- **Beklenti K0:** kapı çıkış 0. Eşikli 14 ikilide hiçbir katman eşiği aşmaz ve zorunlu gerçek pozitifler yerindedir.

**Katman başına beklenti (119; yanlış iddia):**

| Katman | 1.22.1 (119): iddia / yanlış | Beklenti | Kaynak |
|---|---|---|---|
| `bilesim`, `bilesim_yeniden` | 451 / 451 | **0** (bekleyen adaylar `pending_compositions`'ta, kapı saymaz) | P04a MUH-03 (133 ikilide 533 → 0) |
| `blok_yorumu` | 112 / 112 | **≤ 1** | P04a MUH-07 (satır öncelikli matris 409 → 0) |
| `types_h` | 117 / 117 | **0** (adaylar `typed/types_candidates.txt`'te) | P09 (`types.h` yapı 4 109 → 0) |
| `yara_cikti` | 81 / 70 (`bilinmiyor` 88) | **yanlış 0**; iddia ≈ 11 (doğrulanmış zlib); `bilinmiyor` 0 | P03 IMZA-05 (70 → 0); P-S1 dürüst durum |
| `antidebug_cikti` | 23 / 23 | **7** (kalan bilgi düzeyi) | P02 (masum kapı geliştirme 23 → 7) |
| `packer_cikti` | 0 / 0 | **0** | P02 |
| `intel` | 2 130 / 1 965 | **yanlış ≈ 455** (400–520) | P01 + P01b (doğrudan kipte geliştirme 2 102 → 455; P00: doğrudan kip ürün BI'siyle 14 / 14 aynı) |
| `security_etiketi` | 47 / 47; adet 4 327 | adet **≈ 3 352** (±%5); iddia sayısı için sayısal beklenti yok, yön: düşer | P06 TIP-08 (4 327 → 3 352) |
| `algoritma_json`, `algoritma_yeniden`, `algoritma_kod` | 109 / 109; 66 / 66 | Yön: düşer. Sayısal beklenti yok: API (144) ve sabit (32) katmanı değişmedi, 119'daki payları ölçülmedi. HEAD 14'te 45 → 24 | P06 TIP-09 |
| `sarif` | 81 / 81 | Yön: düşer (KRDL003 YARA kaynaklı yanlışlar gider) | P03, P07 |

**Eşik önerisi (dosyayı ana oturum yazar).** `masum_kapi.py --esik-yaz <bu koşunun masum_kapi.json'u>` ancak şu üç koşul birlikte tutarsa:
1. K0 tuttu;
2. hiçbir katmanın 119'daki yanlışı 1.22.1 değerinin üstünde değil;
3. sayısal beklentisi olan katmanlarda ölçülen yanlış, beklentinin üst ucunu aşmıyor (`bilesim` 0, `blok_yorumu` 1, `types_h` 0, `yara_cikti` 0, `antidebug_cikti` 7, `packer_cikti` 0, `intel` 520).

Önerilen eşik = ölçülen değer (sıkı). Koşullardan biri tutmazsa o katmanın eşiği yazılmadan önce iddialar incelenir. Eşik yazımı sapma sayılmaz; kapının amacı budur.

### 5.2 Kanal başına ölçülmüş kesinlik → `MEASURED_PRE_NAME_PRECISION`

- **Kaynak satırlar:** bu ölçümün "Kanal başına" tablosu (`urun_olc` `toplam.kanal`). Tablo yalnız ön ad kanallarını tutar: `on_ad:*`, `ks1:*`.
- **Değer biçimi:** (doğru, ad verilen, Wilson %95 alt sınırı; 3 basamak).
- **Kaynak dizgisi:** `docs/arge/2026-11-19_birlesik_olcum/sonuc.md@<commit>`.
- **Beklenen yeni değerler:**

| Kanal | Bugün (yeni2) | Beklenen |
|---|---|---|
| `on_ad:gnulib` | (621, 843, 0,706) — bayat | **(733, 733, 0,995)** |
| `on_ad:elf_onyuk` | (458, 458, 0,992) | aynı |
| `on_ad:main_giris` | (110, 110, 0,966) | aynı |
| `ks1:func_kalibi` | (246, 259, 0,916) | aynı (±3) |
| `ks1:func_aktarma` | (33, 33, 0,896) | aynı |
| `ks1:func_kalibi+func_aktarma` | (3, 3, 0,438) | aynı |
| `ks1:assert_ust` | (5, 7, 0,359) | aynı |

- **Kim yapar:** tabloyu yenilemek kod değişikliğidir (`karadul/core/naming_labels.py` + `tests/test_p12a_on_ad_guveni.py`). Ana oturum ya da bir paket yapar, bu ölçüm yapmaz.
- **Kural 1 — kanal ayrımı:** `on_ad:gnulib` satırı kanalın üç kararını (dizgi parmak izi / çağrı biçimi / ayrıştırma; gelenek kanalı; LTO'suz iç ad) tek satırda toplar. `urun_olc` bunları ayırmaz. Gelenek kanalının n'i 1'dir, ayrı kesinlik iddiası yoktur.
- **Kural 2 — "kesin" etiketi:** bu ölçümle hiçbir kanal "kesin" etiketine yükseltilmez. Gerekçe §8: ölçüm geliştirme seti içidir. gnulib %95'i geçse de etiket kararı geliştirme seti dışı, ön kayıtlı bir ölçüm ister. P-S3b'nin taze Mach-O kabul seti 8 / 8, Debian 9.4 ve Ubuntu 9.4 derlemeleri destekleyici sayılır, yeterli sayılmaz.

### 5.3 Parametre adları (P05, P05b; ikincil, karar yok)

- **Komut (§6):** `p05_olc.py kos --hizalama` yeni koşunun kayıtlı girdileriyle ve ürün ağacının koduyla koşulur (119 ikili; DWARF hükmü 22 ikilide).
- **Beklentiler:**
  - Kusurlu ad (geçersiz / anahtar sözcük / tip / Ghidra biçimi / gövde çakışması) **0**.
  - İşaretçiye skaler ad **0**.
  - Kanıtsız `str` ailesi **0**.
  - Betiğin doğrulaması (yeniden oynatılan `param_naming_map` = kayıtlı) 119 / 119 aynı. Ürün ile ağaç aynı kod olduğu için.
  - D (22 ikili) tam / yakın / yanlış için nokta beklenti P05b son kol `k4` = 67 / 69 / 4 964. Girdiler değişti (P09, P10, P11 tip ve yapı onarımları, yeni Ghidra koşusu), bu yüzden bant geniş: doğru (tam + yakın) 120–150, yanlış ≤ 5 287 (P05 sonrası tavan).
  - Kaynak: `docs/arge/2026-11-18_onarim/P05b.md` §7.

### 5.4 Sağlamlık denetimi (ikincil, karar yok)

- **Komut (§6):** `saglamlik_denetle.py`. Taban: `P00/saglamlik_urun_yeni2.md`.
- **Sayısal beklentiler:**
  - `sayi:fonksiyon_sayisi` 0 (P16a yaması 335db1d);
  - `decompiled_json_kirpik` 0, kırpma kayıtlı biçime (`decompiled_json_kirpik_kayitli`) geçer (P16a B-B4);
  - `cift_tanim_adres` 0 (1.23.1 düzeltmesi);
  - `sayi:log_kaynak_dosya` ve `sayi:log_yazilan_dosya` 0.
- **Yön beklentileri (sayısal değil):** `bsim_yedege_dustu` (78) düşer (P16b, P16c). Öbür kalemler yalnız yazılır.

### 5.5 İkili başına süre (yalnız kaba karşılaştırma)

- **Kaynak:**
  - Yeni: künyedeki `sonuclar[].sure_sn`.
  - Taban: `urun-yeni2-f30ac9a/kosu_kunyesi.json` (83 iş) + `urun-yeni2-f30ac9a-yarim-20261111/kosu_kunyesi.ilk-kosu.json` (kalanlar).
- **Karşılaştırma:** iki kolda da `tamam` süresi olan ikililerde medyan oran (yeni / taban) ve toplam.
- **Yük uyarısı:** makine ortak yük altındaydı. Koşu sürerken başka ajanlar, pytest ve Ghidra'lı koşular vardı; 36 GB RAM ve 14 çekirdek paylaşıldı. Süreler karar dışıdır, ikili başına neden aranmaz.
- **Yalnız yön beklentisi:** medyan oran < 1. P16c toplu BSim sorgusu Ghidra köprüsünde 2,8–6,7 kat hızlandırdı; Ghidra ürün süresinin %77'si.

## 6. Aşama 2 komutları (koşu bitince, sırayla)

```bash
K=~/karadul_olcum/runs/urun-onarim-a62f15e
T=~/karadul_olcum/runs/urun-yeni2-f30ac9a
U=~/karadul_olcum/urun-a62f15e
O=~/karadul_olcum/runs/onarim-2026-11-19/OLCUM      # GT'li ve ham çıktılar (depo dışı)
D=docs/arge/2026-11-19_birlesik_olcum               # özetler ve sonuç (depo)
mkdir -p $O

# 0) Sabitlenen dosyaların özeti (§2.2) — ölçüm ağacında ve ürün ağacında
shasum -a 256 scripts/measurement/{urun_olc,ks1_olc,function_f1,macho_f1,macho_measure,masum_kapi,saglamlik_denetle,p05_olc}.py \
  tests/benchmark/metrics.py karadul/core/naming_labels.py karadul/reconstruction/tarif/alt_kanal.py \
  scripts/measurement/masum_kapi_esik.json docs/arge/2026-11-10_n1_adim3/{kol_butunlugu.py,urun_olcumu_yeni2.json}

# 1) Bütünlük B1–B5, B8 (GT yok)
python3 $D/butunluk.py --kok $K --taban-kok $T --commit a62f15ee6e64bc1f55ecd856136185de3cb46bb8 \
  --surum 1.24.1 --json $D/butunluk.json
# 2) Ghidra zemini B6 (GT yok)
python3 docs/arge/2026-11-10_n1_adim3/kol_butunlugu.py --taban-debian $T/debian --taban-mac $T/mac \
  --yeni $K --json $D/kol_butunlugu.json
#    B1–B6'dan biri tutmazsa §2.1'deki işlem; karar okunmaz.

# 3) Ad ölçümü (GT) — §2.2'ye göre seçilen ağaçtan
PYTHONDONTWRITEBYTECODE=1 python scripts/measurement/urun_olc.py olc --kok-debian $K/debian --kok-mac $K/mac \
  --mac-veri /Users/apple/Black_Widow/workspaces/olcum_mac --kol onarim \
  --json $D/urun_olcumu_onarim.json --md $D/urun_olcumu_onarim.md
PYTHONDONTWRITEBYTECODE=1 python scripts/measurement/urun_olc.py karsilastir \
  --taban docs/arge/2026-11-10_n1_adim3/urun_olcumu_yeni2.json --yeni $D/urun_olcumu_onarim.json \
  --json $D/urun_olcumu_fark_yeni2_onarim.json --md $D/urun_olcumu_fark_yeni2_onarim.md
#    --eksik-izinli yalnız B1 (iii) durumunda.

# 4) Masum kapı, çıktı kipi (ürün ağacının koduyla); eşik YAZILMAZ
PYTHONDONTWRITEBYTECODE=1 python scripts/measurement/masum_kapi.py --agac $U --kosu $K --kosu-seti gelistirme \
  --cikti-dizin $O/masum_cikti \
  --karsilastir ~/karadul_olcum/runs/onarim-2026-11-18/P00/taban_cikti_urun_yeni2/masum_kapi.json
cp $O/masum_cikti/masum_kapi.md $D/masum_kapi_cikti.md

# 5) Sağlamlık
PYTHONDONTWRITEBYTECODE=1 python scripts/measurement/saglamlik_denetle.py --kok $K --cikti-dizin $O/saglamlik --is 6
cp $O/saglamlik/saglamlik.md $D/saglamlik.md

# 6) Parametre adları (ürün ağacının koduyla yeniden oynatma)
PYTHONHASHSEED=0 PYTHONDONTWRITEBYTECODE=1 python $U/scripts/measurement/p05_olc.py kos --kosu $K \
  --kok $O/p05 --etiket birlesik --hizalama ~/karadul_olcum/runs/t0b-1acba60/hizalama

# 7) Beklenti ↔ ölçüm tablosu ve sonuç belgesi: $D/sonuc.md (H1–H16 tuttu / tutmadı; §5; sapmalar)
```

**Kurallar:**
- Ham ve GT'li ara çıktılar `$O`'ya yazılır. Depoya yalnız `urun_olc` ve `karsilastir` JSON / MD'leri (ad içermezler), bütünlük JSON'ları ve özet belgeler girer.
- Koşu kökü ve ürün ağacı salt okunur. `PYTHONDONTWRITEBYTECODE=1` ürün ağacına `__pycache__` yazılmasını önler.
- `masum_kapi_esik.json`'a yalnız ana oturum yazar (§5.1).

## 7. Sapma kuralı

- **Ölçüt sabit.** Sonuç görüldükten sonra ölçü tanımı, eşik, bant, makro kuralı, nüfus ve hüküm değiştirilmez.
- **Değişiklik zorunlu olursa** (araç kusuru, kayıp dosya, beklenmeyen biçim), değişiklik sonuç belgesinde **"Sapma"** başlığı altında yazılır. Her sapma için: ne değişti, neden, sonuç görülmeden önce mi sonra mı fark edildi, değişikliğin sayılara etkisi. Mümkünse ön kayıtlı tanımla değiştirilmiş tanımın ikisi de raporlanır.
- **Tutmayan beklenti.** "tutmadı" yazılır; beklenti geriye dönük düzeltilmez. Açıklama ayrı paragrafta "ölçüm sonrası açıklama" diye etiketlenir.
- **Yeni soru.** Ölçüm sırasında doğan soru (ör. GHIDRA-16'nın `oz_ad` etkisi) bu ölçümün kararlarına eklenmez. Yeni ön kayıtla ayrı ölçülür.

## 8. Yorum sınırları (ön kayıtlı)

1. **Geliştirme seti içi ölçüm.** 119 ikili geliştirme setidir. P-S3, P-S3b, P12a ve P12b'nin kuralları bu setin GT'sine bakılarak kuruldu ve sınandı.
   - Buradaki kesinlik ve yanlış oranları genelleme iddiası değildir; üst sınır gibi okunur.
   - Genelleme için kilitli test setinde ya da taze ikililerde ön kayıtlı ölçüm gerekir. Mythos ARGE planı bunu ayrı satır olarak taşımalı.
2. **Makro birkaç birime dayanıyor.** Makro yanlış oranını iki birimin `oz_ad` yanlışları taşır: zstd ve sqlite3. Altı programın ikisi yoksul / küçük birimdir (sqlite3'te beklenen 12 ad). Program sayısı az olduğu için makro oynaktır.
3. **Kapsamın düşmesi kusur değil.** Yanlış adların kalkmasının doğal sonucudur. Ölçüt "analisti yanıltmamak"tır; doğru ad kapsamı (H15) ayrıca izlenir.
4. **Kanal ölçeği.** Yeni2 → onarım farkının üç kanal dışındaki kısmı (H7, H8) ürünün başka paketlerinin etkisidir. Bu ölçüm onları paket paket ayırmaz.

## 9. Ölçüm araçlarında görülen kusurlar (değiştirilmedi; bu ölçümde elle denetleniyor)

1. **`ks1_olc.debian_elfleri` `BITTI`'nin içeriğine bakmıyor.** P15a'dan beri `urun_kos` kısmi koşuya da (`analyze` çıkış 3) `BITTI` yazıyor (`3`; commit 6c0b79b). Bu yüzden kısmi ikili `urun_olc`'a sessizce "bitmiş" diye girer. Bu ölçümde B1 (`butunluk.py`) denetliyor.
2. **`ks1_olc.mac_elfleri` `BITTI`'ye hiç bakmıyor.** Yalnız `ws/` varlığına bakıyor; Mac ikilisinde yarım koşu ölçüye girebilir. `haritasizlari_isaretle` yalnız ad haritası yoksa yakalar. B1 denetliyor.
3. **`urun_kos` künyesi `KARADUL_CACHE_DIR`'ı yazmıyor.** `PYTHONHASHSEED`'i yazıyor ama bunu yazmıyor. İmza VT künyesini de yazmıyor (yalnız `signatures.lmdb`'nin varlığını şart koşuyor, şemasını değil). B4 bunu ikili başına rapordan denetliyor; önbellek dizinini ana oturum sonuç belgesine yazmalı.
4. **`urun_olc` ad sınıflayıcısını betiğin bulunduğu ağaçtan içe aktarıyor.** Ölçülen ürünle aynı sürüm olduğunu kendisi denetlemiyor. `naming_labels.py` ve `alt_kanal.py` yeni2 ön kaydından beri değişti (§2.2); ölçüm ağacı §2.2'ye göre seçilir.
5. **`kol_butunlugu.py` taban kökün düzenini varsayıyor.** `<program>/<ikili>` bekliyor; `urun_kos` düzeninde `--taban-debian <kök>/debian` verilerek çalışır (§6'daki komut).
6. **`urun_olc` `on_ad:gnulib` kanalını karar nedenine göre ayırmıyor.** Parmak izi, gelenek ve LTO'suz iç ad ayrılmıyor. `MEASURED_PRE_NAME_PRECISION` için alt kanal kesinliği gerekirse `static/gnulib_candidates.json` ile ayrı sayım gerekir (bu ölçümde yok).

## 10. Dosyalar (bu commit)

- `on_kayit.md` (bu belge).
- `beklenti.py` → `beklenti.json`: nokta beklentileri. Yalnız taban JSON'unu okur, tabanı yeniden hesaplayıp ölçülmüş tabanla sağlar.
- `butunluk.py`: B1–B5 ve B8 denetimi, GT'siz. Taban kökte kendisine karşı sınandı. Beklendiği gibi B4 tutmadı (1.22.1'de VT künyesi yok) ve commit kısaltması B2'yi düşürdü; öbür denetimler tuttu.
