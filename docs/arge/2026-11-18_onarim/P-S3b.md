# P-S3b — gnulib ön ad kanalı: sürümden ve platformdan bağımsız varlık kanıtı + kalan gnulib ad kusurları — ilerleme

Brif: `ONARIM_BRIF.md`. Paket metni: `gonderim/PS3b.md`. Karar: K-2. Önceki paket: `P-S3.md` (H5 tutmadı).
Ön kayıt: `P-S3b_on_kayit.md` (kod değişmeden önce commit'lendi).

- Taban: worktree `origin/main`'den (d2f205d) açıldı; `git merge --ff-only main` → **cce2e8c** (yerel `main` ucu).
- `karadul.__file__` worktree yolunu gösteriyor. Çalışma zamanı verisi symlink (commit'lenmez).
- Ölçüm kökü: `~/karadul_olcum/runs/onarim-2026-11-18/P-S3b/`; dondurulmuş taban `taban_kod/` (cce2e8c'nin `git archive`'ı).

| Kalem | Durum | Commit |
|---|---|---|
| 0 — ön kayıt | bitti | 7a86f56 |
| 1 — varlık işaretleri | bitti (H1–H7 tuttu) | 41c8116 |
| 2 — `usage` gelenek kanalı | ölçüldü; kural yamada (H10 tuttu) | b402a02 + yama |
| 3 — `sort` `full_write` (`_exit`) | bitti (H8, H9 tuttu) | b58e3d5 |
| 4 — LTO'suz iç adlar | ölçüldü; tablo commit, davranış yamada (H11) | b402a02 + yama |
| 5 — aday kaydı raporda | bitti (H12 tuttu) | 212e301 |

## Kalem 1 — sürümden ve platformdan bağımsız varlık işaretleri

### a. Göster (önce)
- İşaret dağılımı (`isaret_tarama.py` → `isaret_tarama.json`): tablo ön kayıtta. Seçilenler: getopt (uzun seçenek iletilerinin
  `'%s%s'` biçimi) ve error ("Unknown system error"): geliştirme setinin 13 gnulib'siz programında 0, `/usr/bin`'in 640
  Mach-O dosyasında 0. Reddedilenler: c-stack (redis ×2, tmux ×2, `/usr/bin/sqlite3`), xalloc-die (tree, 8 `/usr/bin`),
  closeout (5 gnulib'siz, 20 `/usr/bin`).
- **Kaçış kusuru:** Ghidra decompile çıktısı tek tırnağı `\'` diye kaçırıyor; P-S3'ün xstrtol-error işaretleri üründe hiç
  eşleşmiyordu (geliştirme setinin coreutils'inde ham 0, kaçışı çözülmüş 8 ikili).
- Taban kod (cce2e8c, `taban_kod/`) Ghidra'sız yeniden oynatma, Mach-O (B koşularının `static/`'i; gcat P-S3 A'sının):

| İkili | Taban: varlık | Taban: kanal adı (GT) |
|---|---|---|
| gettext, envsubst, gmktemp (taze) | **yetersiz** (1 modül: version-etc) | 0 (usage, xalloc_die, close_stdout, version_etc tutuldu) |
| idn2 (taze) | yeterli (progname + version-etc) | 0 (version_etc `lto_yerlesimi`) |
| gsort (taze) | yeterli (version-etc + argmatch) | usage doğru |
| gcat (P-S3'te görüldü) | yetersiz (1) | 0 |
| xz (taze, gnulib'siz) | yetersiz (0) | 0 |

### b. Onar
- `karadul/analyzers/gnulib_fingerprints.py`: `unescape_ghidra_quotes` (s. ~375) ve `presence_evidence` artık kaçışı çözülmüş
  metinde arıyor; `GnulibPresenceMarker.glibc_shared`; yeni modüller `getopt` ve `error` (`glibc_shared=True`); version-etc'ye
  "Written by %s, %s, and %s."; yeterlilik = ≥ 2 modül VE en az biri glibc ile ortak olmayan (`GnulibPresence.glibc_shared_modules`;
  kanıt satırı "hepsi glibc ile ortak" der). `stages.py` değişmedi (aday kaydı biçimi aynı).

### c. Yeniden say (Ghidra'sız; `yeniden_kos.sh taban|k1`, özet `ozet.py`)
Ölçülen kod `k1_kod/` (taban + yeni `gnulib_fingerprints.py`, sha256 `3e1e6e1e…`; commit'lenen dosyayla aynı).

| # | Ölçü | Taban | Yeni | Hüküm |
|---|---|---|---|---|
| H1 | geliştirme seti coreutils dışı 13: gnulib yazımı / varlık | 0 / 13'ü 0 modül | **0** / 13'ü 0 modül | tuttu |
| H2 | geliştirme seti coreutils: doğru / yanlış | 620 / 1 | **620 / 1** | tuttu (modül sayısı 3-6 → 4-7: kaçış + yeni modüller) |
| H3 | /usr/bin 640 Mach-O: yeterli (`usr_bin_varlik.py`) | — | **0** (640'ının hepsi 0 modül) | tuttu |
| H4 | taze gnulib'li Mach-O 5: yeterli | 2 / 5 | **5 / 5** (2-4 modül) | tuttu |
| H4 | gcat (görülmüş): yeterli | hayır (1) | evet (version-etc + getopt) | — |
| H5 | taze gnulib'li Mach-O 5: kanal doğru / yanlış (GT) | 1 / 0 | **8 / 0** (yanlış %0) | tuttu |
| H6 | xz (taze, gnulib'siz) | 0 ad, 0 modül | **0 ad**, 0 modül | tuttu |
| H7 | korpuslar Debian 9.4 / Ubuntu 9.4 / od-pr: doğru / yanlış | 29/0, 35/0, 14/1 | aynı | tuttu |

- Yeni doğru adlar (taze 5): gettext ve envsubst'te `usage`, `xalloc_die`, `close_stdout`; gmktemp'te `usage` (gsort `usage`
  tabanda da vardı). Tutulan: idn2 / gsort / gmktemp `version_etc` (`lto_yerlesimi`, LTO'suz yerleşim — kalem 4).
- **gcat (ayrı satır, taze değil):** 1 doğru (`usage`) / **1 yanlış**: `close_stdout` "write error" dizgisinin TEK sahibi olan
  fonksiyona yazıldı, GT'de `write_error` (coreutils `system.h`'deki satır içi yardımcı). Ayrıştırıcı (close_stdout ↔ write_error)
  bugün yalnız iki aday varken çalışıyor; gcat'te `close_stdout`'un kendisi dizgiyi decompile çıktısında taşımıyor (tek aday).
  Ön kayıtta yok; kalem 1'in kuralı değiştirilmedi. Öneri ve ayrı ölçüm: aşağıda "Ek bulgu".
- Sadakat notu: yeniden oynatmanın "kayıtlı gnulib adı" karşılaştırması (`sadakat_bozuk`) geliştirme setinde taban kodla da
  bozuk çıkıyor: köken kayıtları P-S3'ten ÖNCEKİ ürün koşusuna (`urun-yeni2`, 1.22.1) ait; taban kod P-S3 sonrası. Beklenen.

### d. Test ve mutasyon
- `tests/test_ps3b_gnulib_varlik.py` (10): version-etc + getopt (Ghidra kaçışlı) yeter; version-etc + error yeter; version_etc_arn'ın
  "Written by" dizgisi version-etc sayılır; getopt + error (yalnız glibc ortak) yetmez ve kanıt satırı söyler; tek yeni modül yetmez;
  tek tırnaklı işaret kaçışla eşleşir; çözücü; kanıt satırı; yeni işaretler upstream kaynakta ve glibc işaretleri yalnız getopt / error.
  **Eski kodda 7 / 9 kırmızı** (o anki 9 testten; 2'si aşırı tutma bekçisi), 10'uncusu sonradan eklendi ve mutantla sınandı.
- Mutasyon `scripts/measurement/mutation_specs_ps3b.json`: **7 / 7 öldü** (kaçış çözülmez, çözücü etkisiz, glibc koşulu yok,
  getopt glibc'siz, getopt işareti eşleşmez, error işareti eşleşmez, "Written by" yok). P-S3'ün `mutation_specs_ps3.json`'u
  yeni kodla 17 / 17, `mutation_specs_on_ad_onarimi.json` 15 / 15. Koşum sonrası dosya sha256 yine `3e1e6e1e…`.
- İlgili testler (`test_ps3b_gnulib_varlik`, `test_ps3_gnulib_kanit`, `test_gnulib_fingerprints`, `test_main_gnulib_seed_ordering`): 75 geçti.

## Kalem 3 — `sort`'ta `full_write` yanlışı (`_exit` dışlaması)

### a. Göster
- Yeniden oynatma (kalem 1 kodu): geliştirme setinin TEK kalan gnulib yanlışı coreutils `sort` `FUN_001079e0` = `full_write`.
  Çağrı çizgesi (`urun-yeni2` sort): `callee_count` 4 — `strlen`, `write`, `_exit`, `FUN_0010e300`; çağıranlar 0x108a20,
  0x108cd0 (geniş; yerleşim kuralı tutmuyor). gnulib `full-write.c`, `safe-write.c`, `safe-read.c`'de `_exit` YOK (grep).

### b. Onar
- `gnulib_fingerprints.py`: `GnulibCallShape.excluded_callees` (NOR); `full_write` için `("_exit",)`; `match_call_shape` dışlanan
  çağrıyı yapan fonksiyonu o şekle eşlemez. Öbür şekiller değişmedi.

### c. Yeniden say (Ghidra'sız; `yeniden_kos.sh k3`, kod `k3_kod/`, sha256 `8820e7ce…` = commit'lenen dosya)
| # | Ölçü | Kalem 1 sonrası | Kalem 3 sonrası | Hüküm |
|---|---|---|---|---|
| H8 | geliştirme seti coreutils doğru / yanlış | 620 / 1 | **620 / 0** | tuttu |
| H9 | Ubuntu 9.4 `cat` `full_write` (GT doğru) | var | var | tuttu |
| H9 | k1 ↔ k3 değişen ad (bütün setler) | — | yalnız sort `FUN_001079e0` (`full_write` gitti; yerine başka gnulib adı yok) | tuttu |
| — | Mach-O kabul (taze 5 / gcat / xz) | 8/0, 1/1, 0 | aynı | — |

### d. Test ve mutasyon
- `tests/test_ps3b_full_write.py` (4): sort düzeni ad almaz; `_exit`'siz write sarmalayıcısı (LTO'lu Ubuntu düzeni) `full_write` alır;
  `match_call_shape` dışlaması (`close_stream` etkilenmez); dışlanan çağrı upstream kaynakta yok. **Kalem 1 kodunda 3 / 4 kırmızı**
  (1 bekçi). Mutant: `ps3b_full_write_dislama_yok`, `ps3b_dislama_uygulanmaz` → spec'in tamamı **9 / 9 öldü**.

## Kalem 5 — aday kaydı raporda

### a. Göster
- `static/gnulib_candidates.json` (P-S3) yalnız diskteydi: rapor verisinde (`report_data.py`), dört raporlayıcıda ve temiz çıktının
  HTML'inde `gnulib` geçmiyordu (`grep`). Taban B koşularında (6 Mach-O) yazılmayan aday 1-3 / ikili, raporda 0 iz.

### b. Onar
- `karadul/reporting/report_data.py`: `gnulib_candidates(workspace)` (yapıt yoksa `None`: kanal koşmadı, 0 aday DEĞİL) ve
  `gnulib_candidates_note`; "Name Reliability" bölümüne (`_naming` → eski gövde `_naming_labels`) `extra["gnulib_candidates"]`
  (tutulan sayı, nedenlere göre kırılım, varlık kanıtı satırı, en çok 20 aday: anahtar, aday ad, kanal, neden, kanıt) ve özet
  cümlesi ("N candidate name(s) withheld, no name written (neden: sayı; evidence in static/gnulib_candidates.json)"; tutulan yoksa
  "no candidate withheld"). Rapor dili İngilizce (bölümün öbür cümleleri gibi).
- `karadul/reporting/sections_render.py`: `gnulib_candidate_rows`; HTML ve Markdown'da bölümün altında "gnulib candidates (no name
  written)" tablosu + varlık kanıtı satırı (aday yoksa tablo yok). JSON / SARIF `to_dict` üstünden `extra`'yı zaten taşıyor.
- Fonksiyon kartı (`ui/**`) bu pakette değil (dokunma listesi); arayüz `naming` bölümünün `extra.gnulib_candidates`'ını okuyabilir.

### c. Ürün koşusu (A; H12)
- 6 / 6 koşuda (gettext, envsubst, idn2, gsort, gmktemp, xz) `reports/report.md`, `report.json` ve `out/report.html` bölümü taşıyor;
  sayı `gnulib_candidates.json`'daki `withheld` ile aynı (0, 0, 1, 1, 1, 1); tutulan yoksa tablo yok (`a_denetle.py`). **H12 tuttu.**

### d. Test ve mutasyon
- `tests/test_ps3b_rapor_gnulib.py` (4; P07 `urun_cat` fikstürü + gerçek ürün kaydından kısaltılmış aday kaydı): rapor verisi
  (sayı, kırılım, kanıt), dört çıktı (JSON, Markdown, HTML, temiz HTML), tutulan yokken tablo yok, yapıt yokken aday iddiası yok.
  Eski kodda içe aktarım hatası (4 / 4 kırmızı). Rapor testleri (`*rapor*`, `*report*`, `*sarif*`, P07, P-GUV) 198 geçti.
- Mutant (spec'e eklendi): aday kaydı rapora girmez, uygulananlar da sayılır, yapıt yokken 0 yazılır, tablo çizilmez → **4 / 4**;
  spec toplamı 13 / 13.

## Ürün koşusu (B ↔ A, Mach-O kabul seti; `kos_mac.sh`, `a_denetle.py`)
- B: taban `taban_kod/` (cce2e8c); A: `a_kod/` (kalem 1 + 3 + 5; `karadul/` worktree'yle `diff -rq` aynı, kalem 5 commit'lenmeden
  önce). `PYTHONHASHSEED=0`, sıralı, koşu başına `KARADUL_CACHE_DIR`. Süreler A: gmktemp 77, idn2 29, gettext 48, envsubst 60, xz 60,
  gsort 174 sn (B: 95, 40, 53, 63, 68, 157).

| İkili | B: `on_ad:gnulib` | A: `on_ad:gnulib` (GT) | A = yeniden oynatma | B ↔ A değişen genel ad anahtarı |
|---|---|---|---|---|
| gettext | 0 | usage, xalloc_die, close_stdout (3 doğru) | evet | 3 (hepsi gnulib) |
| envsubst | 0 | usage, xalloc_die, close_stdout (3 doğru) | evet | 3 (hepsi gnulib) |
| idn2 | 0 | 0 (version_etc tutuldu) | evet | 0 |
| gsort | usage | usage (doğru) | evet | 0 |
| gmktemp | 0 | usage (doğru) | evet | 1 (gnulib) |
| xz (gnulib'siz) | 0 | 0 | evet | 0 |

- Taze 5 gnulib'li Mach-O: ürün çıktısında kanal **1 → 8 doğru, 0 yanlış**; başka değişen ad anahtarı 0. xz 0. Yeniden oynatmanın
  öngörüsü ürün çıktısıyla 6 / 6 aynı.

## Kalem 2 — `usage` gelenek kanalı (ayrı ölçüm satırı; kural `stages.py` yamasında)

### a. Göster (kalem 3 kodu, Ghidra'sız; `usage_olc.py k3`)
| Grup | `usage` önerisi | Karar | GT |
|---|---|---|---|
| geliştirme seti coreutils (gnulib'li) | 101 | uygulandı | 101 doğru |
| taze Mach-O gnulib'li (gettext, envsubst, gsort, gmktemp) + gcat | 5 | uygulandı (kalem 1'den sonra) | 5 doğru |
| geliştirme seti gnulib'siz: zstd | 1 | tutuldu (`gnulib_kaniti_yetersiz`) | **doğru** (P-S3'te kaybedilen) |
| taze Mach-O gnulib'siz: xz | 1 | tutuldu | **yanlış** (GT `message_help`) |

- Yani "Usage: %s" tek başına gnulib'siz programda 1 doğru / 1 yanlış: kanıtsız `usage` yazılmamalı (xz).
- İkinci bağımsız kanıt (ön kayıttaki aday kural): ürünün entry'den kurtardığı `main` adayı doğrudan çağırıyor. zstd: evet
  (`main` = `FUN_001063c0`, aday 3 çağıranlı); xz: hayır (Mach-O'da `_recover_main_from_entry` `main` bulmuyor → kanıt yok →
  tutulur). gnulib'li programlarda kanal değişmedi (varlık kanıtıyla).

### b. Onar → yama (`yamalar/P-S3b__stages.py.patch`, P-S4 uygular)
- `_offer`: varlık kanıtı yetersizken ad `USAGE_CONVENTION_NAME` (`usage`) ve `_main_caller(fk)` bir `main` anahtarı döndürüyorsa
  ad yazılır, karar `applied` / `usage_gelenegi`, kanıt satırı `evidence_convention` ("gnulib varlık kanıtı yok; 'Usage: %s' tek
  fonksiyonda ve main (FUN_…) onu doğrudan çağırıyor"). Başka ad için istisna yok.
- `USAGE_CONVENTION_NAME` `gnulib_fingerprints.py`'de (bu pakette commit'lendi; yama onu içe aktarıyor).

### c. Yeniden say (yama dalda uygulanmış `yama_kod/`, Ghidra'sız; `yama_fark.py`)
| # | Ölçü | Yama öncesi | Yamalı | Hüküm |
|---|---|---|---|---|
| H10 | geliştirme seti gnulib'siz 13: `usage` doğru / yanlış | 0 / 0 | **1 / 0** (zstd) | tuttu |
| — | xz (Mach-O gnulib'siz) | 0 | 0 (tutuldu: `main` yok) | — |
- Örneklem küçük (yazılan 1): kesinlik iddiası yok. xz'in tutulması kuralın değil Mach-O'da `main` kurtarılamamasının sonucu;
  Mach-O'da `main` kurtarılınca xz `message_help`'i `main` çağırmıyorsa (GT'de çağıran `FUN_` tek; bakılmadı) yine tutulur.

## Kalem 4 — LTO'suz yapıda iç adlar (ölçüm + yama)

### a. Ölç (kalem 3 kodu; `lto_yerlesimi` ile tutulan adaylar; `ic_ad_olc.py` → `ic_ad_k3.json`)
| Set | Dış ad (tutulan) | GT adı | İç ad adayı | Katı | Gevşek |
|---|---|---|---|---|---|
| geliştirme seti coreutils | version_etc ×104 | version_etc_arn | version_etc_arn | **104 / 104** | 104 / 104 |
| geliştirme seti coreutils | full_write ×8 | safe_write | safe_write | **8 / 8** | 8 / 8 |
| geliştirme seti coreutils | hard_locale ×104 | setlocale_null_r_unlocked | setlocale_null_r | 0 / 104 | 104 / 104 |
| Debian 9.4 (5) | version_etc ×5, hard_locale ×5, full_write ×1 | version_etc_arn, setlocale_null_r, safe_write | aynı | 11 / 11 | 11 / 11 |
| Ubuntu 9.4 (LTO'lu) | hard_locale ×1 (expr) | hard_locale.constprop.0 | setlocale_null_r | 0 / 1 | 0 / 1 |
| Mach-O (idn2, gsort, gmktemp, gcat) | version_etc ×4 | version_etc_arn | version_etc_arn | **4 / 4** | 4 / 4 |

- **H11:** version_etc_arn katı 113 / 113 ve safe_write 9 / 9 (≥ %90) → kural + yama. setlocale_null_r katı 5 / 110 (yalnız 2023
  gnulib'i; 2024+ adı `setlocale_null_r_unlocked`), gevşek 109 / 110 → **yazılmadı** (sürüme bağlı; Ubuntu expr'deki tek yanlış,
  yerleşim kuralının LTO'lu yapıdaki bilinen yanlış tutması). Aday kaydında `hard_locale` `lto_yerlesimi` olarak kalıyor.
- Geliştirme ile kabul ayrımı: tablo geliştirme setinde kuruldu; Mach-O 4 / 4 (3'ü taze) ve Debian 9.4 11 / 11 geliştirme seti dışı.

### b. Onar
- `gnulib_fingerprints.py` (bu pakette commit): `LTO_LESS_INNER_NAMES` (`version_etc` → `version_etc_arn` / version-etc.c,
  `full_write` → `safe_write` / safe-read.c), `lto_less_inner_name`. Davranış `stages.py` yamasında: `lto_less_layout` tutuyorsa ve
  tabloda iç ad varsa iç ad yazılır (`applied`, `lto_yerlesimi_ic_ad`, `outer_name`, `caller_callee_counts`, `evidence_layout`);
  tabloda yoksa eskisi gibi tutulur. Çağrı şekli katmanı iç adla dolu anahtarı aday sayar (ikinci çağrı aynı kalsın).

### c. Yeniden say (yamalı, Ghidra'sız; `yama_fark.py`) — kalem 3 ↔ yama değişen adlar
| Set | Yeni ad | GT |
|---|---|---|
| geliştirme seti coreutils | version_etc_arn 104, safe_write 8 | 112 doğru |
| geliştirme seti gnulib'siz | usage 1 (zstd, kalem 2) | doğru |
| Debian 9.4 | version_etc_arn 5, safe_write 1 | 6 doğru |
| Mach-O | version_etc_arn 4 (idn2, gsort, gmktemp, gcat) | 4 doğru |
| başka değişen ad | 0 | — |
- Yamalı toplam: geliştirme seti coreutils **732 doğru / 0 yanlış** (kalem 3 sonrası 620 / 0); gnulib'siz 1 / 0; Mach-O 13 / 1
  (yanlış: gcat `close_stdout`, ek bulgu); korpus Debian 9.4 35 / 0, Ubuntu 9.4 35 / 0, od / pr 14 / 1 (P-S3'ten beri `mbslen`).

### d. Test ve mutasyon
- Commit'lenen: `tests/test_ps3b_ic_ad.py` (3: tablo, iç ad upstream kaynakta tanımlı, `usage` adı); mutant 3 / 3 (hard_locale
  tabloya girer, version_etc_ar, kaynakta olmayan ad) → P-S3b spec toplamı **16 / 16**.
- Yamayla gelen: `yamalar/P-S3b__test_ps3b_stages_yama.py.patch` (yeni dosya, 6 test: main çağırıyorsa usage, çağırmıyorsa yok,
  gelenek yalnız usage; ince çağıranda iç ad + hard_locale tutulur, geniş çağıranda dış ad, ikinci çağrı aynı) — **yamasız kodda 2 / 6
  kırmızı** (4 bekçi), yamalı kodda 6 / 6. `yamalar/P-S3b__test_ps3_gnulib_kanit.py.patch`: P-S3'ün iki yerleşim testi yeni davranışa
  (iç ad) uyarlanır (beklenti: version_etc_arn yazılır, hard_locale tutulur; amaç aynı: dış ad ve başka gnulib adı yazılmaz).
- Yamalı kodda mutasyon (`~/karadul_olcum/runs/onarim-2026-11-18/P-S3b/mutation_specs_ps3b_yama.json`): **5 / 5 öldü** (gelenek
  kapalı, main kanıtı aranmaz, istisna her ada, iç ad yazılmaz, iç adla dolu anahtar çağrı şeklinde aday değil).
- Yamalı kodda gnulib / ön ad / köken testleri (`grep -l "gnulib\|pre_name\|naming_provenance\|_offer" tests/*.py`): 752 geçti / 0.

## Ek bulgu (ön kayıtta yok; kural değiştirilmedi) — gcat `close_stdout` → `write_error`
- gcat'te "write error" dizgisi decompile çıktısında TEK fonksiyonda (`FUN_10000a924`); GT adı `write_error` (coreutils
  `system.h` satır içi yardımcısı: `fflush` + `fpurge` + `clearerr` + `error`). Ayrıştırıcı (`close_stdout` ↔ `write_error`) yalnız
  dizgi iki adaydayken çalışıyor; burada tek aday olduğu için `close_stdout` yazıldı. Geliştirme setinde (ELF) 105 / 105 doğru.
- Öneri (ayrı ön kayıtla): `close_stdout` dizgi adayına tek aday olsa da ayrıştırıcının dışlama koşulu uygulansın (`__fpurge` /
  `fpurge` / `clearerr` / `clearerr_unlocked` çağıran fonksiyon `close_stdout` olamaz; closeout.c'de yok). Mach-O'da çağrı adlarının
  biçimi (`_fpurge` mi `fpurge` mı) Ghidra çıktısında doğrulanmalı. Bu pakette uygulanmadı (gcat taze değil; tek örnek).

## P-S4 için (`yamalar/P-S3b__stages.py.patch`)
- **Uygulanacak yamalar (sırayla, worktree kökünden):** `git apply docs/arge/2026-11-18_onarim/yamalar/P-S3b__stages.py.patch`,
  `…/P-S3b__test_ps3_gnulib_kanit.py.patch`, `…/P-S3b__test_ps3b_stages_yama.py.patch` (yeni test dosyası). Taban: P-S3b dalının ucu
  (`gnulib_fingerprints.py`'de `USAGE_CONVENTION_NAME`, `lto_less_inner_name` olmalı; yama onları içe aktarıyor). `git apply --check`
  cce2e8c + P-S3b commit'leri üstünde temiz.
- **Gerekçe:** (1) kalem 2 — gnulib'siz programda `usage` yalnız "Usage: %s" tekilliği + `main`'in doğrudan çağırması (iki bağımsız
  kanıt) varsa: zstd `usage` geri gelir (GT doğru), xz'in `message_help`'i (GT) `usage` olmaz. (2) kalem 4 — LTO'suz yerleşimde dış ad
  yerine iç ad: version_etc_arn 113 / 113, safe_write 9 / 9 katı doğru; hard_locale bilerek tablo dışı. Yamalı yeniden oynatma: yeni 123
  ad, hepsi doğru; başka değişen ad 0 (bkz. kalem 2-c, 4-c).
- **Değişen davranış (ürün):** `static/gnulib_candidates.json`'da yeni nedenler `usage_gelenegi` ve `lto_yerlesimi_ic_ad` (`applied`;
  ek alanlar `evidence_convention`, `outer_name`); `stats["gnulib_withheld"]` geliştirme setinde ikili başına 3 → 1 (yalnız hard_locale).
  Kalem 5'in rapor bölümü bunları kendiliğinden doğru sayar (yalnız `withheld` sayılıyor).
- **Sınanacak testler:** `tests/test_ps3b_stages_yama.py` (6; yamasız kodda 2 kırmızı), `tests/test_ps3_gnulib_kanit.py` (yamayla
  uyarlanan 2 test dahil 15), `tests/test_ps3b_gnulib_varlik.py`, `tests/test_ps3b_full_write.py`, `tests/test_ps3b_ic_ad.py`,
  `tests/test_main_gnulib_seed_ordering.py`, `tests/test_gnulib_fingerprints.py`; geniş: `grep -l "gnulib\|pre_name\|naming_provenance"`
  (yamalı kodda 752 geçti). Mutasyon: `~/karadul_olcum/runs/onarim-2026-11-18/P-S3b/mutation_specs_ps3b_yama.json` (5 mutant; yama
  uygulanınca `scripts/measurement/mutation_specs_ps3b.json`'a taşınabilir) + `mutation_specs_ps3.json` (17) + `mutation_specs_ps3b.json` (16).
- **Ölçüm önerisi:** yama birleşince geliştirme setinde `on_ad:gnulib` doğru ad 620 → 732 beklenir (yeniden oynatma); birleşik ölçümde
  gnulib kanalının güven etiketi (`naming_labels.MEASURED_PRE_NAME_PRECISION`, şu an 0,706) yenilenmeli: P-S3 + P-S3b sonrası
  geliştirme seti katı kesinlik 620 / 620 (yamasız), 732 / 732 (yamalı).

## Ön kayıt hükümleri
| # | Hüküm | Not |
|---|---|---|
| H1 | tuttu | gnulib'siz 13: 0 ad, 0 modül |
| H2 | tuttu | coreutils 620 / 1 (kalem 1); kalem 3'le 620 / 0 |
| H3 | tuttu | /usr/bin 640 Mach-O: yeterli 0 (hepsi 0 modül) |
| H4 | tuttu | taze gnulib'li Mach-O 5 / 5 yeterli (taban 2 / 5); gcat yeterli |
| H5 | tuttu | taze 5: kanal 8 doğru / 0 yanlış (taban 1 / 0); ürün koşusu aynı |
| H6 | tuttu | xz 0 ad |
| H7 | tuttu | korpuslar aynı |
| H8 | tuttu | coreutils yanlış 1 → 0 |
| H9 | tuttu | Ubuntu 9.4 `full_write` korunur; değişen tek ad sort'unki |
| H10 | tuttu (yamalı) | gnulib'siz `usage` 1 doğru / 0 yanlış (zstd); xz tutulur |
| H11 | tuttu | version_etc_arn 113 / 113, safe_write 9 / 9 → yama; setlocale_null_r katı 5 / 110 → tablo dışı |
| H12 | tuttu | 6 / 6 raporda bölüm, sayılar eşit |
| Aykırı öncül 1 | çürütüldü | getopt / error gnulib'siz Mach-O'da (/usr/bin 640, xz) bulunmadı |
| Aykırı öncül 2 | çürütüldü | gettext 1.0 ve libidn2 de getopt + error (+ version-etc) taşıyor: 5 / 5 |
| Aykırı öncül 3 | taze sette çürütüldü, gcat'te kısmen doğrulandı | taze 5'te yanlış 0; gcat'te 1 yanlış (`write_error`, ek bulgu) |

## Tam takım
`PYTHONDONTWRITEBYTECODE=1 python -m pytest -q -p no:cacheprovider` (worktree, b402a02; çalışma zamanı verisi symlink'li): **9 759 geçti, 10 atlandı, 153 seçim dışı, 0 kaldı** (1 007 sn; makinede başka ajanların koşularıyla eşzamanlı). Main ucunda (cce2e8c) tam takım DURUM.md'ye göre 9 653; fark bu paketin ve P20 / P22d'nin yeni testleri.

## Ana oturumun bilmesi gerekenler
1. **Yama (P-S4):** `yamalar/P-S3b__stages.py.patch` + iki test yaması; gerekçe ve testler "P-S4 için"de. Yamasız main'de kalem 2 (zstd
   `usage`) ve kalem 4 (123 iç ad) ürün davranışına girmez; kalem 1, 3, 5 girer.
2. **Ek bulgu (gcat `close_stdout` → GT `write_error`):** Mach-O coreutils'te "write error" tek fonksiyonda kalınca ayrıştırıcı
   devreye girmiyor. Taze 5 ikilide görülmedi; ayrı ön kayıtla onarılmalı (öneri yukarıda). Kalem 1'den önce bu yanlış gcat'te yoktu
   (kanal susuyordu) — kalem 1 gcat'te 1 doğru + 1 yanlış getirdi; taze sette 8 / 0.
3. **Güven etiketi:** gnulib kanalının ölçülmüş kesinliği (`naming_labels`, 0,706) P-S3 + P-S3b sonrası bayat: geliştirme seti katı
   620 / 620 (yamasız), taze Mach-O 8 / 8. Birleşik ölçümde yenilenmeli (dokunma listesinde).
4. **Kaçış kusuru genel olabilir:** Ghidra'nın `\'` kaçışı, decompile dizgisini kaynak metniyle karşılaştıran öbür kanallarda da
   (ör. dizgi parmak izleri, KS-1 dizgi çapaları) eşleşmeyi bozabilir. Bu pakette yalnız varlık işaretlerinde çözüldü; parmak izi
   çapaları (`GNULIB_FINGERPRINTS`) tek tırnak içermiyor (denetlendi: hiçbirinde `'` yok), öbür kanallara bakılmadı.
5. **Mach-O'da `main` kurtarılmıyor** (`_recover_main_from_entry`, `usage` adayı olan 6 Mach-O ikilinin hiçbirinde `main` bulmadı): kalem 2'nin gelenek kanalı Mach-O'da çalışmaz;
   ayrı iş.
6. **Ölçüm hijyeni:** salt okur kökler (`urun-yeni2-f30ac9a`, `aday-f893d72`, `on-ad-onarimi-2026-11-11`, `P-S3`) bu paketin
   başından beri 0 yeni / değişen dosya (`find -newer`). Kabul seti kopyaları ve GT `P-S3b/mac_kabul/` altında; ürün koşuları
   `P-S3b/B`, `P-S3b/A`; dondurulmuş ağaçlar `taban_kod/`, `k1_kod/`, `k3_kod/`, `a_kod/`, `yama_kod/` (silinebilir, onaya bağlı).
7. Ölçüm betikleri depo dışında (`P-S3b/`): `isaret_tarama.py`, `usr_bin_varlik.py`, `gnulib_yeniden.py` (P-S3'ün uyarlaması,
   `--mac-kabul`), `yeniden_kos.sh`, `ozet.py`, `kos_mac.sh`, `a_denetle.py`, `ic_ad_olc.py`, `usage_olc.py`, `yama_fark.py`,
   `mutation_specs_ps3b_yama.json`.
8. `~/.claude/team-state/discussion.md`'ye yazılmadı (paket metni `~/.claude/**` yazmayı yasaklıyor).
9. Süre: hedef 90 dk aşıldı (yaklaşık 2,5 saat); kalem 1 erkenden commit'lendi.

## PAKET BİTTİ
