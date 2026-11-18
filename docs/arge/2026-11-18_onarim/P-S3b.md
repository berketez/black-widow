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
| 2 — `usage` gelenek kanalı | bekliyor | |
| 3 — `sort` `full_write` (`_exit`) | bitti (H8, H9 tuttu) | b58e3d5 |
| 4 — LTO'suz iç adlar | bekliyor | |
| 5 — aday kaydı raporda | bitti (H12 tuttu) | (kalem 5 commit'i) |

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
