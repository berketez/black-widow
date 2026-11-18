# P-S3b — gnulib ön ad kanalı: sürümden ve platformdan bağımsız varlık kanıtı + kalan gnulib ad kusurları — ilerleme

Brif: `ONARIM_BRIF.md`. Paket metni: `gonderim/PS3b.md`. Karar: K-2. Önceki paket: `P-S3.md` (H5 tutmadı).
Ön kayıt: `P-S3b_on_kayit.md` (kod değişmeden önce commit'lendi).

- Taban: worktree `origin/main`'den (d2f205d) açıldı; `git merge --ff-only main` → **cce2e8c** (yerel `main` ucu).
- `karadul.__file__` worktree yolunu gösteriyor. Çalışma zamanı verisi symlink (commit'lenmez).
- Ölçüm kökü: `~/karadul_olcum/runs/onarim-2026-11-18/P-S3b/`; dondurulmuş taban `taban_kod/` (cce2e8c'nin `git archive`'ı).

| Kalem | Durum | Commit |
|---|---|---|
| 0 — ön kayıt | bitti | 7a86f56 |
| 1 — varlık işaretleri | bitti (H1–H7 tuttu) | (kalem 1 commit'i) |
| 2 — `usage` gelenek kanalı | bekliyor | |
| 3 — `sort` `full_write` (`_exit`) | bekliyor | |
| 4 — LTO'suz iç adlar | bekliyor | |
| 5 — aday kaydı raporda | bekliyor | |

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
