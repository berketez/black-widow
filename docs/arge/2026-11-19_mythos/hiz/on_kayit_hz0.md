# HZ-0 ön kaydı — boş makinede taban ölçümü (koşudan ÖNCE commit)

- Yazıldı: 2026-11-20, Dalga 0 OLCEK paketi. Koşu yapılmadı.
- Dayanak: `hiz/PLAN.md` §1 ve HZ-0 (adımlar 1–8, kabul, ön kayıt), `KARARLAR.md` A-9 (oranla kabul) ve A-18 (ÖLÇ-1 ile tek koşu), `SONRAKI_OTURUM.md` §5 (Avast: HZ-0 iki kolla; dışlamayı Berke yapar), `hiz/BULGULAR.md`.

## Koşu düzeni (değişmez)

- Kuyruk `scripts/arge/olcek/gece_kosusu.py --gece 1` (gruplar `hz0`, `p16c`, `k_appcds`, `avast`); her koşu `scripts/measurement/olcek_kos.py` (ÖLÇ-A) ile, her biri `ghidra_kuyruk.sh` içinde, aynı anda tek Ghidra. Ürün ağacı `~/karadul_olcum/urun-<commit>` (commit `kunye.json` → `agac.commit`).
- Hedefler (`hiz/PLAN.md` §1): K = `debian/coreutils/sort` (625 fn), O = `mac/tmux` (2 821 fn), B = Ollama 0.40.3 arm64 dilimi (13 559 fn; **ayar `gosteri.yaml`**, "Objective-C Message Analyzer" kapalı: gösteri koşusunun koşulu). K ve O'nun girdisi `~/karadul_olcum/runs/urun-onarim-a62f15e/<hedef>` çalışma alanının `raw/` kopyası (sha256 `target_info.json` ile denetlenir).
- Sıra K1 O1 B1 K2 O2 B2 K3 O3 B3; duvar 10 800 sn; her koşu boş `KARADUL_CACHE_DIR`; her birine `scripts/arge/hiz/hz0_ek.py` eşlik eder (30 sn'de bir `ps -M`; başta ve sonda açma gecikmesi ve donanım künyesi).
- Boş makine (`hiz/PLAN.md` §1): koşu başında (koşucunun kendi kaydı, kuyruk kilidi alındıktan sonra) ve sonunda 1 dk yük < 0,25 × `os.cpu_count()` (bu makinede 3,5). Bitiş denetimi: koşu bittikten sonra en çok 180 sn içinde eşiğin altına inmeli (1 dk ortalamanın kendi yükünden sönümü; gerekçe `gece_kosusu.py` belge başı). Geçersiz koşu en çok 2 kez yinelenir.
- Ek koşular (medyana girmez): `b_jfr` (B × 1, JFR `settings=profile`; `--gece 2`'de), `k_appcds` (K × 4, `-XX:+AutoCreateSharedArchive`), `p16c` (K ve O için çözümleyici süreleri). JFR ile AppCDS aynı koşuya konmaz: arşiv dökülürken JVM JFR'ı kapatıyor (`java -version` ile denendi: "JFR will be disabled during CDS dumping").

## Öngörüler (planın metni aynen; ölçüm yolu yanında, koşudan önce sabitlendi)

| No | Öngörü (`hiz/PLAN.md` HZ-0, aynen) | Ölçüm yolu |
|---|---|---|
| H0-a | B'de BSim Ghidra köprüsünün ≥ %40'ı (yük altında %51,2). | B'nin 3 geçerli tekrarının ortancası: BSim süresi / `ghidra_status.duration_seconds`. BSim süresi `kunye.json` → `ghidra.adim_sureleri`: HZ-1 alanı varsa `bsim_ingest + bsim_query`, yoksa dosya zamanından `bsim` (`function_id.json` → `bsim_shadow.json`). Kaynak `ghidra.adim_kaynagi`'nda. |
| H0-b | K'de toplam duvarın en büyük kalemi `feedback_loop`. | `python scripts/arge/hiz/zaman_cizelgesi.py taban --kok <gece kökü>` kalem dökümü (`_ozet_payi`) yalnız `hz0/K/*` koşularında: en büyük kalem `R: feedback_loop`. |
| H0-c | B'de CFG ms / fonksiyon, O'nunkinin ≥ 3 katı (yük altında 44,3 ↔ 2,2). Tutmazsa doğrusal üstü büyüme yük kaynaklıydı → HZ-4b'nin önceliği düşer. | `ghidra.adim_sureleri.cfg` × 1000 / `ghidra.fonksiyon`; B ortancası / O ortancası ≥ 3. |
| H0-d | JFR'de CFG ve xref aralıklarındaki örneklerin ≥ %50'si Ghidra program veritabanı / blok modeli çerçevelerinde (`ghidra.program.database.*`, `ghidra.program.model.block.*`), < %20'si JPype çerçevelerinde. Tutarsa darboğaz Java tarafının işidir (HZ-4a / HZ-4b sayıyı azaltarak kazandırır); tutmazsa geçiş maliyetidir. | `b_jfr/B/1/kayit.jfr`: `jfr print --events jdk.ExecutionSample`; aralıklar `ghidra.cikti_zamani_sn` (xref: `types.json` → `xrefs.json`; CFG: `pcode.json` → `cfg.json`). Bir örnek, yığınında yukarıdan ilk `ghidra.` ya da `org.jpype.` / `jpype.` ile başlayan çerçevenin sınıfına göre sayılır; ikisi de yoksa "öbür". |
| H0-e | boş makinede var olan `.c` açma ortancası ≥ 0,3 ms (Avast etkin). Tutarsa HZ-6'nın önceliği yükselir. | `hz0_ek.json` → `acma_bas.oku_ac.ortanca_ms` (başvuru dizini: `urun-onarim-a62f15e/mac/tmux` `decompiled/`, 1 000 dosya); 9 HZ-0 koşusunun ortancası. "Avast etkin" `hz0_ek.json` → `donanim_bas.sistem_uzantilari` satırlarından okunur. |

Ek öngörü (planın 5b adımı ve HZ-5 adım 8 eşiği; TAHMİN `hiz/BULGULAR.md` §4.2):

| No | Öngörü | Ölçüm yolu |
|---|---|---|
| H0-f | AppCDS: K'de ilk Ghidra adımı eksi otomatik analiz (JVM + içe aktarma + fonksiyon listesi) oranı ≤ 0,85. TAHMİN sınıf yükleme kısmı −%15–35 (§4.2). | pay: `k_appcds/K/{2,3,4}` ortancası; payda: `hz0/K/{1,2,3}` ortancası. Adım: `ghidra.adim_sureleri["otomatik_analiz+fonksiyonlar"]` (HZ-1 varsa `functions`) − `static/ghidra_log.txt` "Otomatik analiz: N sn". `k_appcds/K/1` arşivi kurar, hesaba girmez. |

## Kabul (planın)

9 koşunun 9'unun künyesi eksiksiz; her hedefte geçerli tekrarların uçtan uca süresinde (en büyük − en küçük) / ortanca ≤ 0,10 (aşarsa `gece_kosusu.py` o hedefe en çok 2 tekrar daha koşar; yine aşarsa kayda geçer); JFR kaydı açılabiliyor (`jfr summary kayit.jfr` çıkış 0).

## Avast kolu (HZ-0 adım 7) — hüküm biçimi (koşudan önce)

- **Kollar.** Dışlamasız = `hz0/K/{1,2,3}` ve `hz0/O/{1,2,3}` (aynı gece, aynı ürün). Dışlamalı = `~/karadul_olcum/runs/hiz-avast-dislama/<commit>/avast/{K,O}/{1,2,3}` (sıra K1 O1 K2 O2 K3 O3); Berke bu kökü Avast'ta dışlamış olmalı. `gece_kosusu.py` bu grubu yalnız `--avast-dislama-yapildi` verilirse koşar; verilmezse grup "Berke onayı yok" diye kayda geçer ve hüküm yazılmaz.
- **Ölçüler (hedef başına).**
  1. Açma gecikmesi: `hz0_ek.json` → `acma_son_kendi.oku_ac.ortanca_ms` (koşunun kendi `decompiled/` dizini; dışlamalı kolda dışlanan kökün içinde; 1 000 dosyaya kadar).
  2. Denetim: `acma_son_basvuru.oku_ac.ortanca_ms` (dışlanmayan başvuru dizini; iki kolda da aynı dizin).
  3. Uçtan uca: `kunye.json` → `boru.toplam_sn`.
- **Oran.** r = ortanca(dışlamalı 3 tekrar) / ortanca(dışlamasız 3 tekrar). "Ayrık" = iki kolun 3'er değeri örtüşmüyor (dışlamalının en büyüğü < dışlamasızın en küçüğü).
- **Anlamlı sayılan fark (koşudan önce sabit):**
  - Açma: r_açma ≤ 0,67 **ve** ayrık **ve** denetim dizininde r ∈ [0,8; 1,25] (fark dışlamaya özgü) → "dışlama açma gecikmesini anlamlı düşürüyor". Ayrıca r_açma ≤ 0,2 → "erişimde tarama açma maliyetinin baskın nedeni" (gerekçe: bu makinede var olanı açma ↔ yeni dosya oluşturma oranı düşük yükte 15–20; `hiz/BULGULAR.md` §4.4).
  - Uçtan uca: r_uç ≤ 0,95 **ve** ayrık → "dışlama uçtan uca süreyi anlamlı kısaltıyor" (gerekçe: HZ-0 kabulü tekrar yayılımına 0,10'a kadar izin veriyor; eşik bunun yarısı).
  - Öbür durumlar: "fark yok / ayırt edilemedi". r > 1,05 ve ayrık: "dışlamalı kol yavaş (beklenmedik)" diye ayrıca kayda.
- **Öngörü (H0-g):** en az bir hedefte açma farkı anlamlıdır (r_açma ≤ 0,67, ayrık, denetim tutarlı). Dayanak: `hiz/BULGULAR.md` §4.4 (korelasyon; nedensellik ölçülmedi). Uçtan uca fark için yön öngörüsü yok; yalnız yukarıdaki biçimle hüküm.
- Güvenlik notu: dışlanan kökte yalnız iki açık kaynak programın (Debian `sort`, `tmux`) analizi koşar; dışlama yalnız deneme süresince durur (`GECE_PLANI.md`, Berke paragrafı).

## Ölçülmeyecekler / sınırlar

- Tek makine (Apple M4 Max 10P + 4E, 36 GB); öbür donanımlar HZ-9 (c)'de.
- `p16c` grubunun çözümleyici süreleri için öngörü yok (G3 kararına girdi).
- JFR'nin kendi ek yükü ölçülmez (B_jfr medyana girmez).
