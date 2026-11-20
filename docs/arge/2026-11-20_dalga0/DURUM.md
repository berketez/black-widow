# Dalga 0 — durum (2026-11-20)

Yaşayan kayıt: hangi paket kimde, ne main'e girdi, hangi karar verildi. Oturum yarıda kalırsa buradan sürdürülür.

## Kurallar (bu oturum)

- Berke (2026-11-20 07:5x): "argeyi yapmaya başlatalım … aynı anda 5 ajan olacak şekilde başlayalım."
- Dalga 0 toplam **8 ajan** (aynı anda en çok 5): BAYRAK, OLCUM, OK5, OLCEK, HZ1 (ilk 5, 08:13'te gönderildi); MUTBAKIM, HEDEF, KIMLIK (yer açıldıkça). İlk ilan 9'du; Berke ÖL-10'u Mythos oturumuna bıraktı (A-24) → 8. Takılan olursa yerine açılacak ajan sayıya dahildir; aşılırsa Berke'ye sorulur (CLAUDE.md §26).
- Ajan kimlikleri (bekçi için): BAYRAK a9659944b32ed01ff, OLCUM af4cea2568cbc91f4, OK5 a6b44e6ccb8e6088a, OLCEK a22f2a2142be019e1, HZ1 a6926ad632ec03810. Bekçi: `python3 -u docs/arge/2026-11-20_dalga0/bekci_d0.py AD=kimlik:ilerleme_yolu …` (Monitor, 30 dk'da bir yeniden).
- Bütün ajanlar Opus 5.5, effort xhigh, kendi worktree'si. Ortak brif `ORTAK_D0.md`; paket metinleri `gonderim/`.
- Ghidra kuyruğu: makinede aynı anda tek koşu; `~/karadul_olcum/ghidra_kuyruk.sh` (kilit `ghidra_kuyruk.lock`, kayıt `ghidra_kuyruk.log`).

## Ana oturum

| Saat | İş | Sonuç |
|---|---|---|
| 07:54–08:02 | Tam takım, main `b6aceb9` | **10 289 geçti / 11 atlandı / 0 kaldı** (475 sn); kayıt `~/karadul_olcum/runs/dalga0-2026-11-20/tam_takim/` |
| 08:03–08:12 | Son doğrulama mutasyonları (main `b6aceb9`, ayrı ağaç `.claude/worktrees/dogrulama-d0`) | p18 13/13, p20b 16/16, lm_kesif 55/55, lm_oturum 52/52, p09 27/27, p16d 11/11 öldü; **p20 25/26** (hayatta `p20_k6_bayrak_ontanimli_acik`, 2026-11-19'daki ile aynı → MUTBAKIM); kayıt `~/karadul_olcum/runs/dalga0-2026-11-20/son_dogrulama/` |
| 08:05–08:21 | S8 tabanı (main `b6aceb9`, ağaç `~/karadul_olcum/urun-b6aceb9`, 1.24.1, temiz) | **8 / 8 tamam** (`BITTI` 0; ikili başına 1–5 dk, yük altında); kök `~/karadul_olcum/runs/dalga0-2026-11-20/s8_taban_b6aceb9/` |
| 08:25– | S8 A/A tekrarı (aynı ağaç, aynı komut) — belirlenimsizlik denetimi: iki koşu arasındaki kendiliğinden farklar "çıktı eşit" denetimlerinden ayrılsın | sürüyor; kök `…/s8_taban_b6aceb9_AA/` |
| — | HIZ planı dosya yolu denetimi (`scripts/arge/hiz/plan_yol_denetimi.py`) | yok / beklenmeyen 0, satır aşımı 0; HZ-1 atıfları elle de doğrulandı (`headless.py:267, :713, :1185`; `macho.py:1103`). Kabul ölçütleri denetimi gece koşusundan önce |
| — | Hüküm: `AD_ESIGI = L / (L + 1)` kesirle (A-13'teki "0,909" yuvarlanmış yazım) | BAYRAK paketine yazıldı; KARARLAR A-25 |
| 08:2x | Push (Berke onayı, A-21) | tarama temiz (gizli anahtar 0, 2 MB üstü / ikili dosya 0); `a62f15e..e996200`, 114 commit |
| 08:3x | V5 indirme (A-22) | libzstd1 + dbgsym, gpgv + sha256 → `~/karadul_olcum/n2_tabaka/kitaplik/` |
| 08:4x | V1 indirme (A-23) | tree, libzstd, sqlite3, redis kaynakları, 31,2 MB → `~/karadul_olcum/kimlik_v1/` |

## Paketler

| Paket | Ajan | Durum | Not |
|---|---|---|---|
| BAYRAK | a9659944b32ed01ff | **bitti 08:52; main'de** (`6e0181f..6551f2f`, 8 commit, cherry-pick) | 49 alan (36 var olan bölümlerde + 5 yeni bölümde 13), hepsi etkisiz ve INERT'te; `AD_ESIGI` / `MALIYET_ORANI_L`; 160 test, mutant 14/14; ajanın tam takımı 10 337 geçti, 7 kırmızı yalnız eksik çalışma verisi (bağla geçti). **Bağımsız doğrulama (ana oturum, main `6551f2f`, `dogrulama-d0`): 8 test dosyası 262 / 0; mutasyon 14 / 14 öldü** (`~/karadul_olcum/runs/dalga0-2026-11-20/dogrulama/BAYRAK/`) |
| OLCUM | af4cea2568cbc91f4 | **bitti 09:18; main'de** (`11949f4..233f199`, 10 commit) | P-Ö1 6 / 6 tuttu (a62f15e: biçim 40, tam + biçim yanlış 79 / 1 800, makro 0,1914; f30ac9a: 47, 625 / 2 261, 0,4077); 7 araç kusuru onarıldı (ks1 `BITTI`, masum `sarif` 12 → 0, sağlamlık "yazıldı" 119 → 0, BuildID not sahibi 2 → 0, urun_kos künyesi, urun_olc sınıflayıcı sürüm denetimi); ajanın tam takımı 10 322 / 0. **Bağımsız doğrulama (main `233f199`): 7 test dosyası 190 / 0 (1 atlandı); mutasyon po1 7/7, olcum_araci 26/26, urun_olc 65/65, ks1 67/67, function_f1 18/18, p00 41/41** |
| OK5 | a6b44e6ccb8e6088a | çalışıyor (08:13) | Ghidra kuyruğu uzun (86 ELF) |
| OLCEK | a22f2a2142be019e1 | **bitti 09:30; main'de** (`…b4e02be`, 11 commit) | ÖLÇ-A `olcek_kos.py` (36 test, mutant 17/17); duman (cat, 41 sn, künye eksiksiz); ÖLÇ-0 ön kaydı 10 satırın 3'ü tuttu; gece kuyruğu `gece_kosusu.py` (Gece 1 / Gece 2); ajanın tam takımı 10 325 / 0. Bağımsız doğrulama sürüyor |
| HZ1 | a6926ad632ec03810 | çalışıyor (08:13) | S8 "sonra" kolu tabanı bekler |
| MUTBAKIM | aa0b927e2895ab045 | çalışıyor (09:32) | Dalga 0'ın son (8.) ajanı |
| HEDEF | a2c93f93ab3c32a19 | çalışıyor (09:19) | bugün yalnız terminal-notifier koşulur (öbürleri tahmini > 60 dk) |
| KIMLIK | a2e74e17f3b864d9d | çalışıyor (08:53) | V5 ve V1 indi; V1 derlemesi izinli (A-23) |
| OL10 | — | **Dalga 0'dan çıktı** | Mythos oturumuna (A-24) |

## Sonraki dalgalara notlar (paket raporlarından)

- **BAYRAK → bağlayan paketler:** bağlayan paket `config.py`'ye yazmaz; INERT satırını silen ve alan satırındaki `# ETKİSİZ` yorumunu kaldıran yamayı `docs/arge/<dalga>/yamalar/<PAKET>__config.py.patch` olarak bırakır, ana oturum uygular. Bağlama tablosu: `docs/arge/2026-11-20_dalga0/BAYRAK.md` §3.1.
- **BAYRAK → ÜST VERİ (Dalga 2):** P-ÜV1 / P-ÜV2 / P-ÜV3 bayrağı `getattr` ile okursa `test_p15a` INERT satırını o pakette sildirir ama adım Faz 1'e ancak P-ÜV6'da girer (arada alan sessizce etkisiz). Ana oturum hükmü: okuyucu paketleri (P-ÜV1–4) bayrak OKUMAZ; bayrakları P-ÜV6 bağlar ve INERT satırlarını o siler. (`enable_rtti_recovery` için P-ÜV4'te aynı kural.)
- **BAYRAK → ÖL-2 / ÖL-5a:** `timeouts.ghidra_adim`, `paket.toplam_butce_sn`, `paket.bilesen_butce_sn` için 0 = sınırsız (bugünkü davranış); bağlayan paket bu anlamı uygular.
- **BAYRAK → ÖL-9:** alan adı `onbellek.ghidra_kosusu` (plandaki `onbellek.ghidra` `test_p15a`'nın ad aramasında `timeouts.ghidra` ile çakışıyordu).
- **OLCUM → KS-1:** `ks1_olc.py` ve `function_f1.py` KS-1 ön kaydının sha256'larıyla sabitti; KS-1 yeniden koşulacaksa yeni bir sapma kaydı gerekir (`ks1_olc.py olc` artık durur).
- **OLCUM → eski kökler:** sınıflayıcısı farklı eski kökler (`urun-yeni2-f30ac9a`, `urun-yeni-93a2956`) artık `urun_olc --siniflayici-agac <ürün ağacı>` ister.
- **OLCUM → P23 / ölçüm paketi:** `masum_kapi.kosu_ikilileri` `BITTI`'nin yalnız varlığına bakıyor (kısmi `3` bitmiş görünür); aynı kusur, bu pakette kapsam dışıydı.
- **Masum kapı eşikleri (ana oturum, 09:2x, `c530b8c`):** çıktı kipi / geliştirme 119 ikili (a62f15e); `sarif` yeni kodla 0. Önce 14 ikili → şimdi 119: bileşim 82 → 0, sarif 37 → 0, YARA 31 → 0, types.h 14 → 0, intel 353 → 455, algoritma_json 45 → 56.
- **OLCEK → ölçek modeli:** 119 küçük ikiliden kurulan örneklem modeli gösteriyi tutturmadı (ÖLÇ-0: 10 satırın 7'si tutmadı; reconstruct 2 353 sn ↔ öngörü üst sınırı 710–732; toplam 7 729 ↔ 1 632–1 827). Büyük ikili için 119'dan dışa uzatma güvenilmez (KARŞI İ-1 / İ-2 ile tutarlı); ÖL-10 tasarımı ve ÖLÇ-1 bunu hesaba katmalı.
- **OLCEK → HIZ (JDK):** Ghidra'nın JVM'i Temurin 27, `JAVA_HOME`'daki 21 değil → `hiz/BULGULAR.md`'deki JDK künyesi yanlış; HZ-5 (yığın / CDS bayrakları) ve AppCDS / JFR adımları JDK 27'ye göre yeniden denetlenmeli. pyghidra iki yan JVM açıyor ve onlar da `JAVA_TOOL_OPTIONS`'ı okuyor (GC günlüğü süreç numarasıyla ayrıldı). JFR'ın çıkış dökümü 0 bayt; kayıt deposu saklanınca okunuyor, Ghidra'lı koşuda denenmedi → Gece 2'den önce boş makinede `--yalniz duman` (~1 dk).
- **Gece kuyruğu (OLCEK `GECE_PLANI.md`):** tek seferde TAHMİN [10,4; 16,9] sa → iki gece. Gece 1 (HZ-0 + p16c + K AppCDS + Avast kolu) [3,5; 8,5] sa (ek tekrar gerekirse en kötü +4,9 sa); Gece 2 (B_jfr + ÖLÇ-1) [6,9; 8,4] sa. B hedefi gösterinin `gosteri.yaml`'ıyla (ObjC çözümleyicisi kapalı); T100 / T300 / PAKET öntanım ayarla. Komut (ana ağaç kökünden, makine boşken): `PYTHONHASHSEED=0 PYTHONDONTWRITEBYTECODE=1 python scripts/arge/olcek/gece_kosusu.py --commit <hash> --gece 1 [--avast-dislama-yapildi]`; Avast klasörü `--avast-hazirla` ile `~/karadul_olcum/runs/hiz-avast-dislama/<kısa-commit>/`.
- **Scratchpad ortak:** iki ajanın `tam_takim.log`'u karıştı (08:5x); ORTAK_D0 §2'ye kural eklendi, çalışan ajanlara bildirildi.

## Berke'nin kararları (2026-11-20 08:1x)

- Push: evet (A-21, yapıldı). V5 indirme: evet (A-22, yapıldı). A-12: Go derleyicisi + kaynaktan derleme, ikisine de izin (A-23; V1 indi, Go derleyicisi P-ÜV9 kalem 3–4 sırası gelince). ÖL-10: Mythos oturumuna (A-24).

## HIZ planı denetimi (ana oturum, 08:3x; KARŞI yapamamıştı)

- Dosya yolları: `plan_yol_denetimi.py` → yok / beklenmeyen 0, satır aşımı 0; HZ-1 atıfları elle doğrulandı.
- HZ-0 ön kaydı kaynaklarıyla tutuyor: H0-a BSim %51,2 (`hiz/BULGULAR.md` s. 49), H0-b küçük ikilide `feedback_loop` en büyük kalem %30,5 (s. 78), H0-c CFG 44,3 ms / fn (s. 91), H0-e düşük yükte `.c` açma 0,59–0,87 ms (s. 214).
- HZ-1 … HZ-9 kabul ölçütlerinin hepsi oran + çıktı eşitliği (A-9'a uygun). Notlar:
  1. **Oran ölçümleri boş makine ister; her HZ paketine ayrı gece yok.** Uygulama: paket gündüz çıktı eşitliğiyle (S8, yük altında geçerli) main'e alınır; oran ölçümü gece kuyruğunda toplu yapılır (paket başına önce / sonra ağacı aynı gece, aynı hedef), HZ-9 ayrıca. Oran tutmazsa paket geri alınmaz, kayda "tutmadı" yazılır ve öncelik yeniden sıralanır (ana oturum hükmü).
  2. HZ-3'ün "dengesizlik ≥ 1,5 olan S8 ikilileri (… benzeri)" kümesi belirsiz → HZ-0 verisinden ölçümden önce listelenip ön kayda yazılacak.
  3. HZ-9 (c) ikinci makine ister (farklı çekirdek düzeni; aday: 4090 dizüstü, Windows) — Berke'nin makinesine bağlı, Dalga 4'te sorulacak.
- **Gece koşusunun önkoşulu:** "boş makine" = 1 dk yük < 0,25 × 14 = 3,5. Başka oturumların ağır işleri (ör. karadelik benzetimi, HRMA koşuları) o gece bu Mac'te çalışmamalı → Berke'ye söylenecek.

## Bekleyenler

- Gece koşusu (ÖLÇ-1 + HZ-0, boş makine) ve Avast dışlaması: OLCEK paketinin `GECE_PLANI.md`'si gelince Berke'ye sorulacak.
