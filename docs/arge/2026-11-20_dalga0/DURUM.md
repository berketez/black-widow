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
| 08:25–09:55 | S8 A/A tekrarı (aynı ağaç, aynı komut) — belirlenimsizlik denetimi: iki koşu arasındaki kendiliğinden farklar "çıktı eşit" denetimlerinden ayrılsın | **8 / 8 tamam** (kuyrukta OK5'in postgresql-17 koşusu yüzünden uzadı); kök `…/s8_taban_b6aceb9_AA/`; taban ↔ A/A fark tablosu HZ1 raporunda |
| — | HIZ planı dosya yolu denetimi (`scripts/arge/hiz/plan_yol_denetimi.py`) | yok / beklenmeyen 0, satır aşımı 0; HZ-1 atıfları elle de doğrulandı (`headless.py:267, :713, :1185`; `macho.py:1103`). Kabul ölçütleri denetimi gece koşusundan önce |
| — | Hüküm: `AD_ESIGI = L / (L + 1)` kesirle (A-13'teki "0,909" yuvarlanmış yazım) | BAYRAK paketine yazıldı; KARARLAR A-25 |
| 08:2x | Push (Berke onayı, A-21) | tarama temiz (gizli anahtar 0, 2 MB üstü / ikili dosya 0); `a62f15e..e996200`, 114 commit |
| 08:3x | V5 indirme (A-22) | libzstd1 + dbgsym, gpgv + sha256 → `~/karadul_olcum/n2_tabaka/kitaplik/` |
| 08:4x | V1 indirme (A-23) | tree, libzstd, sqlite3, redis kaynakları, 31,2 MB → `~/karadul_olcum/kimlik_v1/` |

## Üst veri hızlı hattı (Berke 10:5x: "her şeyi okuyacak" — A-27; "4'e kadar vaktin var")

- Gece koşusu iptal olduğu için öğleden sonra boş; hedef setinde bugünkü ürün 0 / 40 (terminal-notifier) ve 17 / 13 160 (Ollama) → üst veri okuyucuları öne alındı. Sert son 15:15 (ajanlar), 16:00 oturum kapanışı.
- Bugünkü toplam ajan sayısı **13** (Dalga 0: 8; hızlı hat: PUV0, PUV1, PUV2 şimdi + OKUMA-ENVANTERİ, P-ÜV5 OK5 / KIMLIK bitince). Aynı anda en çok 5.
- PUV1 / PUV2, PUV0'ın plandaki `Goruntu` arayüzüne göre paralel yazılır (sentetik testler); PUV0 main'e girince ana oturum haber verir, ikisi bir kez `git rebase main` yapıp gerçek ikili kabulünü koşar.
- Gönderilenler (10:45): PUV0 ad5317ce5403117ed (`ustveri/P-UV0.md`), PUV1 ae969d253c02cdadb (`ustveri/P-UV1.md`), PUV2 a6a28cc2493650023 (`ustveri/P-UV2.md`). ~~Sırada: OKUMA, PUV5 — OK5 / KIMLIK bitince.~~ **Berke (11:0x): "bu ajanlar bitince bi duralım"** → yeni ajan gönderilmez; çalışan beşi (OK5, KIMLIK, PUV0, PUV1, PUV2) bitince durulur. OKUMA (`gonderim/OKUMA.md`) ve PUV5 (`gonderim/PUV5.md`) hazır, sonraki oturuma. Bugünkü toplam ajan sayısı 11 (Dalga 0: 8, hızlı hat: 3).
- **Ghidra kuyruğu düzeni (10:48):** KIMLIK'in uzun x86-64 işleri (redis-cli 499 sn) OK5'in kısa kör işlerini (~20 sn) aç bırakıyordu (OK5 3–4 sa sürecekti). Sarmalayıcıya paket bekletme eklendi (`~/karadul_olcum/ghidra_kuyruk.bekle.<PAKET>` varsa o paketin yeni çağrıları bekler; başlamış koşuya dokunulmaz); KIMLIK, OK5'in 85 işi bitene kadar (en geç 75 dk) bekletiliyor; kaldırma kendiliğinden (arka plan izleyicisi). Toplam iş aynı; sıra değişti. KIMLIK'e bildirildi.

## Paketler

| Paket | Ajan | Durum | Not |
|---|---|---|---|
| BAYRAK | a9659944b32ed01ff | **bitti 08:52; main'de** (`6e0181f..6551f2f`, 8 commit, cherry-pick) | 49 alan (36 var olan bölümlerde + 5 yeni bölümde 13), hepsi etkisiz ve INERT'te; `AD_ESIGI` / `MALIYET_ORANI_L`; 160 test, mutant 14/14; ajanın tam takımı 10 337 geçti, 7 kırmızı yalnız eksik çalışma verisi (bağla geçti). **Bağımsız doğrulama (ana oturum, main `6551f2f`, `dogrulama-d0`): 8 test dosyası 262 / 0; mutasyon 14 / 14 öldü** (`~/karadul_olcum/runs/dalga0-2026-11-20/dogrulama/BAYRAK/`) |
| OLCUM | af4cea2568cbc91f4 | **bitti 09:18; main'de** (`11949f4..233f199`, 10 commit) | P-Ö1 6 / 6 tuttu (a62f15e: biçim 40, tam + biçim yanlış 79 / 1 800, makro 0,1914; f30ac9a: 47, 625 / 2 261, 0,4077); 7 araç kusuru onarıldı (ks1 `BITTI`, masum `sarif` 12 → 0, sağlamlık "yazıldı" 119 → 0, BuildID not sahibi 2 → 0, urun_kos künyesi, urun_olc sınıflayıcı sürüm denetimi); ajanın tam takımı 10 322 / 0. **Bağımsız doğrulama (main `233f199`): 7 test dosyası 190 / 0 (1 atlandı); mutasyon po1 7/7, olcum_araci 26/26, urun_olc 65/65, ks1 67/67, function_f1 18/18, p00 41/41** |
| OK5 | a6b44e6ccb8e6088a | çalışıyor (08:13) | Ghidra kuyruğu uzun (86 ELF) |
| OLCEK | a22f2a2142be019e1 | **bitti 09:30; main'de** (`…b4e02be`, 11 commit) | ÖLÇ-A `olcek_kos.py` (36 test, mutant 17/17); duman (cat, 41 sn, künye eksiksiz); ÖLÇ-0 ön kaydı 10 satırın 3'ü tuttu; gece kuyruğu `gece_kosusu.py` (Gece 1 / Gece 2); ajanın tam takımı 10 325 / 0. **Bağımsız doğrulama (main `b4e02be`): 36 / 0; mutasyon 17 / 17; Gece 1 `--kuru` 20 koşu, TAHMİN [3,5; 8,5] sa** |
| HZ1 | a6926ad632ec03810 | **bitti 10:17; main'de** (`…be9550e`, 11 commit) | `GHIDRA_ADIMLARI` (18 adım), `adim_sureleri`, `decompile_parcalari`, `ghidra_status.json`'a `analysis` / `adim_sureleri`; `s8_esitlik.py` (`--aa`). 23 test; mutant hz1 13/13, macho 34/34, p16a 33/33, p16c 16/16, p16d 11/11. **S8: H1 (8 / 8 çıktı eşit) TUTMADI — 7 / 8**: htop'ta 6 / 23 JSON ve 3 / 1 148 `.c` farklı, hepsi çağıran listesinin SIRASI (`// Callers:`); sıralanınca 0, kümeler aynı; A/A'da da debian tmux'ta aynı türden fark (4 JSON, 2 `.c`); htop 6 koşuda 4 farklı sıra; kaynak sıralanmayan `getReferencesTo` yinelemesi, HZ-1 o yola dokunmuyor. H2–H4 8 / 8 (`analyzer_times` 8 / 8, `adim_sureleri` 17 adım, toplamı köprü süresinden ≤ 0,002 sn). `naming_map` 24 / 24, `pcode.jsonl` 8 / 8 bayt eşit. Ajanın tam takımı 10 312 / 0. **Bağımsız doğrulama (main `be9550e`, `dogrulama-d0b`): 79 / 0; mutasyon hz1 13/13, macho 34/34, p16a 33/33, p16c 16/16, p16d 11/11, p13a 22/22 (MUTBAKIM'ın uyarısı: HZ1'den sonra temiz)** |
| MUTBAKIM | aa0b927e2895ab045 | **bitti 10:09; main'de** (`…ef62543`, 12 commit) | 9 / 9 tanım temiz, 272 / 272 öldü (önce: 3 hayatta, 15 hata). Hayatta kalanlar: p20 bayat (mutant ikiye bölündü), p13a ve adim3_c_namer gerçek test açığı → `tests/test_mutbakim_p13a.py`, `tests/test_mutbakim_adim3_c_namer.py` (c_namer: analistin elle verdiği ad kaybolabiliyordu, artık kilitli). Çoklu eşleşme 1 ve aynı uzunluk 5 mutant düzeltildi. Ajanın tam takımı 10 520 / 0. **Bağımsız doğrulama (main `ef62543`): 2 yeni test 2 / 0; 9 tanım 272 / 272 öldü** |
| HEDEF | a2c93f93ab3c32a19 | **bitti 10:01; main'de** (`…c99c88e`, 12 commit) | Hedef seti: keşif terminal-notifier, docker-cli; sınama docker-compose, iTerm2, llama-server (GT 92 / 35 050 / 90 257 / 108 776 / 17 210 adres; veri depo dışında). Keşifte araç araştırma çıktısını birebir üretti (docker-cli Go 35 048 / 35 048, alt 0,99989; terminal-notifier ObjC 32 / 32, n küçük → A-2 hayır). H1 25 / 25; bütçe 16 / 16. **Bugünkü ürün: terminal-notifier 0 ad (ad bekleyen 40)**; öbür dördü süre yüzünden ölçülmedi (TAHMİN llama-server 164–215 dk, docker-cli 334–983, docker-compose 859–7 378, iTerm2 1 046–11 219). P-ÜV9 kalem 1: `LC_FUNCTION_STARTS` 12 916 / 12 952 Ghidra'da fonksiyon; Go girişleri 10 457 / 10 600 jenerik adlı, Ghidra'nın verdiği Go adı 3; ObjC 148 / 151 yalnız seçiciyle adlı. 23 test, mutant 14/14; ajanın tam takımı 10 505 / 0. **Bağımsız doğrulama (main `c99c88e`): 23 / 0; mutasyon 14 / 14** |
| KIMLIK | a2e74e17f3b864d9d | çalışıyor (08:53) | V5 ve V1 indi; V1 derlemesi izinli (A-23) |
| OL10 | — | **Dalga 0'dan çıktı** | Mythos oturumuna (A-24) |

## Sonraki dalgalara notlar (paket raporlarından)

- **BAYRAK → bağlayan paketler:** bağlayan paket `config.py`'ye yazmaz; INERT satırını silen ve alan satırındaki `# ETKİSİZ` yorumunu kaldıran yamayı `docs/arge/<dalga>/yamalar/<PAKET>__config.py.patch` olarak bırakır, ana oturum uygular. Bağlama tablosu: `docs/arge/2026-11-20_dalga0/BAYRAK.md` §3.1.
- **BAYRAK → ÜST VERİ (Dalga 2):** P-ÜV1 / P-ÜV2 / P-ÜV3 bayrağı `getattr` ile okursa `test_p15a` INERT satırını o pakette sildirir ama adım Faz 1'e ancak P-ÜV6'da girer (arada alan sessizce etkisiz). ~~Ana oturum hükmü: okuyucu paketleri bayrak okumaz~~ → **düzeltildi (10:5x, hızlı hat):** okuyucu paketlerinin üretici adımı bayrağı planın dediği gibi okur (`getattr(…, False) is True`) ve INERT satırını silen yamayı `yamalar/PUVn__config.py.patch` olarak bırakır; ana oturum birleştirirken uygular. Adım Faz 1'e ancak P-ÜV6'da girdiği için arada alan fiilen etkisiz kalır (yalnız uyarı çıkmaz); kabul edildi.
- **BAYRAK → ÖL-2 / ÖL-5a:** `timeouts.ghidra_adim`, `paket.toplam_butce_sn`, `paket.bilesen_butce_sn` için 0 = sınırsız (bugünkü davranış); bağlayan paket bu anlamı uygular.
- **BAYRAK → ÖL-9:** alan adı `onbellek.ghidra_kosusu` (plandaki `onbellek.ghidra` `test_p15a`'nın ad aramasında `timeouts.ghidra` ile çakışıyordu).
- **OLCUM → KS-1:** `ks1_olc.py` ve `function_f1.py` KS-1 ön kaydının sha256'larıyla sabitti; KS-1 yeniden koşulacaksa yeni bir sapma kaydı gerekir (`ks1_olc.py olc` artık durur).
- **OLCUM → eski kökler:** sınıflayıcısı farklı eski kökler (`urun-yeni2-f30ac9a`, `urun-yeni-93a2956`) artık `urun_olc --siniflayici-agac <ürün ağacı>` ister.
- **OLCUM → P23 / ölçüm paketi:** `masum_kapi.kosu_ikilileri` `BITTI`'nin yalnız varlığına bakıyor (kısmi `3` bitmiş görünür); aynı kusur, bu pakette kapsam dışıydı.
- **Masum kapı eşikleri (ana oturum, 09:2x, `c530b8c`):** çıktı kipi / geliştirme 119 ikili (a62f15e); `sarif` yeni kodla 0. Önce 14 ikili → şimdi 119: bileşim 82 → 0, sarif 37 → 0, YARA 31 → 0, types.h 14 → 0, intel 353 → 455, algoritma_json 45 → 56.
- **OLCEK → ölçek modeli:** 119 küçük ikiliden kurulan örneklem modeli gösteriyi tutturmadı (ÖLÇ-0: 10 satırın 7'si tutmadı; reconstruct 2 353 sn ↔ öngörü üst sınırı 710–732; toplam 7 729 ↔ 1 632–1 827). Büyük ikili için 119'dan dışa uzatma güvenilmez (KARŞI İ-1 / İ-2 ile tutarlı); ÖL-10 tasarımı ve ÖLÇ-1 bunu hesaba katmalı.
- **OLCEK → HIZ (JDK):** Ghidra'nın JVM'i Temurin 27, `JAVA_HOME`'daki 21 değil → `hiz/BULGULAR.md`'deki JDK künyesi yanlış; HZ-5 (yığın / CDS bayrakları) ve AppCDS / JFR adımları JDK 27'ye göre yeniden denetlenmeli. pyghidra iki yan JVM açıyor ve onlar da `JAVA_TOOL_OPTIONS`'ı okuyor (GC günlüğü süreç numarasıyla ayrıldı). JFR'ın çıkış dökümü 0 bayt; kayıt deposu saklanınca okunuyor, Ghidra'lı koşuda denenmedi → Gece 2'den önce boş makinede `--yalniz duman` (~1 dk).
- **Gece kuyruğu (OLCEK `GECE_PLANI.md`):** tek seferde TAHMİN [10,4; 16,9] sa → iki gece. Gece 1 (HZ-0 + p16c + K AppCDS + Avast kolu) [3,5; 8,5] sa (ek tekrar gerekirse en kötü +4,9 sa); Gece 2 (B_jfr + ÖLÇ-1) [6,9; 8,4] sa. B hedefi gösterinin `gosteri.yaml`'ıyla (ObjC çözümleyicisi kapalı); T100 / T300 / PAKET öntanım ayarla. Komut (ana ağaç kökünden, makine boşken): `PYTHONHASHSEED=0 PYTHONDONTWRITEBYTECODE=1 python scripts/arge/olcek/gece_kosusu.py --commit <hash> --gece 1 [--avast-dislama-yapildi]`; Avast klasörü `--avast-hazirla` ile `~/karadul_olcum/runs/hiz-avast-dislama/<kısa-commit>/`.
- **HEDEF → ölçüm (hüküm, ana oturum 10:0x):** `/usr/bin/strip` iTerm2'de 6, llama-server'da 214 sembol bırakıyor (dışa aktarımlar; bağlama için gerekli). İkili değiştirilmez; bu adresler ölçüm nüfusundan çıkarılır ve sayısı ayrıca yazılır (ürün düzeyi koşu o zaman yapılabilir; adlar Ghidra'ya sızmış sayılır, hükme girmez).
- **HEDEF → P-ÜV6 (Dalga 3):** Ghidra ObjC yöntemlerini yalnız seçiciyle adlandırıyor (Ollama 148 / 151); P13b'nin "aday yalnız Ghidra'nın adsız bıraktığı fonksiyona" kuralı değişmezse ObjC kanalı terminal-notifier'da 1, Ollama'da 2 ad yazabilir ve P-ÜV6 H4 tutmaz. P-ÜV6 karar verecek: Ghidra adı üst verideki seçiciyle aynıysa tam adın (`-[Sınıf seçici]`) onun yerine yazılması (tutarlılık denetimiyle, `üst veriden` etiketiyle).
- **HEDEF → bitiş çizgisi:** hedef setinin ürün düzeyi "önce" sayısı bugünkü ürünle yalnız terminal-notifier (0 / 40) ve gösteri (13 160 fonksiyonda 17 ad) için var; öbürleri bugünkü hızla ölçülemiyor. Ölçek / hız paketlerinden sonra (ÖLÇ-2, ÖL-10) yeniden.
- **MUTBAKIM → HZ1 sonrası:** p13a tanımının iki mutantı `karadul/ghidra/headless.py`'de; HZ1 main'e alınınca p13a yeniden koşulacak (ana oturumun HZ1 doğrulamasına eklendi).
- **Mutasyon tanımı denetimi (ana oturum, 10:1x; `~/karadul_olcum/runs/dalga0-2026-11-20/mut_denetim/`, MUTBAKIM'ın `denetle.py`'si, main `ef62543`, 84 tanım):** bayat `find` 11 mutant / 8 tanım (adim3_alt_kanal, adim3_baglama, p01, p15a, pguv ×4, project_builder, surum_oncesi, ui_cagri_kenari); açık `occurrence` olmadan çoklu eşleşme 9 (harita_olc ×3, p05b, p10 ×2, p16b ×2, project_builder); aynı uzunlukta değişim 30. `mutation_probe.py` çoklu eşleşmeyi hata saymıyor. → **Dalga 1'e küçük paket (MUTBAKIM-2):** tanımların onarımı + `mutation_probe.py` sıkılaştırması (açık `occurrence` olmadan çoklu eşleşme hata; aynı uzunlukta değişimde uyarı ya da dosya zamanını ileri alma).
- **HZ1 → yeni bulgu ve hüküm (ana oturum, 10:2x): çağıran sırası belirlenimsiz.** `getReferencesTo` sırasız dolaşılıyor → çağıran listelerinin sırası ve `.c` dosyalarındaki `// Callers:` satırı koşudan koşuya değişiyor; 5'ten fazla çağıranı olan fonksiyonda analist farklı alt küme görüyor (analisti yanıltabilecek kusur). Hüküm: HZ1 main'e alındı (değişiklik çıktıyı değiştirmiyor; H1 "tutmadı" olarak kayıtta kalır). **Dalga 1'e belirlenimcilik paketi (P16e):** çağıranlar adrese göre sıralanır (çıktıyı değiştirir: ön kayıtlı, S8 + 119 ad ölçümü değişmemeli); `headless.py` sırasında ÖL-1'den önce. P16e girene kadar bütün S8 / çıktı eşitliği denetimlerinde çağıran listeleri sıra-normal karşılaştırılır, ham fark ayrıca yazılır.
- **HZ1 → ÖL-1:** `from karadul.ghidra.headless import GHIDRA_ADIMLARI` (gerekirse `ADIM_*`, `DURUM_SURE_ALANLARI`); ilerleme olayları `_AdimSaati.basla / bitti` noktalarına bağlanır (ikinci zamanlayıcı yok). Sözleşmedeki `ghidra.bsim` burada `ghidra.bsim.ingest` + `ghidra.bsim.query`.
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

- **Gece koşusu ertelendi (Berke 10:4x, A-26):** bu gece yok. Sabit ürün `be9550e`, ağaç `~/karadul_olcum/urun-be9550e`, Avast kökü `~/karadul_olcum/runs/hiz-avast-dislama/be9550e` (boş) silinmez. Berke izin verdiği gece: `PYTHONHASHSEED=0 PYTHONDONTWRITEBYTECODE=1 python scripts/arge/olcek/gece_kosusu.py --commit be9550e --gece 1 [--avast-dislama-yapildi]`, ertesi gece `--gece 2` (Gece 2'den önce `--yalniz duman`).
