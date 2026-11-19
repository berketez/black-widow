# Karadul ARGE soru listesi (Mythos için) — 2026-11-18 / 2026-11-19

- **Yazan:** ana oturum (Opus 5.5), Berke'nin isteğiyle. Onarım dalgaları sürerken yazıldı; onarımın ilk günü bitince (2026-11-18 akşamı, sürüm 1.24.1) §1.1 ve §3.H eklendi; 2026-11-19'da onarımın 40 paketine göre son hâline getirildi (ARGE ajanı; ilerleme `docs/arge/2026-11-18_onarim/ARGE_liste.md`).
- **Durum: SON SÜRÜM ADAYI (2026-11-19):** birleşik ölçüm sayıları ⟨ÖLÇÜM: …⟩ yer tutucularına girecek; o sayılar girmeden Mythos'a verilmez.
- **Berke'nin önceki sözü (2026-11-18, ARA SÜRÜM için):** ARGE soruları bütün düzeltmeler bittikten sonra son hâline getirilir; onarım bitince bu liste birleşik ürün ölçümünün sayılarıyla yeniden güncellenir, Mythos ancak ondan sonra devreye girer. **2026-11-19:** Berke "mythosa gelelim hemen" dedi (`gonderim/OTURUM_2026-11-19.md`). Liste, onarımın son paketleri sürerken birleşik ölçüm tabanına (a62f15e) göre kapatıldı; süren paketlerin etkisi o tabanda yok (§6).
- **Kime:** Mythos, ARGE oturumunda.
- **Ne bekleniyor:** Mythos bu sorulardan hat seçer ve her hat için ölçülebilir bir plan yazar (§5'teki biçimde). Planları Opus ekibi uygular; ana oturum doğrular.
- **Ne beklenmiyor:** kod yazmak. Ayrıca "şunu dene" türünden ölçütsüz fikir listesi de istenmiyor.

**Mythos için okuma sırası**
1. §1 (zemin: 1.22.1 → a62f15e ad tablosu, ölçüm altyapısı, olumsuz sonuçlar) ve §1.1 (onarımın özeti).
2. `docs/arge/2026-11-19_birlesik_olcum/sonuc.md` ve aynı dizindeki ön kayıt (birleşik 119 ölçümü).
3. §2 bağlayıcı kurallar.
4. §3 sorular (A–H; her sorunun "Onarım sonrası" satırı) ve §3.I (onarımdan doğan araştırma soruları).
5. §4 öncelik önerisi (itiraz edilebilir), §5 plan biçimi, §6 sınırlar.
6. Ayrıntı gerektiğinde: `DURUM.md`'nin ilgili paket satırı, sonra paket dosyası (`docs/arge/2026-11-18_onarim/P*.md`).

## 0. Önce bunları oku

| Ne | Nerede |
|---|---|
| Birleşik ürün ölçümü (a62f15e, 119 ikili): sonuç ve ön kayıt | `docs/arge/2026-11-19_birlesik_olcum/` (`sonuc.md`; ön kayıt aynı dizinde). Koşu kökü `~/karadul_olcum/runs/urun-onarim-a62f15e`, ağaç `~/karadul_olcum/urun-a62f15e` |
| Onarımın son durumu: 40 paketin önce / sonra sayıları, K-1…K-10, tam takım ara noktaları | `docs/arge/2026-11-18_onarim/DURUM.md` (a62f15e'deki hâli; son ara nokta 2026-11-18 20:4x) ve paket dosyaları (`P00.md` …, ön kayıtlar `P*_on_kayit.md`) |
| Onarımın kalanı: DURUŞ, sıra, Berke'nin kararını bekleyenler, atanmamış bulgular | `docs/arge/2026-11-18_onarim/gonderim/OKU.md`; süren / sıradaki paket metinleri aynı dizinde (`P12c.md`, `P16d.md`, `PS4.md`, `P22c.md`, `P02b.md`, `P18.md`, `P10b.md`, `P05c.md`, `P08b.md`, `P03b.md`, `P20b.md`, `P23.md`) |
| 2026-11-19 oturum notları ve Berke kararları (K-10 silme, eski deobf zinciri, K-2 `kebap_ad`) | `docs/arge/2026-11-18_onarim/gonderim/OTURUM_2026-11-19.md` |
| Genel tarama (137 bulgu, temalar, vizyon) | `docs/arge/2026-11-18_genel_tarama/RAPOR.md` (§3 temalar, §6.1 ölü kod, §7 KaradulLM) |
| Ürün ad ölçümünün önceki tabanı (1.22.1; karşılaştırma için) | `docs/arge/2026-11-10_n1_adim3/urun_olcumu_fark_yeni_yeni2.md` (+ `urun_olcumu_taban.md`, ön kayıt ekleri) |
| KaradulLM v2 tasarımı (iki motor, olay akışı, kipler) | `docs/arge/2026-11-18_karadullm_v2/TASARIM.md` |
| Literatür taraması | `docs/arge/2026-10-21_literatur/yontem_taramasi.md`, `docs/arge/2026-10-15_makale/tersine_derleme_sinirlari.md`, `derleyici_sentez.md`, `veri_setleri.md` |
| Kilitli test seti (DOKUNULMAZ) | `docs/arge/test_seti_kilidi.md` (15 program; açılış planı dışında Karadul'la analiz edilmez, çıktısına bakılmaz) |
| Doğrulama seti | `docs/arge/dogrulama_seti_kilidi.md`, `dogrulama_seti_onkayit.md` |
| Olumsuz sonuçlar (yinelenmesin) | `docs/arge/2026-11-10_n4/` (fiil tavanı, tablo yuvası), `docs/arge/2026-11-12_yerlesim/`, `docs/arge/2026-11-11_n4_v2/`, `docs/arge/2026-11-11_yeniden_hesapla/`; onarımın tutmayan ön kayıtları §1'deki tabloda |
| KaradulLM ilk tasarımı ve Onuncu Adam itirazları | `docs/arge/2026-11-11_karadullm/` |

## 1. Zemin: Karadul bugün

**Ne yapıyor:** derlenmiş ikiliyi alıyor (ELF, Mach-O, PE; ayrıca JS/Electron, Java/APK, .NET, Python paketleri). Ghidra 12.1.2'nin (PyGhidra, başsız) çıktısı üstünde **hesaplamayla** çalışıyor; motor LLM kullanmıyor. Fonksiyon ve değişkenlere ad veriyor, tip ve yapı kurtarıyor, ilişkileri çıkarıyor, analist için kaynak ağacı ve rapor üretiyor. KaradulLM ayrı ve isteğe bağlı bir katman: araç kullanan, yerel modelle (Qwen 27B, Q4) çalışan yardımcı ajan. Onarımda olay omurgası, denetim, araç kaydı v2, oturum / kipler ve komut satırı (`python -m karadul.lm`) kuruldu (P21, P22a/b/d/e); arayüzü P22c'de yapılıyor. Gerçek modelle hiç koşulmadı.

**Ad ölçümü: 1.22.1 → onarım sonrası (geliştirme seti, 119 ikili):**

| Ölçü | 1.22.1 (yeni2, 2026-11-12) | a62f15e (onarım sonrası, 2026-11-19) |
|---|---|---|
| Ürünün verdiği fonksiyon adı (havuz) | 2 261 | ⟨ÖLÇÜM: havuz⟩ |
| Doğru (tam eşitlik) | 1 589 (%70,3; %95 GA %68,4–%72,1) | ⟨ÖLÇÜM: doğru (%; %95 GA)⟩ |
| Yanlış | 672 (**%29,7**; %27,9–%31,6); program düzeyi makro yanlış oranı **%52,8** | ⟨ÖLÇÜM: yanlış (%; %95 GA); makro yanlış⟩ |
| Ad bekleyen nüfus (Ghidra'nın jenerik bıraktığı fonksiyonlar; GT'den) | 21 371 | ⟨ÖLÇÜM: nüfus⟩ |
| Ad verilen kapsam | 1 764 / 21 371 (%8,3) | ⟨ÖLÇÜM: ad verilen kapsam⟩ |
| **Doğru ad kapsamı** | **1 120 / 21 371 (%5,2)** | ⟨ÖLÇÜM: doğru ad kapsamı⟩ |
| "kesin" etiketli adlar | 249 / 262 doğru (%95,0; makro %97,3); kapsamı 252 / 21 371 (%1,2) | ⟨ÖLÇÜM: kesin etiketli doğru / toplam; kapsam⟩ |
| Hedef "yanlış ≤ %10" | tutmadı | ⟨ÖLÇÜM: tuttu / tutmadı⟩ |

Kaynak: 1.22.1 sütunu `urun_olcumu_fark_yeni_yeni2.md`; a62f15e sütunu `docs/arge/2026-11-19_birlesik_olcum/sonuc.md`. Ölçü tanımları: `scripts/measurement/urun_olc.py` (tam eşitlik; Mach-O'da baştaki `_` soyulur; derleyici klonu tabana eşlenir; nüfus GT'den, `ks1_olc.GtBirimi.nufus`). Kanal kırılımı (1.22.1 → a62f15e): ⟨ÖLÇÜM: kanal kırılımı farkı (`urun_olc.py karsilastir`)⟩.

Paketlerin kendi alt küme ölçümleri birleşik sayının yerine geçmez; beklenen yönü gösterir (kaynak DURUM.md): `kebap_ad` −239 yanlış, kaybedilen doğru 0 / 441 (P12b, 14 ikili); gnulib coreutils dışı 7 → 0 ve coreutils yanlış 217 → 1 (P-S3, yeniden oynatma), yamalı yeniden oynatmada coreutils 620 / 0 → 732 / 0 (P-S3b); rol adının fonksiyon adı yapılması 70 → 0 (P12a); birleştiricinin `exact_multi` 42 → 0 (P13a); imza VT'nin uygulanan ad farkı 0 (P15b, 6 ikili).

**Ölçüm altyapısı (onarım sonrası):**
- Geliştirme seti: 119 ikili, `scripts/measurement/urun_kos.py` → `isleri_topla`. 117'si Debian 13 AArch64 ELF (GCC 14), 2'si Mac (htop, tmux). Bu bir yanlılıktır; G1'e bakın.
- Ürün koşusu ve ad ölçümü: `urun_kos.py` + `urun_olc.py olc / karsilastir` (birim, tabaka, kanal kırılımı, Wilson aralığı). Süre: 1.22.1'de 119 ikili ≈ 3–4 saat (`--paralel 3`); a62f15e'de ⟨ÖLÇÜM: urun_kos süresi (119 ikili, `--paralel 3`)⟩. Hijyen: `PYTHONHASHSEED=0`, koşu kökü başına ayrı `KARADUL_CACHE_DIR` (BSim deposu dahil, P16b); ağaçta `signatures.lmdb` bağı şart (7b25084, P15b); kısmi çıkış (3) bitmiş koşu sayılır (6c0b79b, P15a).
- Masum ikili kapısı (P00; `scripts/measurement/masum_kapi.py`, el kitabı `docs/arge/2026-11-18_onarim/P00.md`): doğrudan kip 5 katman (`bi`, `antidebug`, `packer`, `yara`, `capa`) × 4 set (gelistirme 119, macos 48, pe 21, pozitif 6; 194 ikili, ~25 sn); çıktı kipi 11 katman. Eşik dosyası `masum_kapi_esik.json`'ı yalnız ana oturum yazar; P01b'den sonra bütün katmanlarda geçiyor (DURUM, 11:3x ara noktası). Çıktı kipinin eşiği 14 HEAD ikilisinden kuruldu, 119 ile tamamlanacak: ⟨ÖLÇÜM: masum kapı çıktı kipi, 119 ikili; koşulmadıysa "koşulmadı"⟩.
- Çıktı sağlamlık denetimi: `scripts/measurement/saglamlik_denetle.py` (P16a yamasıyla yeni biçimi tanıyor; kayıtlı kırpma kusur sayılmaz): ⟨ÖLÇÜM: sağlamlık denetimi kusur sayıları, 119 ikili; koşulmadıysa "koşulmadı"⟩.
- **Ghidra'sız yeniden oynatma:** (a) masum kapının `bilesim_yeniden` / `algoritma_yeniden` katmanları (depoda; 119 / 119 aynı, P00); (b) `ReconstructionStage` yeniden oynatması: var olan koşunun çalışma alanı kopyalanır, yalnız yeniden kurma koşulur (araç depo dışı, yöntem `P12a.md`); 14 ikililik set (P12a, P12b) ve 119 ikili (P-S3). Ad kanalı değişikliğini dakikalar içinde ölçer; Ghidra tarafındaki değişikliği görmez (P12b ürün koşusunda 2 fark, `P12b.md`).
- **BSim:** P16c'den beri toplu sorgu (tek `GenSignatures` + tek `QueryNearest`) öntanım; Ghidra köprüsü cat 2,8×, Mac htop 6,7× hızlı, `bsim_matches.json` 12 / 12 çiftte bayt bayt aynı; `bsim.batch_query` ile kapatılır (DURUM, P16c). Kilit ve sızıntı onarıldı (P16b).
- **Mutasyon düzeni:** `scripts/mutation_probe.py` + `scripts/measurement/mutation_specs_<paket>.json` (her onarım paketinin kendi tanımı); mutant metni özgününden farklı uzunlukta, `PYTHONDONTWRITEBYTECODE=1` (`.pyc` tuzağı); aynı worktree'de eşzamanlı mutasyon koşusu yok ve mutantın `find` metni tekil (P-S3b'de bayat `find` 1 hayatta mutant verdi); ajan beyanından sonra ana oturum main koduyla bağımsız yeniden koşar (`ONARIM_BRIF.md` §4d, DURUM ara noktaları).
- Ön kayıt düzeni: her ad / tip değişikliği `P*_on_kayit.md` ile, değişiklikten önce commit'li; tutmayan hipotez kural değiştirilmeden kayda geçer (aşağıdaki tablo).
- Tip tabanı (DWARF, dwz farkında): `scripts/measurement/dwarf_tip.py`, `ghidra_tip_tabani.py`, `parametre_hizala.py`, `p09_olc.py`; ölçüt taslağı `docs/arge/2026-10-21_k1_k2_onkayit_taslak.md`.
- Yerleşim (modül sınırı) ölçümü: `scripts/measurement/harita_olc.py`, `yerlesim_urun_olc.py`.
- Kör insan etiketleme protokolü: `docs/arge/etiket_protokolu_v2.md`, `scripts/measurement/etiket_paketi.py`, `etiket_puan.py`. Onarımda tek etiketçili gevşek rubrik kullanıldı (P15c rubrik v2; P12b N0b etiketleri); iki değerlendirici ve kappa hâlâ yok (B3).
- Native olmayan hat örnekleri: `~/karadul_olcum/dogrulama_native/` (11 dosya; `MANIFEST.json`; K-8).

**Bilinen olumsuz sonuçlar (yeniden keşfetmeyin, üstüne kurun):**
- **N4 fiil tavanı:** fonksiyon adının fiilini ikilideki kanıttan türetmenin tavanı Mac tmux'ta ≤ %11,1, Mac htop'ta ≤ %20,6. Tablo yuvası kanıtı tmux'ta ≤ %10,6. Kaynak: `docs/arge/2026-11-10_n4/`.
- **Adres sırasına göre yerleşim:** geliştirme setinde makro ARI 0,705 (eşit bölme 0,424, eski ürün 0,097). Sinyal GCC 14 / AArch64'e özgü (`function_align 32:16`); GCC 13 ile derlenmiş ikililerin bir kısmında ve Mach-O htop'ta yok. Bayrak arkasında, kapalı. Kaynak: `docs/arge/2026-11-12_yerlesim/`.
- **Literatür:** LLM tabanlı yöntemler (SYMGEN, REFORGE vb.) ne ölçekte ne doğrulukta tek başına çözüm değil; ölçüm tanımları bizimkinden cömert. Kaynak: `yontem_taramasi.md`.
- **Onarımın olumsuz sonuçları ve tutmayan ön kayıtları** (sayılar DURUM.md'nin paket satırından; ayrıntı paket dosyasında):

| Paket | Ne tutmadı / bedel | Sayı |
|---|---|---|
| P05 | doğru parametre adı düştü; ön kayıt sınırı %10 | 141 → 124 (−%12) |
| P05b | ön kayıt "doğru ≥ 141 ya da kaybın yarısı geri" tutmadı; kanal kesinliği DWARF'a göre %2,7 | 124 → 136; 17 kaybın 5'i geri; 5 100 hükümlü addan 136 doğru |
| P11 | CFG-iso gerçek kod bankası kesinliği hedef 0,90'ın altında (klon düzeltmesiyle 0,912; kalan 9 yanlış `quotearg_*` ↔ `*_mem` ikizleri); öntanımlı banka AArch64'te eşleşemez; ürüne alınmadı (K-1) | ham 0,882 |
| P11 | MaxSMT ofset doğru ama kapsam düşük; erişimlerin %37'si dökülmeyen `CAST` / `PTRSUB` yüzünden çözülemiyor | 727 / 9 295 yapı işaretçisi parametresi |
| P11 → P15c | imza VT'nin adsız fonksiyonlara verdiği adlar tam eşitlikte; gevşek ölçütte (rubrik v2, tek etiketçi) `call_pattern` / `string_ref`; ölçülmüş güvenle ad seçimi gevşek doğruyu 2 düşürdüğü için geri alındı | 0 / 208; 19 / 83 (Wilson alt 0,152) ve 5 / 153 (0,014) |
| P12a | AD-08 H2 tutmadı (17'si ek değil, stratejinin kendi `file_handle_4` adı; tanım değiştirilmedi) | açıklanamayan yerel ad eki 46 730 → 0; H2 tanımıyla 17 |
| P12b | `kebap_ad` adları tam eşitlikte hiç doğru değildi; ad kuralı kurulamadı, en iyi sınıf anahtar erişimi (Wilson %4,4–%21,8); AD-02 "rol + öğe" 92 satırda kural yok; H4 / H5 tanım gereği tutmadı | 239 adda 0 doğru; 5 / 49; N0b gevşek 6 / 76 |
| P-S3 | H5 tutmadı: Homebrew `gcat` (Mach-O, gnulib 2024+) varlık kanıtı yetmedi, kanal sustu → P-S3b'de onarıldı (Mach-O kabul seti 2 / 5 → 5 / 5) | 1 / 2 |
| P16c | "Decompiler Switch Analysis" otomatik analizin %55'i, ama kapatınca `.c` / JSON değişiyor → kabul ölçütünü geçmedi, yalnız ayar; decompile işçi sayısı yük altında ölçülemedi | — |
| P13b | IMZA-16 (C++ RTTI üretici adımı) yapılmadı; kanal tarafı hazır, durum `desteklenmiyor` | — |
| P13a | H6 tutmadı (Mac htop ve `defaults`'ta aday yok); P16a'nın 2 doğru `faz1` adı da gitti | birleştirici kaydı 8 / 10 |
| P16a | GHIDRA-16 dizgi bağı (`808a7f8`) kol B'de B2 / B3 tutmadı → bekletildi; P13a'da aynı ön kayıtla alındı (`faz1` adı 0) | 60 `faz1` adı, 58'i yanlış |
| P08 | H6 tutmadı: Mac htop'ta dizgi katmanı `entry`'ye sahte aday (koda uygulanmıyor) | — |
| P09 | öz-kanıtsız sayacı %50 düşmedi; DWARF'a göre yanlış tip arttı (bağlamanın kaldırılmasından) | +3 |
| P06 | bedel: içerikçe doğru yapısal algoritma etiketleri de düştü (zstd, sqlite3, openssl) | 10 etiket |
| P15c | P08'in "`_` geri düşüşünü kapat" önerisi ölçüldü, uygulanmadı | 4 269 doğru içe aktarımı siliyordu |

- **Hesaplama füzyonu** artık ad kanalı olarak kapalı (`computation.enable_fusion_naming`, P11); güveni ölçülmüş kesinliğin Wilson alt sınırı, ölçülmemiş kaynak çekimser.
- **İmza veritabanı:** yeniden kuruldu (K-5; şema 2, 9 092 473 ad; PyPI kaynağı dışlandı). Kitaplık iddiası kesinliği 0,695 → 0,975 — bu ölçü ikilinin kendi içe aktarım tablosuna karşıdır, ad kesinliği değildir (P08). Kalan 711 yanlışın 616'sı iki sınıftı (`__cxa_*`, `acl_*`); P15c kitaplık iddiasını ikilinin bağlanma kanıtına (ELF sürüm gereksinimi + `DT_NEEDED`) bağladı, 6 742 kaydın iddiası düzeldi.

### 1.1 Onarımın özeti (2026-11-18/19, 40 paket)

İş emri genel taramadır (`RAPOR.md`, 137 bulgu). a62f15e'de 40 paket main'de; tam takım 10 042 geçti / 11 atlandı / 0 kaldı (DURUM, 2026-11-18 20:4x ara noktası). Her pakette ajanın mutasyon sınaması ve ana oturumun main koduyla bağımsız yeniden koşusu var. Paket başına önce / sonra sayıları DURUM.md'de; aşağıdaki bütün sayılar oradandır.

**Kapanan: analisti yanıltan çıktılar**
- Tespit katmanları: ikili istihbarat iddiaları 2 267 → 646, Bluetooth / OpenGL 119 → 0 (P01; kalıntılar P01b'de); anti-debug MED/HIGH geliştirme 8 → 0, masum PE FSG 30 → 0 (P02); YARA yanlış geliştirme 70 / macos 127 / pe 71 → 0, capa ilk kez çalışıyor (P03); yapısal algoritma etiketi 216 → 2, güvenlik anahtar etiketi 894 → 16 (P06).
- Mühendislik paketi: raporlanan bileşim şablonu 533 → 0 (P04a); kapı açıkken API dışı tespit 307 448 → 6 (P04b); `types.h` kanıtsız yapı 4 109 → 0, Ghidra'nın somut tipini ezen 781 → 0 (P09); `rewritten_files` 40 016 → 0, ezilen Ghidra alan adı 4 722 → 0 (P10).
- Adlar: kodda geçersiz parametre adı 2 249 → 0 (P05), işaretçiye skaler ad 656 → 0 (P05b); rol adı fonksiyon adı olarak 70 → 0 (P12a); gnulib kanalı kanıta bağlı (P-S3, P-S3b); dizgi kaynaklı Faz 1 önerisi ön ad değil kanıt satırı (P13a AD-09); kebap adı 239 → 0, yerine `string_roles` kanıt satırı 0 → 266 (P12b); imza VT'nin yanlış kimlik iddiası geliştirme 236 → 0, kabul 123 → 0 (P15c); kitaplık iddiası kesinliği 0,695 → 0,975 (P08); `pdb_parser` her PDB adresini yanlış okuyordu, libz3.dll'de 0 / 771 → 771 / 771 (P13b).
- Rapor, arayüz, akış: uydurma sayaç 42 → 0, dört rapor üreticisi tek veri katmanından (P07); arayüzde eski "F1 ~0.45" yerine yeni2 künyesi, ad düzeltmesi doğru ikiliye 0 / 14 → 14 / 14 (P17); tarama durumları dürüst (`calisti / kismi / hata / arac_yok / desteklenmiyor / kapali`, P-S1); belirlenimci hata aşamayı 4 kez → 1 kez koşturuyor, 8 eşzamanlı çalışma alanı 1 → 8 ayrı dizin (P14).
- Belirlenimcilik: ad haritası `PYTHONHASHSEED`'den bağımsız (P12a; Ghidra dahil 3 ikilide bayt bayt aynı); decompile sırası (P16a); veri akışı birleştirme sırası (P-S3).
- KaradulLM: kanıtsız ad kabulü 4 / 4 → 0 / 4, enjeksiyon 6 / 6 → 0 / 6, masum 8 324 fonksiyonda yanlış alarm 0 (P21).

**Kapanan: güvenlik**
- P-GÜV: hedef çalıştırma ve ağ (GHIDRA-07, 11, 13, MEK-03), 4 / 4; kaynak eşleme artık `network.enabled` da istiyor.
- P19: native olmayan hatlarda düşman girdi 11 + 3 → 0, içe aktarma 2 / 5 → 0.
- P15a: `clean . --yes` bütün çalışma alanlarını siliyordu → reddediliyor; `allow_reference_download` yalnız açık true.
- P16b: BSim sızıntısı (soyulmuş Mac htop'ta sembollü kopyadan adlı aday 597 → 0, GT adı 585 → 0) ve süreçler arası kilit.
- P17 / K-6: ayarsız ilk açılışta giden güncelleme isteği 1 → 0; yeni uçlarda jeton / Host / Origin / yol geçişi 403.

**Hız:** toplu BSim (Ghidra köprüsü 2,8×–6,7×) ve otomatik analiz süre sınırı (P16c); istihbarat taraması 196 ikilide 208 sn → 14 sn (P01b).

**Bekletilenler (K-1: koşar, iddiası koda / rapora yazılmaz):** bileşim şablonları (103 aday, `pending_compositions`; P04a); yapı yeniden yazımı `StructRecoveryEngine.APPLY_REWRITES = False` (önkoşulu P14'te kapandı; ad kaynağı ölçümü P10b'de); capa kod beslemesi `enable_capa_code_feed` (P-S1); füzyon ad kanalı `computation.enable_fusion_naming` ve CFG-iso gerçek kod bankası (P11). Aynı düzende bayrak arkasında: K-4 kanalları (PDB açık; DWARF / BN / TRex / Rust / Go / RTTI kapalı; P13b), FLIRT bayt imzaları (P15b'den beri her girişte bekletiliyor → P08b), JS `analysis.deep_synchrony_prepass` (P20), yerleşim bayrağı (2026-11-12).

**Açık kalanlar** (etkileri a62f15e tabanında YOK; her biri kendi ön kayıtlı ölçümünü taşır):
- Süren (2026-11-19): **P12c** c_namer çok satırlı imza (14 alanda 697 / 13 832 = %5,0 fonksiyon gövdeye bakan stratejilere görünmez; P12b) + P13a kalanları (c_namer kapalıyken ön ad sabit 0,85; FID `caseD_N`); **P16d** Ghidra döküm sırası (`pcode_high_vars` sırası cat 4–6, tree 7–8, sort 11–16 fonksiyonda koşudan koşuya değişiyor; P16c); **P-S4** `stages.py` 4. tur (native olmayan hatlar, evrensel Mach-O dilimleri, `_collect_all_algorithms` silme); **P22c** KaradulLM arayüzü; **P02b** anti-debug kalanları.
- Sırada: **P18** çıktı ağacı (`undefined8 → uint64_t` öntanımı: 8 115 değişen parametrenin 4 450'si; P09); **P10b** K-1 yeniden yazım + MaxSMT `CAST` / `PTRSUB`; **P05c** parametre adları (K-2) + n-gram kökeni; **P08b** FLIRT seçici VT (K-2); **P03b** capa; **P20b** JS + eski deobf silme; **P22h** keşif görevinin ajana bağlanması (metni yazılmadı); en son **P23** (test / CI / ölü kod) ve kapanış denetimi.
- Berke'ye açık (OKU.md): `sigs/ngram_name_db` uygulama paketine girsin mi (uygulamada n-gram `veri_yok`); push.

**Kararlar**

| No | Özet (tam metin DURUM.md "Kararlar", 2026-11-19 kararları `OTURUM_2026-11-19.md`) |
|---|---|
| K-1 | Beklet: uzun onarım isteyen katmanlar koşar; onarılıp masum kapıdan geçene kadar iddiası rapora / koda yazılmaz (silme değil). |
| K-2 | Susturma yok, düzelt: ad kanalları hesaplamayla doğru ada yaklaştırılır. 2026-11-19: `kebap_ad` için Berke karar veremedi; ana oturum önerisi uygulanıyor — kanal ölçülmüş kural gelene kadar ad değil kanıt satırı yazar; ad kuralı Mythos'a hat olarak gider (A5, I1). |
| K-3 | Ölü kod silme (A listesi: `stages.py` monoliti, Ghidra `legacy/`, `confidence_calibration.py`, paralel ad koşucusu); B türü (bağlanabilir) silinmez. |
| K-4 | B türü ad kanalları (PDB, DWARF, BN, TRex, Rust / Go, RTTI) bağlanır; ad üretenler bayrak arkasında ve ölçülerek açılır. |
| K-5 | Yeniden kurulan imza VT uygulama paketine gömülür. |
| K-6 | Açılıştaki güncelleme sorgusu öntanımlı kapalı (uygulandı; açık onay alınmadı). |
| K-7 | Güvenlik bulgularını içeren rapor, güvenlik onarımlarından sonra push edilir (uygulandı; main a62f15e push edildi). |
| K-8 | Native olmayan hatlar için 11 dosyalık örnek seti (`~/karadul_olcum/dogrulama_native/`); hiçbiri çalıştırılmaz. |
| K-9 / K-10 | Ölçüm kopyalarının ve onaylı ölü kodun silinmesi; 2026-11-19'da K-10 onaylandı (eski füzyon, VF2 süreç yolu → P23; `_collect_all_algorithms` → P-S4), eski deobf zincirinin `beautify` / `babel_transforms` adımları silinecek (P20b). |

**Ölçüm zemininde değişenler (planlar bunu bilmeli):** ön ad güveni kanal başına ölçülmüş kesinliğin Wilson alt sınırı (`karadul/core/naming_labels.py` `MEASURED_PRE_NAME_PRECISION`; ölçülmemiş kanalda `null`); gnulib satırı (0,706) P-S3 / P-S3b'den sonra bayat → ⟨ÖLÇÜM: gnulib ön ad kanalının yeni kesinliği⟩; yerel adlar fonksiyon başına tekil; `ghidra_function_count` artık program fonksiyonunu sayıyor, thunk ayrı (eski koşularla kıyas yarıya iner; P16a) — ad nüfusu GT'den geldiği için etkilenmez; imza VT şema 2 veri kökünden açılıyor (P15b); ad haritasında kaynak `signature_db:kimlik` / `signature_db:davranis` (P15c).

## 2. Bağlayıcı kurallar

1. **Motor LLM'siz kalır.** Hesaplama ve kanıt deterministiktir. KaradulLM ayrı bir katmandır: analist açar; ad önerisi ayrı köken bölümünde durur, analist onaylamadan ad haritasına girmez. Yayımlanacak iddialar LLM'siz sonuçlardır.
2. **Başarı ölçütü:** analisti yanıltmamak. Berke amacı doğru anlatan adı başarı sayıyor ("benzerliğe okeyim"; gevşek mod: "seramik duvar" yerine "fayans duvar" başarıdır, "pencere" başarısızlıktır). Ama benzerlik ölçüsü önce tanımlanmalı ve insan yargısıyla doğrulanmalıdır (B3). Tanımsız "benzer" iddiası kabul edilmez.
3. **Önce kesinlik.** Kapsamı artıran her yöntem yanlış oranını artırmamalı. Hedef: yanlış ≤ %10. Ad vermemek (`FUN_…` bırakmak) yanlış ad vermekten iyidir; ama `FUN_` teslim değil, son çaredir. K-2: kanal susturulmaz; ölçülmüş kural yoksa ad yerine kanıt satırı yazar (P12b `string_roles`, P13a AD-09, P15c `davranis`).
4. **Kapsam küçültülmez** (Berke, 2026-11-18). Katman silinmez, onarılır. Onarım evresindeki "yeni özellik yok" kuralı ARGE'de gevşer, ama her yeni yöntem önce bayrak arkasında ve ön kayıtlı ölçümle girer.
5. **Test seti dokunulmazdır** (`test_seti_kilidi.md`). Ayar, eşik ve sözlük yalnız geliştirme setine göre yapılır. Doğrulama seti ara karar içindir; test seti yalnız planlanan açılışta açılır.
6. **Bilim düzeni:** hipotez → ölçüt → ön kayıt (değişiklikten önce, commit'li) → ölçüm → olumsuz sonuç da kayda geçer → iddia yalnız ölçülen kadar. Wilson %95 aralığı; tek ikiliden genelleme yok.
7. **Yaratıcılık protokolü** (Berke, CLAUDE.md §29):
   - (a) Her soru mekanik olarak sınanabilir biçime indirgenir. Doğrulayıcısı olmayan sonuç en fazla "yön gösterici" etiketi alır.
   - (b) Uzlaşıyı bilerek kır. Her hat için literatürün beklenen cevabını yazıp ona aykırı bir öncül dene. Bütün fikirler aynı yere iniyorsa bu bir uyarıdır.
   - (c) Tek hatta uzun süre kal. Her dalgada yeni konu açılmaz; başarısız denemeler ve "neden olmadı" notları sonraki adıma taşınır.
   - (d) Seçimi insan uzman yapar. Berke tersine mühendislikte uzman değil (kendi sözü); eşiğe gelen sonuç yayımdan önce dış bir RE uzmanına okutulur.

## 3. Sorular

Her sorunun altında aynı alanlar var:
- **Bugün:** ölçülmüş durum.
- **Doğrulayıcı:** sonucun mekanik olarak nasıl sınanacağı.
- **Aykırı öncül:** denenmesi istenen karşı görüş.
- **Not:** bilinen tuzak.
- **Onarım sonrası:** a62f15e itibarıyla: değişmedi / kısmen ele alındı (paket + sayı, kaynak DURUM.md) / gereksizleşti / yeni alt soru.

### A. Ad sayısı nasıl artar? (kapsam)

**A1. Eksik adlar nerede? Kapsam bütçesi.**
- **Soru:** 21 371 ad bekleyen fonksiyonun GT'ye göre kırılımı nedir? Kategoriler: statik bağlı kitaplık kodu, derleyici / çalışma zamanı, gnulib türü paylaşılan kod, uygulamaya özgü kod, küçük yaprak fonksiyon, thunk / sarmalayıcı. Her kategoride bugünkü kanalların ulaşabileceği **üst sınır** nedir?
- **Bugün:** doğru ad kapsamı %5,2; kategori kırılımı yok.
- **Doğrulayıcı:** GT'den (dbgsym) kategori etiketi + kanal başına "kanıt var mı" sayımı. Çıktı bir bütçe tablosudur: kategori × (nüfus, bugün doğru, ulaşılabilir üst sınır).
- **Aykırı öncül:** "Kapsamın büyük kısmı kitaplık kodudur ve imzayla çözülür" beklentisini sına. Belki darboğaz uygulama kodudur ve imza işi doymuştur.
- **Onarım sonrası:** değişmedi; bütçe a62f15e tabanından alınır (§1, ⟨ÖLÇÜM: doğru ad kapsamı⟩). Berke'nin hipotezinin (A2, A5, I1) ayrımını bu tablo sayar: ad bekleyen nüfusun ne kadarı kitaplık kopyası (imza yolu, A2), ne kadarı programın kendi kodu (A5). Yeni alt soru: c_namer'ın görmediği fonksiyonlar (14 alanda 697 / 13 832, %5,0; `P12b.md`; onarımı P12c, tabanda yok) bütçede ayrı satır olmalı.

**A2. Kitaplık fonksiyonları: imza, bayt deseni ve benzerlik.**
- **Soru:** Yeniden kurulan imza veritabanı (K-5), FLIRT türü bayt imzaları ve BSim birlikte statik bağlı kitaplık kodunun yüzde kaçını ≥ %95 kesinlikle adlandırır?
- **Doğrulayıcı:** A1'in kitaplık kategorisinde kesinlik ve kapsam. Derleyici sürümü / iyileştirme düzeyi tabakalarında ayrı ayrı.
- **Not:** BSim ortak deposunun sembollü kopyalardan ad sızdırması P16b'de kapandı (soyulmuş Mac htop'ta adlı aday 597 → 0); ölçümde yine koşuya özel `KARADUL_CACHE_DIR`.
- **Onarım sonrası:** kısmen ele alındı. İmza VT yeniden kuruldu ve veri kökünden devrede (P08, P15b: şema 2, 9 092 473 ad; 6 ikilide uygulanan ad farkı 0); kitaplık iddiası kesinliği 119 ikilide 0,695 → 0,975 (P08; içe aktarım tablosuna karşı, ad kesinliği değil); gnulib kanalı yamalı yeniden oynatmada coreutils'te 732 doğru / 0 yanlış (P-S3b); FLIRT bayt imzaları bekletiliyor, seçici VT ile yeniden açılması P08b'de (sırada); BSim toplu sorgu öntanım (P16c). Kanal başına ad kesinliği: §1 kanal kırılımı (⟨ÖLÇÜM: kanal kırılımı farkı⟩).
- **Berke'nin hipotezi (2026-11-19):** "Elimizde çok sayıda imzalı kütüphane var; adı bilinmeyen fonksiyonun ne olabileceğini imzalı olanlardan tahmin edip yerine koymak lazım." Ana oturumun ayrımı: (1) fonksiyon gerçekten bir kütüphanenin kopyasıysa (statik bağlı libc, openssl, zlib, gnulib) imza eşleme doğru yoldur; bu soru A2'dir, ölçülmüş kanıtı yukarıdaki P08 / P-S3b / P15b sayıları. (2) Fonksiyon programın kendi koduysa hiçbir kütüphanede yoktur (A5). (3) İkisinin birleşimi araştırma hattıdır (I1). Bekleyen nüfusta (1) ile (2)'nin payını A1 sayar.

**A3. Derleyicinin kendi bıraktığı üst veriden ad: hiç kullanılmayan kaynaklar.**
- **Soru:** Silinmiş ikilide bile kalan dil çalışma zamanı üst verisi nerede ve ne kadar ad verir?
  - Go: `pclntab`.
  - Rust: v0 / legacy simgeler, panik dizgilerindeki dosya yolları.
  - C++: RTTI / vtable sınıf adları.
  - Objective-C: sınıf ve seçici adları.
  - Swift: tip üst verisi.
  - PDB / DWARF kalıntıları.
- **Bugün (1.22.1):** PDB / DWARF / Binary Ninja / TRex / Rust / Go / RTTI kanalları yazılmış ama akışa bağlı değildi. Mac htop'ta ürün 0 ad veriyordu.
- **Doğrulayıcı:** Mac uygulamaları ve Go/Rust ikililerinden küçük bir set. Kategori başına ad sayısı ve kesinlik. GT'si olan Mach-O'lar `workspaces/olcum_mac/`'ta.
- **Aykırı öncül:** "Mac'te ad sorunu aslında çözülmüş bir sorundur; ObjC / Swift üst verisini okumuyoruz, o kadar" önermesini sına.
- **Onarım sonrası:** kısmen ele alındı (P13b, K-4): kanallar birleştiriciye bağlandı, her biri kendi bayrağıyla (PDB açık, öbür altısı kapalı), aday yalnız Ghidra'nın adsız bıraktığı fonksiyona, güven `null`; `pdb_parser` adres hatası onarıldı (libz3.dll 0 / 771 → 771 / 771); Rust legacy çözülmemiş kaçış 6 102 → 0; RTTI üretici adımı (IMZA-16) yapılmadı; PDB / Go gerçek Ghidra koşusunda ölçülmedi; DWARF yalnız ikili + `.dSYM`. Soyulmuş ELF'te kanallar `veri_yok` (5 ikilide ad haritası bayt bayt aynı) → birleşik tabanda ad etkisi beklenmez. Mac: ⟨ÖLÇÜM: Mac htop / tmux ad sayısı ve doğrusu⟩. Yeni alt sorular: Mach-O'da `main` (I2), üst verinin düşman girdiye dayanıklılığı (I4).

**A4. Başvuru derlemesiyle eşleme (açık kaynak programlar).**
- **Soru:** Programın adı ve sürümü biliniyorsa, aynı kaynağı sembolle derleyip ya da dağıtımın dbgsym paketini alıp fonksiyon eşlemesi yaparak (BinDiff türü, BSim) adların yüzde kaçı kurtarılır? Derleyici, sürüm ve iyileştirme farkı eşleşmeyi nasıl bozar?
- **Bugün:** "kaynak eşleme" katmanı (Layer 1.5) var, ağ kapısına bağlı. Gerçek başarısı ölçülmedi.
- **Doğrulayıcı:** geliştirme setinde başvuru = farklı derleyici / sürüm derlemesi. Ad kesinliği ve kapsamı.
- **Not:** ağa çıkan her yol `network.enabled` kapısından geçer (P-GÜV). Kurulumun çevrimdışı çalışma sözü bozulmaz.
- **Onarım sonrası:** değişmedi. Kaynak eşleme artık `network.enabled` da istiyor (P-GÜV); indirip derleyen `allow_reference_download` yalnız açık true (P15a). Başarısı hâlâ ölçülmedi.

**A5. İkilideki kanıttan hesaplamayla ad (uygulamaya özgü kod).**
- **Soru:** Yalnız ikilideki kanıtla (dizgiler, hata iletileri, çağrılan API'ler, okunan seçenek adları, sabitler) uygulamaya özgü fonksiyonlara ne kadar **yakın** ad üretilebilir? Bu, K-2'nin açık sorusu: `kebap_ad` seçenek adından doğru ada nasıl gider?
- **Bugün (1.22.1):** N4 fiil tavanı düşük (§1). Seçenek adını doğrudan ad yapmak 239 adda 0 doğru verdi.
- **Doğrulayıcı:** B3'te tanımlanan benzerlik ölçüsünün GT'ye karşı dağılımı. Tam eşitlik ayrıca raporlanır. Kural tmux'ta okunduysa tmux dışı, kör etiketli sette sınanır (`P12b.md` kalem 2).
- **Aykırı öncül:** "Uygulamaya özgü adların büyük kısmı ikilide hiçbir kanıt taşımaz" önermesini nicel olarak sına: kanıt taşıyan oran nedir, tavan nedir?
- **Onarım sonrası:** kısmen ele alındı, araştırma açık (P12b). Kebap dizgisinin rolü sınıflandı; kanal ad değil kanıt satırı yazıyor (`string_roles` 0 → 266). 14 ikilide yanlış ad havuzu %44,7 → %21,1, kaybedilen doğru 0 / 441. Ad kuralı kurulamadı (en iyi sınıf 5 / 49). Umut veren iki biçim (`get_<seçenek>` ince alıcı; ikilide tek yayan olay → `<eylem>_<nesne>`) yalnız tmux'ta görüldü; 119'luk sette tmux dışında kebap adı yalnız openssl ve sqlite3'te, toplam 3 ad (`P12b.md`).
- **Karar 2 (K-2, 2026-11-19):** Berke karar veremedi; ana oturumun önerisi uygulanıyor: kanal şimdilik ad değil kanıt satırı yazar. Ad kuralı araştırması kapanmadı; bu hat olarak Mythos'a gider. K-2 bozulmuyor: kanal kapalı değil, ölçülmüş bir kural bekliyor.
- **Bağımsız sınama nüfusu için aday (iddia değil, yalnız aday):** GTK / GLib programları. Kebap biçimli GObject özellik adları (`g_object_get(o, "border-width", …)`) ve sinyal adları (`g_signal_connect(w, "button-press-event", cb)`; geri çağrıların adı çoğu kez `on_<öğe>_<sinyal>`). GT kaynağı Debian dbgsym. Bu nüfus AD-02 "rol + öğe" sorusu için de bağımsızdır.
- **Berke'nin hipotezi burada (A2'deki ayrımın 2. kolu):** programın kendi kodu hiçbir kütüphanede yoktur; `kebap_ad` fonksiyonlarının çoğu tmux'un kendi seçenek işleyicileri. "Benzer imzalı fonksiyonun adını koymak" ölçüldü ve yanlış ad üretiyor: imza VT'nin adsız fonksiyonlara verdiği adlar tam eşitlikte 0 / 208 (P11); gevşek ölçütte `call_pattern` 19 / 83, `string_ref` 5 / 153 (P15c); BSim'deki adlı adaylar aynı programın sembollü kopyasından sızıyordu (597 → 0, P16b). İki bilginin birleşimi I1'de.

**A6. Çağrı grafiği boyunca yayılım.**
- **Soru:** Yapraklar adlandırılınca (kitaplık + kanıtlı adlar) ebeveynlerin adı ya da rolü hesaplanabilir mi? Aşağıdan yukarı ya da yukarıdan aşağı. Hangi kanıt bileşimi yanlış oranını artırmadan kapsamı büyütür?
- **Doğrulayıcı:** yayılımla eklenen adların ayrı kanal etiketiyle kesinliği.
- **Onarım sonrası:** kısmen ele alındı: P13b BORU-10 sayacını gerçeğe çekti (61 "yayıldı" → uygulanan 0; adaylar ayrı alanda, `uygulanmadi` + neden); parametre adı yayılımının uygulanması I5'te. Fonksiyon adı / rol yayılımı için P12b'nin adayı: çağıranın modül öneki (`tty_keys_*` → `tty_keys_<rol>`), yalnız çağıran "kesin" etiketliyse (`P12b.md` kalem 5).

### B. Ad doğruluğu nasıl artar? (kesinlik ve dürüst güven)

**B1. 672 yanlış ad nereden geliyor?**
- **Soru:** Yanlış adların kanal, alt kanal, boyut tabakası ve program bazında kırılımı nedir? Her kanalın ölçülmüş kesinliği nedir; hangileri bir kapıyla düzeltilir, hangileri yöntem değişikliği ister?
- **Doğrulayıcı:** `urun_olc.py` kanal kırılımı. Onarım sonrası taban DURUM.md'deki birleşik ölçümden alınır.

**B2. Güven = ölçülmüş kesinlik (kalibrasyon).**
- **Soru:** Her ada yazılan güven değeri, o kanal ve kanıt türünün geliştirme setinde ölçülmüş kesinliğine eşit olabilir mi? Doğrulama setinde de tutar mı (kalibrasyon eğrisi, Brier / ECE)?
- **Bugün:** ön adlara sabit 0,95 yazılıyordu (AD-07). Mühendislik paketinin "kalibrasyonu" hiçbir karara girmiyordu (MUH-05). Onarım durumu DURUM.md'de.

**B3. "Benzer ad" ölçüsü: tanım ve insan doğrulaması.**
- **Soru:** Berke benzerliği kabul ediyor. Hangi ölçü insanın "amaç doğru" yargısıyla en iyi uyuşur?
  - Adaylar: normalleştirilmiş belirteç Jaccard'ı, eşanlam / kısaltma sözlüğü, düzenleme uzaklığı, belirteç gömme benzerliği.
  - Aday ölçünün eşiği nerede?
- **Doğrulayıcı:** kör iki değerlendirici (`etiket_protokolu_v2.md`). Değerlendiriciler arası uyum (kappa), ölçü ile insan yargısının uyumu (ROC / AUC), eşik doğrulama setinde.
- **Not:** bu ölçü tanımlanmadan A5 / A6 / F'nin hiçbir "benzer ad" iddiası kabul edilmez.

**B4. Ad vermeme kararı (çekimserlik) için maliyet modeli.**
- **Soru:** Analist için yanlış adın maliyeti eksik addan kaç kat yüksek? Bu oran verildiğinde kanal başına en iyi eşik nedir?
- **Doğrulayıcı:** kesinlik / kapsam eğrisinde seçilen işletim noktası, doğrulama setinde.

**B5. Kanallar arası çatışma.**
- **Soru:** İki kanal farklı ad verdiğinde hangisinin doğru olduğu ölçülmüş kesinliklerden belirlenimci bir kuralla seçilebilir mi? Bugünkü birleştirici etkisizdi (AD-04 / 05).
- **Doğrulayıcı:** çatışan çiftlerde seçilen adın kesinliği.

### C. Daha kaliteli tersine mühendislik (tip, yapı, ilişki, okunurluk)

**C1. Tip: Ghidra'dan daha iyi nerede?**
- **Soru:** Karadul'un yazdığı tip, DWARF'a Ghidra'nın tipinden daha mı yakın? Hangi değişken türlerinde (parametre, yerel, global, dönüş) değer katıyor, hangilerinde bozuyor?
- **Doğrulayıcı:** `dwarf_tip.py` + `ghidra_tip_tabani.py`. "Ghidra'dan daha kötü tip yazma" oranı kapıdır (P09'un ön kaydı ve sonucu DURUM.md'de).

**C2. Yapı yerleşimi.**
- **Soru:** İşaretçi aritmetiğinden (`(fonksiyon, değişken)` anahtarıyla, ölçekli ofsetle) ve fonksiyonlar arası birleştirmeden kurtarılan yapıların alan ofsetleri ve boyutları DWARF'la ne kadar uyuşuyor? MaxSMT birleştirmesi (P11'de onarılıyor) ne katıyor?
- **Doğrulayıcı:** yapı başına alan ofseti kesinlik / duyarlılık. Koda bağlanan yapı oranı.

**C3. Modül ve dosya sınırları (yerleşim) derleyiciler arası genelleşir mi?**
- **Soru:** Adres sırası sinyali GCC 14 / AArch64'e özgü çıktı. GCC 12 / 13, clang, MSVC, LTO'lu derlemelerde kaynak dosya sınırını hangi sinyaller öngörür? Hizalama dolgusu, çağrı yerelliği, dizgi tablosu sırası ve hata ayıklama kalıntıları birlikte ne verir?
- **Doğrulayıcı:** `harita_olc.py` ARI, derleyici tabakalarında ayrı ayrı. Yerleşim ön kaydının taslağı `263ae4a`'da.
- **Aykırı öncül:** "0,705 araç zincirinin sonucudur, genelleşmez" (ön kayıt taslağındaki aykırı öncül) burada sınanır.

**C4. Okunurluk ve kod kalitesi.**
- **Soru:** Ghidra çıktısının okunurluğunu ölçen nesnel vekil ölçüler nelerdir? Adaylar: KLOC başına `goto`, `switch` kurtarma oranı, satır içi fonksiyon tespiti, ölü değişken. Karadul'un dönüşümleri bunları nasıl değiştiriyor?
- **Doğrulayıcı:** vekil ölçüler + küçük bir kör insan okunurluk değerlendirmesi. Vekiller insanla uyuşmuyorsa vekil atılır.

**C5. Satıcı / kitaplık kodunu ayırmak.**
- **Soru:** Statik bağlı kitaplık kodunu (gnulib, zlib, OpenSSL) güvenle işaretleyip analistin önünden çekmek, uygulama koduna odaklanmayı ne kadar kolaylaştırır? Yanlış işaretleme zararlı bir modülü "vendor" diye gizler mi (BICIM-11 benzeri risk)?
- **Doğrulayıcı:** işaretleme kesinliği (yanlış "kitaplık" oranı ≤ kabul sınırı) ve kapsam.

### D. Kodun neredeyse tamamını çıkarmak (eksiksizlik)

**D1. Decompile kapsamı: hiçbir fonksiyon ve gövde kaybolmasın.**
- **Soru:** İkilideki fonksiyonların ve komutların yüzde kaçı çıktı ağacına eksiksiz ulaşıyor?
- **Bugün:**
  - `decompiled.json` 500 fonksiyonla sınırlıydı (GHIDRA-05).
  - Gövdeler 5 000 karakterde kırpılıyordu (11 ikilide 13 664 kayıt).
  - Zaman aşımına düşen fonksiyonlar vardı.
  - Onarım durumu P16a'da.
- **Doğrulayıcı:** "kayıp sayacı" (fonksiyon / gövde / dizgi; neden). Hedef: kayıp 0, kalan kayıp nedenleriyle listelenmiş.

**D2. Fonksiyon sınırı ve ayrıştırma kapsamı.**
- **Soru:** Ghidra'nın fonksiyon sınırı tespiti GT fonksiyon listesine göre ne kadar doğru? Kaçan fonksiyonlar, dönmeyen fonksiyonlar, atlama tabloları ve kod içi veri nerede hata yapıyor? Karadul düzeltebilir mi?
- **Doğrulayıcı:** GT (DWARF / simge) fonksiyon başlangıçlarına karşı duyarlılık / kesinlik, mimari ve derleyici tabakalarında.

**D3. Yeniden derlenebilirlik.**
- **Soru:** Çıktı ağacındaki dosyaların yüzde kaçı (taslak başlıklarla) derleniyor? Hangi hata sınıfları baskın? Derlenebilir oran nasıl yükselir?
- **Doğrulayıcı:** dosya başına ve proje başına derleme oranı, hata sınıfı histogramı.

**D4. Davranışça eşdeğer çıktı (en güçlü "kod çıktı" ölçütü).**
- **Soru:** Küçük açık kaynak programlarda (coreutils'ten birkaçı) yeniden derlenen çıktı özgün programın kendi test takımından yüzde kaç geçiyor?
- **Doğrulayıcı:** geçen test oranı. "Neredeyse tamamı çıktı" iddiası ancak bu ölçütle kurulabilir.
- **Not:** bu, bugünkü hedefin çok ötesinde olabilir. Fizibilite önce 1–2 programda denenir; olumsuz sonuç da değerlidir.

**D5. Native olmayan hatların eksiksizliği.**
- **Soru:** JS / Electron, JAR / APK, .NET, PyInstaller örneklerinde (`~/karadul_olcum/dogrulama_native/`) kurtarılan modül, sınıf ve fonksiyon oranı nedir? jadx, ILSpy ve dotnet bu makinede yok; hangi araç zinciri seçilmeli?
- **Doğrulayıcı:** hat başına kurtarılan / toplam (sınıf, metot, modül), ayrıştırılabilir çıktı oranı.

### E. Daha hızlı ve daha az kaynakla çalışmak

**E1. Kritik yol.**
- **Soru:** Geliştirme setinde aşama başına süre ve tepe bellek nedir? Kritik yol hangi aşamalardan geçiyor?
- **Bugün:** eski ölçümde (2026-07-28) Ghidra toplam sürenin ~%56'sıydı. Mühendislik paketi %5,4. Yeniden ölçülmeli.
- **Doğrulayıcı:** boş makinede tekrarlı ölçüm (üç tekrar, medyan), ikili boyutuna göre ölçekleme eğrisi.

**E2. Ghidra analiz seçenekleri: süre ↔ kalite eğrisi.**
- **Soru:** Hangi Ghidra çözümleyicileri kapatılınca ad, tip ve fonksiyon sınırı kalitesi ölçülebilir biçimde düşmüyor? Süre ne kadar kısalıyor?
- **Doğrulayıcı:** seçenek kümesi başına (süre, ad ölçümü, D2 duyarlılığı). Pareto cephesi.

**E3. Önbellek ve artımlı analiz.**
- **Soru:** Ghidra projesini ve aşama çıktılarını sha256 anahtarıyla saklamak yeniden analiz süresini ne kadar düşürür?
- **Bugün:** Ghidra projesi siliniyordu (B-C4). Bu, KaradulLM'in "yeniden hesapla" aracını da engelliyor. Disk maliyeti nedir?
- **Doğrulayıcı:** ikinci koşu süresi / ilk koşu süresi, disk kullanımı.

**E4. Büyük ikililer.**
- **Soru:** 30–40 MB'lık bir ikilide (v1.20.5 hedefi) süre ve bellek nasıl ölçekleniyor? Hangi aşama süperdoğrusal?
- **Doğrulayıcı:** boyut tabakalarında süre / bellek eğrisi.

**E5. BSim.**
- **Soru:** Yerel (native) ve lite kipleri arasında süre ve ad katkısı farkı nedir? Koşuya özel depo, eşzamanlı koşuda kilitlenmeyi (GHIDRA-01) ve sızıntıyı (GHIDRA-02) ne maliyetle çözer?
- **Doğrulayıcı:** BSim kaynaklı adların kesinliği ve kapsamı, süre.

### F. KaradulLM (isteğe bağlı yerel model katmanı)

**F1. Çekimserlik bilgi eksikliğinden mi?**
- **Soru:** Fonksiyon paketine komşu fonksiyonların aşağıdan yukarı özetleri eklenince çekimser oranı ve yanlış ad oranı nasıl değişir?
- **Bugün:** K0 5/5 çekimser. htop'ta çağrılanların 419/419'u adsız (LM-08).
- **Doğrulayıcı:** GT'li küçük sette çekimser oranı, yanlış ad oranı (B3 ölçüsüyle).

**F2. Araç kullanım hatası.**
- **Soru:** Araç döngüsü (K1 / K2) gerçek modelde hiç koşmadı. Yanlış araç, yanlış argüman ve boşa çağrı oranı nedir? Hangi araçlar eksik?
- **Doğrulayıcı:** içerikli araç izi kaydı; hata sınıfı oranları.

**F3. İnce ayar gerekli mi?**
- **Soru:** Ancak F2'de araç hatası yüksek çıkarsa: toplanan izlerle küçük bir modelde (≤ 14B) ince ayar araç hatasını düşürür mü? Bu makinede (36 GiB) bellek sığar mı?
- **Doğrulayıcı:** önce / sonra araç hata oranı, tepe bellek.

**F4. Model boyutu, hız ve bağlam.**
- **Soru:** Boş makinede 27B Q4 modelin 16K bağlamda hızı nedir? Daha küçük modelle kalite ne kadar düşer?
- **Doğrulayıcı:** jeton / sn, F1 ölçüleri.

### G. Ölçmenin kendisi (genelleme ve adil karşılaştırma)

**G1. Geliştirme seti yanlılığı.**
- **Soru:** Geliştirme setinin 117 / 119'u Debian 13 AArch64 GCC 14. x86-64, clang, MSVC, macOS, -O3 / LTO ve PE tabakalarında sayılar ne kadar kayıyor?
- **Doğrulayıcı:** tabakalı bir doğrulama setinde (derleyici × mimari × iyileştirme) aynı ölçüler. Test setine dokunmadan.

**G2. Adil karşılaştırma tabanları.**
- **Soru:** Aynı sette çıplak Ghidra, Karadul ve LLM tabanlı yöntemler (ölçüm tanımı aynı olacak biçimde) nasıl karşılaştırılır? Literatürün cömert ölçüleriyle bizimkini eşitlemeden karşılaştırma yapılmaz.
- **Doğrulayıcı:** ortak ölçü tanımı, aynı GT ve aynı nüfus.

**G3. İnsan değerlendirmesinin maliyeti.**
- **Soru:** B3 ve C4 için kaç örnek, kaç değerlendirici, ne kadar süre gerekir ki aralıklar karar vermeye yetecek kadar dar olsun?

### H. Onarımda ortaya çıkan sorular

**H1. Bekletilen katmanların serbest bırakılma kapısı.**
- **Soru:** K-1 ile bekletilen her katman (bileşim şablonu, yapı yeniden yazımı, capa kod beslemesi, füzyon ad kanalı) hangi ölçüm tutunca öntanımda açılır? Ortak bir "doğrulama kapısı" tanımı: masum ikili kapısında yanlış iddia 0, GT'li sette kesinliğin Wilson alt sınırı ≥ eşik, doğrulama setinde tekrar.
- **Bugün:** her katman kendi paketinde ölçüldü ama açılma ölçütü tek tek yazılmadı.
- **Doğrulayıcı:** katman başına ön kayıtlı kapı + `masum_kapi.py` + GT ölçümü.

**H2. İmza veritabanının adsız fonksiyonlara verdiği adlar.**
- **Soru:** `call_pattern` ve `string_ref` yöntemleri adsız fonksiyonlara betimleyici tahmin üretiyor (`read_env_var`, `verify_certificate`); 12 Debian ikilisinde **0 / 208 doğru** (P11 ölçümü). Bu yöntemler kimlik değil, rol tahmini üretiyor. K-2'ye göre susturulmaz: rol tahmini doğru ada (ya da doğru rol etiketine) nasıl yaklaştırılır, gevşek ölçüyle (B3) ne kadarı "amacı doğru" sayılır?
- **Doğrulayıcı:** GT'ye karşı tam eşitlik ve B3 benzerlik ölçüsü; kanal başına kesinlik.

**H3. CFG-iso: ikizler ve banka genellemesi.**
- **Soru:** Gerçek koddan kurulan şablon bankası (cat → ls / sort / expr) ham 0,882 kesinlik verdi; kalan yanlışların hepsi `quotearg_*` ↔ `*_mem` ikizleri: CFG ve komut histogramı aynı, yalnız işlenenler farklı. İşlenen bilgisi (sabitler, çağrılan fonksiyon kimliği) eklemek ikizleri ayırır mı? Banka derleyici sürümleri ve mimariler arasında genelleşir mi (GCC 12 / 13 / 14, clang, x86-64)?
- **Bugün:** çift başına Wilson alt sınırı 0,76–0,78; füzyonun kabul eşiği 0,90 → banka ürüne alınmadı.
- **Doğrulayıcı:** derleyici tabakalarında kesinlik / duyarlılık; ikiz çiftlerde ayırma oranı.

**H4. Parametre adları: kanıtın tavanı.**
- **Soru:** Anlamsal parametre adlandırıcısının kesinliği DWARF'a göre %2,7 (5 100 hükümlü addan 136 doğru); skaler genel adlar (`count` 5 199, `enabled` 1 165, `value` 573) baskın. Hangi kanıt türleri (çağrı yerindeki API argüman adı, assert dizgisi, yapı alanı) parametre adını gerçekten belirler; tavan nedir?
- **Doğrulayıcı:** `p09_olc.py` + `parametre_hizala.py`; kural başına kesinlik, kanıt türü başına kapsam.

**H5. MaxSMT yapı kurtarmanın kapsamı.**
- **Soru:** Ofset onarıldı (B1 0,997, B2 0,852) ama kapsam düşük: 9 295 yapı işaretçisi parametresinin 727'si. Erişimlerin %37'si P-code dökümüne yazılmayan `CAST` / `PTRSUB` / `MULTIEQUAL` ile tanımlanıyor. Bunları dökmek kapsamı ne kadar artırır, P-code'u okuyan öbür adımları (fonksiyon sınıflaması → ad adayları) nasıl etkiler?
- **Doğrulayıcı:** DWARF yapı alanı kesinlik / duyarlılık, ad haritası farkı (ön kayıtlı).

**H6. Hız: BSim ve Ghidra'nın payı (E1, E2, E5'e veri).**
- **Bugün:** BSim fonksiyon başına ayrı sorgu (0,04–0,22 sn / fonksiyon; Mac htop 597 fonksiyonda 133 sn) ve oturumlar süreçler arası sıraya giriyor. Ghidra'nın otomatik analizi hâlâ süre sınırsız. Hızlandırma paketi (P16c) hazır, sonraki oturumda.

## 4. Ana oturumun öncelik önerisi (yalnız bir görüş; Mythos itiraz edebilir)

0. **Onarım sonrası birleşik ürün ölçümü (119 ikili) önce.** Bütün planlar o tabana göre yazılır (§1.1).
1. **G1 + B3 önce.** Ölçü tanımı ve genelleme sorusu çözülmeden hiçbir "iyileşme" yorumlanamaz.
2. **A1, kapsam bütçesi.** Ad sayısını artırmanın nerede mümkün olduğunu sayıyla gösterir; hangi hattın değerli olduğunu bu seçer.
3. **A3, dil çalışma zamanı üst verisi.** Mac'te ürün bugün 0 ad veriyor. Kanıt güçlü, deterministik, yanlış oranı düşük olması beklenir. En ucuz büyük kazanç adayı.
4. **A2, kitaplık kodu ve D1, kayıp sıfır.** Mühendislik işi ağırlıklı, riski düşük.
5. **A5 ve F.** En belirsiz ve en araştırmacı hatlar; tek hatta uzun süre kalma kuralıyla yürütülür.

## 5. Mythos'tan beklenen plan biçimi (seçilen her hat için)

```
## Hat: <ad>  (soru kimlikleri: A1, …)
- Hipotez: <tek cümle, sınanabilir>
- Literatürün beklediği cevap: <…>   Aykırı öncül: <…>
- Ölçüt ve doğrulayıcı: <hangi betik, hangi set, hangi sayı; "tuttu" / "tutmadı" eşiği önceden>
- Ön kayıt taslağı: <değişiklikten önce yazılacak beklenti>
- İş paketleri (Opus ekibi için): <paket başına dosya sahipliği, 5–8 kalem, ayrık dosya kümeleri>
- Gerekli veri ve araç: <indirme gerekiyorsa liste: ad, kaynak, boyut; Berke onayı>
- Durma ölçütü: <ne olursa hat kapanır>
- Riskler ve bilinmeyenler: <…>
```

## 6. Bu listenin sınırları

- Sorular onarım sürerken yazıldı. Onarım sonrası sayılar (DURUM.md) bazı soruları gereksiz kılabilir ya da yenilerini doğurabilir. Mythos önce DURUM.md'yi okumalı.
- Literatür sayıları bu belgede doğrulanmadı. Ayrıntı ve tarih `yontem_taramasi.md`'de; değişen konular (model sürümleri, araçlar) yeniden taranmalı.
- "Kodun neredeyse tamamı" için kesin bir hedef bugün tanımlı değil. D1–D4 bu hedefi ölçülebilir kılmak için yazıldı.
