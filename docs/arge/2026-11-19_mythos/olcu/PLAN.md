# ÖLÇÜ hattı — uygulama planı (tur 1 sonrası, 2026-11-19)

Bu plan kendi başına uygulanır: yazan ajan sonraki oturumda yok. Dayanak sayılar `BULGULAR.md`, gerekçe ve "neden olmadı" notları `DEFTER.md`. Taban: birleşik ölçüm a62f15e (119 ikili).

**Kısaltmalar:** `$R` = `/Users/apple/Black_Widow`; `$V` = `~/karadul_olcum/runs/arge-2026-11-19/olcu`; `$H` = `$R/scripts/arge/olcu` (bu turun araştırma betikleri). Bütün komutlar `$R`'den, `PYTHONDONTWRITEBYTECODE=1` ile.

**Bu turdan devralınan, diskte duran girdiler** (yeniden üretilebilir; komutlar betiklerin başında):

| Dosya | İçerik |
|---|---|
| `$V/etiketler.jsonl`, `etiket_envanteri.json` | 1 319 vekil (ajan) üçlüsü: küme, aday, GT, etiket (`etiket_topla.py`) |
| `$V/taban_a62f15e.json`, `taban_yeni2_f30ac9a.json` | iki kolun adları + ikili başına bütün GT adları (`taban_dok.py`) |
| `$V/taban_puan.json`, `taban_puan_yeni2.json` | bölge sayımı, 119 yanlışın listesi, ikiz yoğunluğu (`taban_puanla.py`) |
| `$V/roc.json`, `bantlar.json`, `kimlik.json`, `idf.json` | ölçü ↔ vekil hüküm çözümlemeleri |
| `$V/karar.json`, `tekil.json`, `literatur_olcusu.json`, `ornek_sayisi.json` | karar tablosu, tekil sayım, NERO ölçüsü, örnek sayıları |
| `$V/catisma.json`, `kalibrasyon.json` | kazanan ↔ yedek aday dökümü ve kural oynatması; güven ↔ gerçekleşen doğruluk (`catisma.py`, `kalibrasyon.py`) |
| `$V/roc_egri.json`, `kimlik_hatalari_{kural,tutucu}.json` | ROC noktaları ve AUC aralıkları; KİMLİK hattının yanlış eşlemelerinin aynı ölçülerle sayımı |
| `$H/sozluk.json` | sözlük, sha256 `85711dc615f6787189ee7b37d583fa9f70bd76b3e83176f83b863d86a858a46d` (değiştirilmez) |

**Değişmez kurallar (her pakette geçerli):** kilitli setler (`targets/test_seti`, `targets/dogrulama_seti`, koşuları) açılmaz; kilit belgelerinde adı geçen hiçbir program kullanılmaz. İndirme yalnız Berke'nin onayıyla. Aynı anda en çok 1 Ghidra koşusu, koşuya özel `KARADUL_CACHE_DIR`, `PYTHONHASHSEED=0`. Ön kayıt ölçümden önce commit'lenir; tutmayan beklenti silinmez. İnsan etiketini model üretmez. Her sayı betik çıktısıdır; Wilson %95 (`ks1_olc.oran`). Her sayı örnek ve tekil düzeyde verilir.

---

## 0. Hat (soru listesi §5 biçimi)

## Hat: ÖLÇÜ  (soru kimlikleri: B3, B4, B2, B5, G1, G2, G3)

- **Hipotez:** "Amacı doğru ad" tek bir mekanik ölçüyle sayılamaz. Sayılabilir olan üç bölgedir: (1) tam + biçim (mekanik, hükümsüz); (2) belirteç örtüşmesi olmayan adlar (büyük olasılıkla yanlış); (3) aradaki bant (yalnız insan hükmüyle). İki insan değerlendiricinin hükmüne karşı da hiçbir sözcük ölçüsü, tam eşit olmayan adlarda 0,90 kesinlikli eşik vermez.
- **Literatürün beklediği cevap:** belirteç F1 (CodeWordNet'li ya da değil), gömme ya da dil modeli hakem; eşik 0,5. **Aykırı öncül (bu turdan çıkan):** hükmü belirleyen, örtüşen belirteçlerin oranı değil, eksik ya da fazla kalan tek belirtecin fonksiyonu kardeşlerinden ayırıp ayırmadığıdır; bu bilgi ad dizgilerinde değil fonksiyonun işindedir. Hattın ürünü "daha iyi benzerlik ölçüsü" değil, hükmü kimin vereceğini ve kaç etiketle yetinileceğini belirleyen sayım düzenidir.
- **Ölçüt ve doğrulayıcı:** paketlerin kabul ölçütleri (§3). Ana doğrulayıcı: iki kör insan değerlendirici (P-Ö3, P-Ö4).
- **Ön kayıt taslağı:** her paketin "Ön kayıt metni" bölümü.
- **İş paketleri:** §2–§3.
- **Gerekli veri ve araç:** §4 (indirme listesi), iki insan değerlendirici (Berke bulur).
- **Durma ölçütü:**
  - İnsan–insan kappa (`yakin`) rubrik düzeltmesinden sonra da < 0,40 → "amaç doğru" ölçülebilir kavram değil; hat kapanır, proje yalnız `tam + biçim` ve yanlış oranı raporlar.
  - P-Ö4'te hipotez doğrulanırsa mekanik "yakın ad" ölçüsü arayışı kapanır; kalıcı düzen §1'dir.
  - Set dışı tabakalarda (P-Ö6–P-Ö8) kanal kesinliğinin tekil alt sınırı geliştirme setindekinden ≥ 0,10 düşükse güven tablosu tabaka başına yazılır; değilse tek tablo kalır.
- **Riskler ve bilinmeyenler:** değerlendirici bulunamazsa insan kolu durur; `yakin` olumlu payı küçük (~%9), örneklem bu yüzden zenginleştirildi; kanıt satırının ve ad ailesinin yararı (karar modelindeki e, a) hiç ölçülmedi; tekil düzeyde bağımsız kanıt az (gnulib kanalı 10 tekil ad); etiketleme kaynak kodu ister ve geliştirme setinin beş programının kaynağı diskte yok.

## 1. Sayım düzeni (öbür hatlar için bugünden geçerli öneri)

"Yakın ad" iddia eden her ölçüm şu dört bölgeyi birlikte verir; tek sayıya indirmez:

| Bölge | Tanım | Betik | İddia düzeyi |
|---|---|---|---|
| tam | `urun_olc` hükmü | `scripts/measurement/urun_olc.py` | doğru |
| biçim | harf dizisi aynı: büyük / küçük harf, `_`, derleyici eki, `_N` çakışma eki (`harf_tam`) | bugün `$H/taban_puanla.py`; P-Ö1'den sonra `urun_olc.py` | doğru (rubrik v2 `tam` tanımı; insan teyidi P-Ö4 ölçüt 4) |
| ara bant | tam / biçim değil, sözlüklü belirteç örtüşmesi var | `$H/taban_puanla.py` (`kimlik_adayi` + `ortusen_diger`) | **hüküm yok**: insan etiketi ya da "bilinmiyor" |
| ayrık | belirteç örtüşmesi yok | `$H/taban_puanla.py` | yanlış sayılır (vekil hükümle %80,5 yanlış, %3,0 yakın) |

- "F1 ≥ eşik" hiçbir hatta başarı ölçütü olmaz (BULGULAR §2.3, §3). Kimlik eşlemesinde ikiz çiftlerini yalnız tam / biçim ayırır.
- Literatür kıyası için ayrıca NERO tanımıyla belirteç P / R / F1, iki nüfusla (ad verilen; nüfusun tamamı).
- Yeni bir koşuyu bu düzenle saymak için bugün: `python $H/taban_dok.py --agac <ürün ağacı> --kok <koşu kökü> --mac-veri $R/workspaces/olcum_mac --json <d.json>` (ürün ağacı `PYTHONPATH`'te), sonra `python $H/taban_puanla.py --taban <d.json> --json <p.json>` ve `python $H/tekil.py --olgu <olgu.jsonl.gz> --taban <d.json> --json <t.json>`.

## 2. Paket sırası ve önkoşullar

| Sıra | Paket | Önkoşul | Ghidra | İndirme | Paralel gidebilir |
|---|---|---|---|---|---|
| 1 | **P-Ö1** biçim satırı (`urun_olc`) | yok | hayır | hayır | P-Ö3, P-Ö5 ile |
| 2 | **P-Ö2** ad bölgeleri ve belirteç ölçüsünün ortak ölçüme taşınması | P-Ö1 (aynı yardımcı modül) | hayır | hayır | P-Ö3, P-Ö5 ile |
| 1 | **P-Ö3** insan etiket paketi İ-1 (tmux + htop, Mac) | yok | hayır | hayır | P-Ö1, P-Ö5 ile |
| 3 | **P-Ö4** insan etiketinin puanlanması | P-Ö3 + iki değerlendiricinin teslimi | hayır | hayır | — |
| 1 | **P-Ö5** çatışma ve kalibrasyon ölçülerinin ortak ölçüme taşınması | yok (P-Ö1 varsa `ad_bicimi` kullanılır) | hayır | hayır | P-Ö1, P-Ö3 ile |
| 2 | **P-Ö6** tabaka C: yerel derleme matrisi (clang, 6 düzey) | yok (P-Ö1 varsa biçim satırı da raporlanır) | evet (sıralı) | hayır | P-Ö7 ile değil |
| 3 | **P-Ö7** tabaka A / B: x86-64 ve GCC 12 / 13 | Berke'nin indirme onayı; P-Ö6 bitmiş | evet | evet | — |
| 4 | **P-Ö8** tabaka D: keşif dışı set kurası ve ölçümü | Berke'nin onayı; P-Ö7 bitmiş | evet | evet | — |
| 4 | **P-Ö9** insan etiket paketi İ-2 (Debian programları) | P-Ö4 "tuttu" (ölçüt 1); kaynak indirme onayı | hayır | evet | — |

Dosya kümeleri ayrık (her paketin "Dosyalar" satırı). P-Ö1 ile P-Ö2 sıralıdır (ikisi de `scripts/measurement/ad_bicimi.py`'ye bağlı; onu P-Ö1 yazar). Toplam 9 paket; aynı anda en çok 3 (P-Ö1, P-Ö3, P-Ö5).

## 3. Paketler

### P-Ö1 — Biçim satırı (`urun_olc`)

- **Amaç:** tam eşitliğin yanına, insan hükmü gerektirmeyen "yalnız biçim farkı" düzeyini ortak ölçüme duyarlılık satırı olarak eklemek.
- **Dosyalar (yazar):** yeni `scripts/measurement/ad_bicimi.py`; var olan `scripts/measurement/urun_olc.py`; yeni `tests/test_ad_bicimi.py`; var olan `tests/test_urun_olc.py` (yalnız ek sınama); yeni `scripts/measurement/mutation_specs_po1.json`; yeni `docs/arge/2026-11-19_mythos/olcu/P-O1_on_kayit.md`, `P-O1.md`.
- **Dokunmaz:** `scripts/measurement/ks1_olc.py` (ön kayıtla sabit), `karadul/`, `$H/*`.
- **Adımlar:**
  1. `ad_bicimi.py`: `$H/olcu.py`'deki `ek_soy`, `harf_dizisi`, `harf_tam` işlevlerini **aynen** taşı (yalnız bu üçü; `KLON_EKI_RE` `ks1_olc.KLON_EKI_RE`'den içe aktarılır, kopyalanmaz). Belge dizgisinde rubrik v2 `tam` tanımına atıf kalır.
  2. `urun_olc.degerlendir_elf`: her kayda `"bicim": durum == DOGRU or ad_bicimi.harf_tam(yeni, [ks1.platform_adi(g, platform_) for g in gt_adlari])` alanını ekle (GT yoksa `False`).
  3. `urun_olc.fonksiyon_ozeti`: `"bicim_normallestirmesi": ks1.oran(sum(k["bicim"]), n)` ekle; `DUYARLILIK_OLCULERI`'ne adını ekle. **Karar alanlarına (`kol_kararlari`, `olcu`) dokunma.**
  4. `toplam_ozeti` / `program_makrosu` ile aynı kuraldan `tam + biçim` hükmüyle program düzeyi makro yanlış oranını duyarlılık satırı olarak üret (`$H/taban_puanla.py` içindeki `makro` işlevi başvuru uygulamasıdır: birimde en az `ks1.N_MIN` ad; platform birimleri önce ortalanır).
  5. `olc_markdown` ve `karsilastir_markdown`: duyarlılık cümlesine "biçim normalleştirmesiyle doğru k / n; tam + biçim makro yanlış" ekle. `oge_yaz` / `oge_oku` biçimini **değiştirme** (`karsilastir` eski JSON'larla çalışmalı).
  6. İki kolda koş: `python scripts/measurement/urun_olc.py olc --kok-debian ~/karadul_olcum/runs/urun-onarim-a62f15e/debian --kok-mac ~/karadul_olcum/runs/urun-onarim-a62f15e/mac --mac-veri $R/workspaces/olcum_mac --kol onarim --json <çıktı>` ve aynısı `urun-yeni2-f30ac9a` için. (Ad sınıflayıcısı betiğin ağacından geldiği için ana ağaç ile ürün ağacının `naming_labels.py` / `alt_kanal.py` sha256'ları aynı değilse ölçüm, betiğin kopyalandığı ürün ağacından koşulur: birleşik ölçümün ön kaydı §2.2 kuralı.)
  7. Sınamalar ve mutasyon (aşağıda); `P-O1.md` sonuç belgesi.
- **Kabul ölçütü (tam eşitlik; bu turun betik çıktıları):**

| Kol | Ad | Tam doğru | Biçim (tam değil) | Tam + biçim yanlış | Tam + biçim makro yanlış |
|---|---|---|---|---|---|
| a62f15e | 1 800 | 1 681 | 40 | 79 (0,043889) | 0,1914 (coreutils 0,0070; openssl 0,0769; redis-tools 0,2000; sqlite3 0,5833; tmux 0,1178; zstd 0,1636) |
| f30ac9a (1.22.1) | 2 261 | 1 589 | 47 | 625 (0,276426) | 0,4077 |

  Ayrıca: var olan bütün alanlar (karar (a)–(c), kanal kırılımı, `ogeler`) iki kolda bayt düzeyinde eski çıktıyla aynı (yeni alanlar hariç); `tests/test_urun_olc.py` yeşil.
- **Ön kayıt metni (`P-O1_on_kayit.md`, koddan önce commit):**
  > Ölçü: `bicim` = ürün adı GT adlarından biriyle harf dizisi olarak aynı (derleyici eki ve sondaki `_<rakam>` soyulur; küçük harf; harf-rakam dışı atılır) ve tam eşit değil. Karar ölçütlerine girmez. Beklenen: a62f15e'de biçim 40 (hepsi `string_context/oz_ad`; zstd 37, coreutils 1, openssl 1, mac/tmux 1), tam + biçim yanlış 79 / 1 800, makro 0,1914; f30ac9a'da biçim 47, yanlış 625 / 2 261, makro 0,4077. Kaynak: `$V/taban_puan.json`, `$V/taban_puan_yeni2.json` (2026-11-19). **Tuttu:** altı sayı tam eşit. **Tutmadı:** herhangi biri farklı; fark açıklanmadan satır yayımlanmaz. Bu satır "yanlış ≤ %10" kararını değiştirmez; karar tam eşitlikle verilmeye devam eder (Berke aksini söyleyene kadar).
- **Sınama ve mutasyon:** `tests/test_ad_bicimi.py` en az şu durumlar: deve yazımı ↔ küçük harf (`FSE_buildDTable_internal` ↔ `fse_builddtable_internal` → doğru); `_2` eki; `.part.0` / `.isra.0` / `.cold.1` eki; Mach-O baştaki `_`; boş ad ve yalnız rakam (→ yanlış); bir harf farkı (→ yanlış); iki GT takma adı. Mutantlar (`mutation_specs_po1.json`; her biri özgünden farklı uzunlukta, `find` metni tekil): (m1) `.lower()` kaldırılır → deve yazımı sınaması kırmızı; (m2) `_N` soyma kaldırılır → `_2` sınaması kırmızı; (m3) `ek_soy` çağrısı kaldırılır → derleyici eki sınaması kırmızı; (m4) `harf_tam` boş dizide doğru döner → boş ad sınaması kırmızı; (m5) `bicim` karar sayımına katılır → "kararlar değişmez" sınaması kırmızı. Beklenti 5 / 5 öldü. Koşum: `PYTHONDONTWRITEBYTECODE=1 python scripts/mutation_probe.py --spec scripts/measurement/mutation_specs_po1.json`; aynı worktree'de eşzamanlı mutasyon koşusu yok.
- **Ürüne / ortak ölçüme girişi:** yalnız ortak ölçüm (`urun_olc.py` duyarlılık satırı). Ürün koduna girmez. Sonraki birleşik ölçüm belgeleri iki hükmü yan yana yazar.

### P-Ö2 — Ad bölgeleri ve belirteç ölçüsünün ortak ölçüme taşınması

- **Amaç:** §1'deki dört bölgeli sayımı, ikiz yoğunluğunu ve literatür tanımlı belirteç ölçüsünü her koşuda tek komutla üretmek.
- **Dosyalar (yazar):** yeni `scripts/measurement/ad_bolgeleri.py`, `scripts/measurement/belirtec_olc.py`, `scripts/measurement/ad_sozlugu.json`; yeni `tests/test_ad_bolgeleri.py`, `tests/test_belirtec_olc.py`; yeni `scripts/measurement/mutation_specs_po2.json`; `docs/arge/2026-11-19_mythos/olcu/P-O2.md`.
- **Dokunmaz:** `urun_olc.py`, `ks1_olc.py`, `karadul/`, `$H/*` (kaynak olarak okunur, silinmez).
- **Taşınacaklar (nereden → nereye):**

| Kaynak (`$H`) | Hedef (`scripts/measurement/`) | Ne taşınır |
|---|---|---|
| `olcu.py`: `ek_soy`, `harf_dizisi`, `harf_tam` | `ad_bicimi.py` (P-Ö1) | biçim düzeyi |
| `olcu.py`: `belirtecler`, `kok`, `acik`, `kanon`, `eslesir`; `sozluk.json` | `ad_bolgeleri.py`; `ad_sozlugu.json` (bayt bayt kopya, sha256 `85711dc6…`) | yalnız "örtüşme var / yok" ve kardeş karşılaştırması için gereken sözlüklü eşleşme |
| `kimlik.py`: `IkiliGt` | `ad_bolgeleri.py` | ikili içi b, r hesabı |
| `taban_puanla.py`: `bolgeler`, `ikiz`, `makro` | `ad_bolgeleri.py` | bölge ataması, ikiz yoğunluğu |
| `tekil.py` | `ad_bolgeleri.py` (`--olgu` seçeneği) | tekil düzey sayım |
| `taban_dok.py` | **taşınmaz**: girdi OLGU tablosudur (`olgu.jsonl.gz`: `urun_adi`, `gt_adlari`, `kanal`, `hukum`, `nufusta`, `adres_hex`); ikilinin bütün GT adları aynı tablodan toplanır | — |
| `literatur_olcusu.py` | `belirtec_olc.py` | NERO tanımı; iki nüfus; mikro / makro |
| `catisma.py`, `kalibrasyon.py` | `catisma_olc.py`, `kalibrasyon_olc.py` (**P-Ö5**) | çatışma dökümü, kural oynatması, güven ↔ gerçekleşen tablo |
| `roc.py`, `roc_egri.py`, `bantlar.py`, `kimlik.py` (ölçü kısmı), `idf.py`, `karar.py`, `ornek_sayisi.py`, `etiket_topla.py`, `kimlik_hatalari.py` | **taşınmaz** (araştırma betiği; P-Ö4 `$H`'den çağırır) | — |

- **Adımlar:**
  1. `ad_bolgeleri.py`: girdi `--olgu <olgu.jsonl.gz>`; çıktı JSON + Markdown: kanal ve birim başına ayrık bölgeler (`tam`, `bicim`, `kimlik_adayi`, `ortusen_diger`, `ayrik`, `gt_yok`), örnek ve tekil düzeyde; yanlışların listesi yalnız JSON'da (ad geçer; depo dışına yazılır).
  2. İkiz yoğunluğu alt komutu (`ikiz`): nüfus, F1 ≥ 0,5 / ≥ 0,8 ikizi olan, kırpığı başka fonksiyonun adı olan; örnek, tekil, gnulib dışı tekil.
  3. `belirtec_olc.py`: `alt_belirtecler` (alfabetik, deve yazımı bölünür, küçük harf, küme), `say`, `ozet`; nüfuslar: ad verilen, nüfusun tamamı, nüfusta ad verilen.
  4. Sabitler tek yerde (modül başında): uzlaşı eşiği 0,5 (yalnız karşılaştırma bayrağı), ikiz eşikleri (0,5; 0,8), önek kısaltması en az 4 harf.
  5. a62f15e OLGU tablosunda koş; kabul sayılarıyla karşılaştır.
  6. Sınamalar, mutasyon, `P-O2.md`.
- **Kabul ölçütü (a62f15e; tam eşitlik):** bölgeler örnek düzeyinde 1 681 / 40 / 9 / 47 / 23 / 0; tekil düzeyde 422 / 40 / 9 / 46 / 18 (535 tekil ad); ikiz: nüfus 21 371, F1 ≥ 0,5: 16 305, F1 ≥ 0,8: 6 987, kırpık 6 995; tekil nüfus 9 257, F1 ≥ 0,5: 8 099, F1 ≥ 0,8: 3 211; NERO: ad verilen mikro P 0,9587 / R 0,9303 / F1 0,9443; nüfus mikro P 0,9469 / R 0,0493 / F1 0,0938, makro F1 0,0583. Kaynak: `$V/taban_puan.json`, `tekil.json`, `literatur_olcusu.json`.
- **Ön kayıt metni:** yeni ölçüm yok; yeniden üretim paketidir. `P-O2.md` başına: "Beklenen: yukarıdaki sayılar tam eşit. Fark çıkarsa taşıma hatasıdır; `$H` betikleri başvurudur."
- **Sınama ve mutasyon:** bölge ataması için elle kurulmuş küçük bir ikili (5 fonksiyon: tam, biçim, kapıdan geçen, kapıdan geçmeyen kardeş, ayrık); ikiz için 4 adlık küme (`a_b`, `a_b_c`, `a_b_d`, `x`). Mutantlar: (m1) kapı `b > r` yerine `b >= r`; (m2) `ayrik` koşulu `Ps > 0`'a döner; (m3) ikizde `g != f` dışlaması kalkar; (m4) NERO'da küme yerine liste (yineleme duyarlı); (m5) boş tahmin fn saymaz. Beklenti 5 / 5 öldü.
- **Ürüne / ortak ölçüme girişi:** ortak ölçüm betiği; birleşik ölçüm belgelerinin "duyarlılık" bölümüne eklenir. Ürün koduna girmez.

### P-Ö3 — İnsan etiket paketi İ-1 (indirme gerektirmez)

- **Amaç:** iki kör insan değerlendirici için, kaynak kodu diskte olan iki programdan (Mac tmux 3.8, Mac htop 3.5.3) dört tabakalı etiket paketini üretmek.
- **Dosyalar (yazar):** yeni `$H/paket_sec.py`, `$H/paket_tablo.py`; yeni `tests/test_arge_olcu_paket.py`; çıktı `$V/insan_i1/` (paketler, `ogeler.json`); anahtarlar **ayrı** dizinde `~/karadul_olcum/runs/arge-2026-11-19/olcu_anahtar/` (değerlendiricilere verilen dizinlerden ve ajanların geçici dizinlerinden ayrı); `docs/arge/2026-11-19_mythos/olcu/P-O3_on_kayit.md`, `P-O3.md`.
- **Dokunmaz:** `scripts/measurement/etiket_paketi.py`, `etiket_puan.py` (yalnız çağrılır); `docs/arge/etiket_rehberi.md`, `etiket_protokolu_v2.md`; `docs/arge/2026-10-19_g4_etiketleme/veri/` (salt okur).
- **Tabakalar (hepsi tohumlu ve belirlenimci; tohum 2026111901; aynı adres en çok bir tabakada, öncelik T1 > T2 > T4 > T3):**

| Tabaka | Kaynak | Seçim | Öğe |
|---|---|---|---|
| T1 | `$V/taban_puan.json` `yanlislar`, `ikili == "mac/tmux::tmux"`, `bolge ∈ {kimlik_adayi, ortusen_diger, ayrik}` | hepsi | 30 |
| T2-tmux | `$V/etiketler.jsonl`, `kume == "G4-L1-tmux"`, yem değil, tam eşit değil | ajanın `dogru_tarif` dediği 30'un hepsi + dört hücreden (örtüşen / ayrık × `yalniz_alan` / `yanlis`; örtüşme = `olcu.puanla(...)["Ps"] > 0`) 25'er | 130 |
| T2-htop | aynı dosya, `kume == "G4-L3-htop"` | örtüşen 25'in hepsi + ayrık `dogru_tarif` 2 + öbür ayrıklardan 25 | 52 |
| T3 (ikiz) | `$V/taban_a62f15e.json`, `mac/tmux::tmux` ve `mac/htop::htop`, nüfustaki fonksiyonlar | sözlüksüz F1'i en yüksek kardeşi ≥ 0,8 olanlardan program başına 30; **aday = o kardeşin GT adı** (baştaki `_` soyulur; eşitlikte adres sırası) | 60 |
| T4 (biçim) | aynı dosya, nüfustaki fonksiyonlar | htop'tan 20 (aday = GT adının küçük harflisi; GT'de büyük harf olanlardan), tmux'tan 10 (aday = GT adı + `_2`) | 30 |
| yem | `etiket_paketi.py`'nin kendi kuralı (~%10) | otomatik | ~30 |
| **Toplam** | | | **302 ana öğe (+ yem) × 2 değerlendirici** |

  Hücre yeterliliği bu turda sayıldı (`$V/bantlar.json` `kume_iliskisi`): tmux örtüşen `yalniz_alan` 106, `yanlis` 60; ayrık 28 ve 115; htop örtüşen 25, ayrık 72 (2 `dogru_tarif`). Örnek sayısı gerekçesi (`$V/ornek_sayisi.json`): kappa ±0,10 için κ 0,8 ve olumlu payı 0,30'da 168 öğe, 0,10'da 412; T2 bu yüzden `yakin` yönünde zenginleştirildi.
- **Adımlar:**
  1. `paket_sec.py`: yukarıdaki tabloyu uygular; program başına `rows` dosyası yazar (`etiket_paketi.py`'nin okuduğu anahtarlar: `addr`, `gt`, `pred`, `status`; `status` hep `wrong`; T3 / T4'te `pred` üretilen adaydır) ve `ogeler.json` (adres → tabaka, kaynak küme, ajan etiketi, ölçü puanları). `ogeler.json` anahtar dizinine yazılır.
  2. Paketler: `python scripts/measurement/etiket_paketi.py uret --satirlar <rows_tmux.json> --kaynak $R/workspaces/2026-10-15_oturum_scratchpad/src/tmux-dl/tmux-3.8 --ikili tmux --orneklem 0 --tohum 2026111901 --azami-satir 120 --cikti $V/insan_i1/tmux` ve aynısı htop için (`…/src/htop-dl/htop-3.5.3`, `--ikili htop`, tohum 2026111902). Kör kip (`--gt-goster` yok).
  3. `anahtar.json` dosyalarını anahtar dizinine taşı; değerlendirici dizinlerinde yalnız `etiket_rehberi.md`, `amac_paketi.jsonl` (aşama 2'de `aday_paketi.jsonl`) kalsın.
  4. `python scripts/measurement/etiket_paketi.py sizinti-denetimi --paket <paket>`: 0 hata. Gövdesi bulunamayan / belirsiz öğeler künyeden okunur ve `P-O3.md`'ye yazılır (yerine yenisi konmaz).
  5. `paket_tablo.py`: `amac_paketi.jsonl` ve `aday_paketi.jsonl` → değerlendiricinin dolduracağı CSV (sütunlar aşama 1: `id, dosya, govde, amac`; aşama 2: `id, amac, aday, etiket, gerekce`) ve doldurulmuş CSV → `amac.jsonl` / `etiket.jsonl` (`etiket_puan.py`'nin beklediği alanlar: `id`, `amac`, `etiket`, `gerekce`).
  6. Pilot: her değerlendirici ilk 50 öğeyi (tmux paketinin ilk 50 kimliği) etiketler; öğe başına süre kaydedilir; pilot etiketleri ana sayıma girer (ön kayıtta yazılı).
  7. Aşama 1 teslimleri sha256 ile dondurulur (`donma.log`; G4'teki düzen), aşama 2 ancak ondan sonra verilir.
- **Değerlendiriciye verilecek yönerge** (protokol v2 §8'in insan için uyarlanmış hâli; `P-O3.md`'ye aynen konur):

  ```text
  AŞAMA 1. Size C fonksiyonlarının kaynak kodu verilecek. Her fonksiyonun ana işini bir cümleyle yazın.
  - Önce etiket_rehberi.md'nin "Değerlendirme sırası" bölümünü okuyun.
  - Gövdede FONKSIYON, değerlendirdiğiniz fonksiyonun kendi adının yerine geçer. Gizlenen adı tahmin
    etmeye çalışmayın; kodu tanıdığınızı düşünseniz bile bildiğiniz adı yazmayın.
  - Programın kaynak koduna, internete ya da başka bir araca bakmayın. Yalnız size verilen dosyayı kullanın.
  - "dosya" sütunu fonksiyonun kaynak dosyasıdır; modül bağlamı olarak kullanabilirsiniz.
  - Her satır için: ne yapıyor, hangi nesne üzerinde. Ad önermeyin.
  - Gövde "/* ... */" ile bitiyorsa kırpılmıştır; gördüğünüz kadarına göre yazın.
  - Öbür değerlendiriciyle konuşmayın. Süreyi (başlangıç ve bitiş saati) not edin.

  AŞAMA 2 (aşama 1 teslim edildikten sonra). Amaç cümleleriniz artık değişmez. Her satırda bir aday ad
  var. Adayı kendi amaç cümlenizle karşılaştırıp rehberdeki üç etiketten birini yazın:
  dogru_tarif, yalniz_alan, yanlis. ("tam" yazmayın; özgün adı bilmiyorsunuz.)
  - Kısa bir gerekçe yazın ve dayandığınız kuralı belirtin (ör. "kural 4: getter/setter karışması").
  - Adayların bir kısmı denetim amaçlıdır; hangileri olduğunu tahmin etmeye çalışmayın.
  ```
- **Kabul ölçütü:** 302 ana öğenin tabaka sayıları tabloyla aynı (gövdesi bulunamayanlar ayrıca listelenir); sızıntı denetimi 0; anahtar değerlendirici dizinlerinde yok; `paket_tablo.py` gidiş-dönüşte alanları bayt bayt koruyor (sınama); aynı tohumla ikinci üretim aynı paketleri veriyor.
- **Ön kayıt metni (`P-O3_on_kayit.md`; değerlendiricilere paket verilmeden önce commit):** P-Ö4'ün "Ön kayıt metni" ile birlikte tek belge (aşağıda).
- **Sınama ve mutasyon:** `tests/test_arge_olcu_paket.py`: tabaka önceliği (aynı adres iki tabakada çıkmaz), T3 adayının fonksiyonun kendi adı olmaması, T4 adayının `harf_tam` olması ve tam eşit olmaması, tohumla yinelenebilirlik. Mutasyon: (m1) öncelik sırası ters; (m2) T3'te `g != f` kalkar; (m3) T4'te aday GT'nin aynısı. Beklenti 3 / 3 öldü (`mutation_probe.py --module scripts/arge/olcu/paket_sec.py …`).
- **Ürüne / ortak ölçüme girişi:** girmez (araştırma verisi). Etiketler depoya yalnız gövdesiz biçimde girer (G4 düzeni; depo herkese açık).

### P-Ö4 — İnsan etiketinin puanlanması

- **Amaç:** insan–insan ve insan–vekil uyumunu, biçim ve ikiz tabakalarının hükmünü ve ölçü ↔ insan uyumunu, dondurulmuş betiklerle tek okumada ölçmek.
- **Önkoşul:** P-Ö3 paketleri; iki değerlendiricinin (D1, D2) aşama 1 ve 2 teslimleri.
- **Dosyalar (yazar):** yeni `$H/insan_puan.py`; `docs/arge/2026-11-19_mythos/olcu/insan/` (gövdesiz etiket ve amaç dosyaları, `donma.log`, sonuç JSON'u); `docs/arge/2026-11-19_mythos/olcu/P-O4.md`.
- **Dokunmaz:** `$H/olcu.py`, `sozluk.json`, `roc.py`, `kimlik.py`, `idf.py` (dondurulmuş; yalnız içe aktarılır), `scripts/measurement/*`.
- **Adımlar:**
  1. Değerlendirici başına oranlar ve yem kabulü: `python -I -B scripts/measurement/etiket_puan.py puan --anahtar <anahtar_tmux.json> --anahtar <anahtar_htop.json> --etiket <D1>/etiket_tmux.jsonl --etiket <D1>/etiket_htop.jsonl --amac <D1>/amac_tmux.jsonl --amac <D1>/amac_htop.jsonl --cikti <d1.json>` (D2 için aynısı). `--amac` denetimi amaç cümlelerinin değişmediğini doğrular.
  2. `insan_puan.py uyum`: D1 ↔ D2 Cohen kappa (dört etiket; `yakin` / değil; `yanlis` / değil) ve ham uyum; kappa için %95 aralık (öğe önyüklemesi, 2 000 tekrar, tohum 20261119). `cohen_kappa` formülü `docs/arge/2026-10-19_g4_etiketleme/analiz.py` ile aynı.
  3. `insan_puan.py vekil`: T2'de uzlaşılmış insan hükmü (D1 = D2 olan öğeler; uyuşmayanlar sayılır, dışarıda) ↔ ajan etiketi kappa (`ogeler.json`'daki ajan etiketi).
  4. `insan_puan.py tabaka`: T1'de uzlaşılmış `yakin` ve `yanlis` oranı (bölge başına: `kimlik_adayi`, `ortusen_diger`, `ayrik`); T3'te ikiz adayının `yanlis` oranı; T4'te biçim adayının `dogru_tarif` oranı. Wilson aralıklarıyla.
  5. `insan_puan.py olcu`: T1 + T2'nin uzlaşılmış hükümleriyle `roc.auc`, `roc.esik_sec`, `roc.kabul_oku`, `roc.fark_onyukleme` (içe aktarılır). Bölme: AYAR = tmux öğeleri, SINAMA = htop öğeleri. Ölçüler `olcu.SUREKLI_AD_OLCULERI` + `kimlik`, `Ridf` (hesap `kimlik.IkiliGt`, `idf.ridf`).
  6. Yem kabulü değerlendirici başına > %10 ise o değerlendiricinin etiketleri "dikkat denetiminden geçmedi" notuyla ayrıca raporlanır (çıkarılmaz).
  7. `P-O4.md`: ön kayıtlı her ölçüt için sayı, aralık, hüküm.
- **Kabul ölçütleri ve ön kayıt metni (`P-O3_on_kayit.md`'nin ikinci yarısı; paket verilmeden önce commit):**
  > Tek okuma. Birim: öğe. Uyuşmayan öğeler ölçüt 3–5'te dışarıda, sayıları yazılır.
  > 1. **İnsan–insan (T1 + T2 + T3 + T4, yemsiz):** kappa `yakin` / değil ≥ 0,60 ve `yanlis` / değil ≥ 0,60 → **tuttu**. Biri < 0,60 → **tutmadı**: rubrik düzeltilmeden hiçbir "yakın" sayısı yayımlanmaz. < 0,40 → hat durma ölçütü (rubrik düzeltmesi + ikinci tur; yine < 0,40 ise kapanır).
  > 2. **İnsan–vekil (T2, 182 öğe):** kappa `yakin` / değil ≥ 0,80 → ajan ön etiketi ucuz ön eleme olarak kabul; değilse BULGULAR §2 yalnız "model hakemle uyum" olarak kalır.
  > 3. **Ölçü ↔ insan:** hipotez (mekanik eşik yok) **tuttu** sayılır: AYAR'da (tmux) hiçbir ölçüde "puan ≥ t" kabulünün `yakin` kesinliği ≥ 0,90 olan eşik yok. **Tutmadı:** bir ölçüde eşik var ve SINAMA'da (htop) kabul ≥ 20, kesinlik ≥ 0,85, Wilson alt ≥ 0,70. Eşik var ama SINAMA'da kabul < 20 → **ölçülemedi** (P-Ö9'a kalır).
  > 4. **Biçim (T4, 30 öğe):** uzlaşılmış `dogru_tarif` oranı ≥ %95 (≥ 29 / 30 uzlaşılmış öğede; Wilson alt ≥ %83) → `tam + biçim` resmî hüküm satırı olarak önerilir; değilse biçim düzeyi yalnız duyarlılık satırı kalır.
  > 5. **İkiz (T3, 60 öğe):** uzlaşılmış `yanlis` oranı raporlanır. Ön kayıtlı okuma: ≥ %50 ise "kardeş adı yanıltıcıdır" (aykırı öncül 2b'nin insan kolu tuttu); ≤ %20 ise tutmadı; arası "karışık".
  > 6. **Taban koşusu (T1, 30 mac/tmux adı):** uzlaşılmış `yakin` sayısı bölge başına raporlanır; ürünün mac/tmux yanlış oranının üçüncü hükmü (`tam + biçim + insan yakın`) hesaplanır.
  > Beklentiler (tahmin; sayı değil): 1 tutar (kappa 0,6–0,8); 2 tutmaz; 3 tutar; 4 tutar; 5 "≥ %50"; 6 ara bantta azınlık `yakin`.
- **Sınama ve mutasyon:** `insan_puan.py` için sentetik iki etiket dosyasıyla (bilinen kappa: tam uyum 1,0; bağımsız 0'a yakın; elle hesaplanmış 2 × 2 örneği) birim sınaması; mutantlar: (m1) kappa'da beklenen uyum 0 alınır; (m2) uyuşmayan öğeler dışlanmaz; (m3) yem ana sayıya girer. Beklenti 3 / 3 öldü.
- **Ürüne / ortak ölçüme girişi:** ölçüt 4 tutarsa P-Ö1'in satırı "duyarlılık"tan "ikinci hüküm"e yükseltilmesi Berke'ye önerilir (ayrı karar). Ölçüt 2 tutarsa `etiket_protokolu_v2.md`'ye "ajan ön etiketi kabul" notu önerilir. Kod değişikliği bu pakette yok.

### P-Ö5 — Çatışma ve kalibrasyon ölçülerinin ortak ölçüme taşınması (B5, B2)

- **Durum:** iki ölçü bu turda geliştirme setinde alındı (BULGULAR §8.1, §8.2). Bu paket onları her koşuda tekrarlanabilir kılar; set dışı okumaları P-Ö7 ve P-Ö8 yapar.
- **Amaç:** "kazanan ad ↔ yedek adaylar" dökümünü ve güven ↔ gerçekleşen doğruluk tablosunu ortak ölçüme almak.
- **Dosyalar (yazar):** yeni `scripts/measurement/catisma_olc.py`, `scripts/measurement/kalibrasyon_olc.py`; yeni `tests/test_catisma_olc.py`, `tests/test_kalibrasyon_olc.py`; yeni `scripts/measurement/mutation_specs_po5.json`; `docs/arge/2026-11-19_mythos/olcu/P-O5.md`.
- **Dokunmaz:** `karadul/`, `urun_olc.py`, `ks1_olc.py`, `$H/*` (başvuru uygulaması: `$H/catisma.py`, `$H/kalibrasyon.py`).
- **Adımlar:**
  1. `catisma_olc.py`: `$H/catisma.py`'nin mantığı; girdi koşu kökü (`urun_olc` ile aynı seçenekler). Kayıt alanları koddan doğrulanmış hâliyle: `naming_provenance.json` → `global[FUN_<adres>]` → `runners_up[]` (`strategy`, `new_name`, `confidence`), `n_candidates`; jenerik ad süzgeci `function_f1.is_generic_name(ad, [adres])`; doğruluk `ks1_olc.capa_degerlendir` ya da `ad_bicimi.harf_tam` (P-Ö1 yoksa `$H/olcu.harf_tam`).
  2. Çıktı: sayım tablosu, kazanan kanal × yedek strateji çatışma tablosu, yedek strateji başına kesinlik, "kazananı yanlış ve yedeği doğru" listesi (ad geçer → JSON depo dışına).
  3. Kural oynatması (BULGULAR §5 kural 5): kanal p'leri `--guven-tablosu` ile dışarıdan verilir (varsayılan: ölçülmemiş kanal 0); değişen karar sayısı, kazanılan / kaybedilen doğru.
  4. `kalibrasyon_olc.py`: `$H/kalibrasyon.py`'nin mantığı; girdi OLGU tablosu ya da koşu kökü; kanal ve güven değeri başına gerçekleşen oran, Brier, ECE (0,1 kutular); örnek ve tekil.
  5. a62f15e'de koş, kabul sayılarıyla karşılaştır; sınamalar, mutasyon, `P-O5.md`.
- **Kabul ölçütü (a62f15e; tam eşitlik; kaynak `$V/catisma.json`, `$V/kalibrasyon.json`):** uygulanan ad 1 800; yedek 2 612 (jenerik 496, kimlik iddialı 2 116); çatışmalı ad 1 300; kazananı yanlış 79, bunlardan çatışmalı 41, yedeği doğru 0; yedek kesinliği `api_call` 1 / 1 298, `callee_based` 1 / 709, `string_context` 99 / 109; kural (ölçülmemiş p = 0) değişen karar 0. Kalibrasyon: `string_context/oz_ad` n 197, ortalama güven 0,831, ECE 0,3586 (tam) / 0,1556 (tam + biçim); güven 0,80 → 22 / 76 tam, 39 / 76 tam + biçim; güven 0,85 → 71 / 121 ve 94 / 121; toplam ECE 0,1253 (tam, örnek), 0,0629 (tam + biçim, tekil).
- **Ön kayıt metni:** yeniden üretim paketidir; "Beklenen: yukarıdaki sayılar tam eşit. Fark taşıma hatasıdır." Set dışı okumaların ön kaydı P-Ö7 / P-Ö8'in metnindedir (aşağıda "çatışma ve kalibrasyon satırı").
- **Sınama ve mutasyon:** 3 fonksiyonluk sentetik köken kaydı (çatışma yok; jenerik yedek; farklı adlı kimlik iddialı yedek) ve 4 adlık sentetik güven tablosu (elle hesaplanmış Brier ve ECE). Mutantlar: (m1) jenerik süzgeç kalkar; (m2) "kazananla aynı" karşılaştırması harf dizisi yerine ham dizgi; (m3) ECE'de kutu ağırlığı düşer; (m4) kural yüksek p yerine düşük p'yi seçer. Beklenti 4 / 4 öldü.
- **Ürüne / ortak ölçüme girişi:** iki betik ortak ölçüme girer. Ürüne giren bir şey yok. İki ürün önerisi sahibine devredilir (§6): `oz_ad` güveninin ölçülmüş değerle değiştirilmesi; `api_call` / `callee_based` adaylarının kanıt satırı olarak yazılması.
- **Bu veriyle ölçülemeyen (açık):** ad verilmeyen fonksiyonların aday listesi köken kaydında tutulmuyor (yalnız `eliminated_keys` sayaçları). "Elenen adaylar arasında doğru ad var mıydı" sorusu için ürünün elenen adayları da kayda yazması gerekir; bu bir ürün değişikliğidir (sahibi onarım hattı; öneri: `below_min_confidence_candidates` ve susturulan adaylar için fonksiyon başına en çok 3 kayıt). Yazılmadan ölçülemez.

### P-Ö6 — Tabaka C: yerel derleme matrisi (G1; açık ölçüm, indirme yok)

- **Amaç:** aynı kaynağı (tmux 3.8, htop 3.5.3) Apple clang ile altı iyileştirme düzeyinde derleyip kanal kesinliği ve kapsamının iyileştirme düzeyine duyarlılığını ölçmek.
- **Dosyalar (yazar):** yeni `$H/derleme_c.sh`, `$H/tabaka_olc.py`; veri `~/karadul_olcum/n2_tabaka/c/` (Spotlight dışı); `docs/arge/2026-11-19_mythos/olcu/P-O6_on_kayit.md`, `P-O6.md`.
- **Dokunmaz:** `$R/workspaces/olcum_mac/`, `$R/workspaces/2026-10-15_oturum_scratchpad/src/` (kaynak ağaçları kopyalanır, yerinde derlenmez), `scripts/measurement/*`.
- **Adımlar:**
  1. Kaynak ağaçlarını `~/karadul_olcum/n2_tabaka/c/src/` altına kopyala. Derleme bağımlılıkları (libevent, ncurses, utf8proc) Homebrew'da kuruluysa kullanılır; eksikse **kurma**, eksik listesini yaz ve dur (indirme onayı gerekir).
  2. `derleme_c.sh`: `CFLAGS` ∈ {`-O0`, `-O1`, `-O2`, `-Os`, `-O3`, `-O2 -flto`} × 2 program = 12 derleme; `-g` yok; sembollü ikili saklanır.
  3. Her ikili için soyulmuş kopya: `/usr/bin/strip` (PATH'teki conda `strip` değil); `xcrun dyld_info -exports` ile dışa aktarım tablosunun boş olduğu doğrulanır (hafıza: Mac strip tuzağı).
  4. GT: `scripts/measurement/macho_measure.py`'nin var olan GT üretimi (sembollü ikilinin `nm` çıktısı); `workspaces/olcum_mac` düzeninde ama `n2_tabaka/c/gt/` altında.
  5. Ürün koşusu: `scripts/measurement/urun_kos.py` düzeninde, sıralı (paralel 1), `KARADUL_CACHE_DIR=~/karadul_olcum/n2_tabaka/c/cache`, `PYTHONHASHSEED=0`; ürün ağacı o günkü main (commit künyeye yazılır).
  6. `tabaka_olc.py`: düzey başına `urun_olc` (kök yapısı `mac/<program>` olacak biçimde düzenlenir), P-Ö2'nin `ad_bolgeleri.py`'si (yoksa `$H/taban_dok.py` + `taban_puanla.py`); tablo: düzey × (nüfus, ad, tam, biçim, ara bant, ayrık, kanal başına kesinlik).
  7. `P-O6.md`.
- **Kabul ölçütü ve ön kayıt metni:**
  > Açık ölçüm; beklenen sayı yok. Bütünlük: 12 derlemenin 12'si koştu, soyulmuş kopyalarda dışa aktarım 0, Ghidra sürümü sabit. Okuma kuralları (önceden): (a) `ks1:func_kalibi` kesinliği her düzeyde ≥ 0,85 (ad ≥ 10 olan düzeylerde; Wilson aralığıyla) → "iyileştirme düzeyinden bağımsız"; bir düzeyde < 0,85 → o düzey için güven tablosu satırı ayrı yazılmalı. (b) `-O2` düzeyindeki mac/tmux sonucu taban koşusunun mac/tmux'uyla (236 ad, 205 doğru; Homebrew derlemesi) karşılaştırılır; fark açıklanır, ölçüt değildir. (c) Yerleşim ve başka hatların ölçüleri bu veride ayrıca okunabilir; bu paketin ölçütü değildir.
- **Sınama ve mutasyon:** `tabaka_olc.py` yalnız toplama yapar; birim sınaması: iki sentetik düzey JSON'undan tablo. Mutasyon gerekmez (ölçü mantığı yok); gerekçe `P-O6.md`'ye yazılır.
- **Ürüne / ortak ölçüme girişi:** veri kalıcıdır (`n2_tabaka/c`); sonraki birleşik ölçümlerde "tabaka C" satırı olarak koşulabilir. Kod girişi yok.

### P-Ö7 — Tabaka A / B: x86-64 ve GCC 12 / 13 (G1; açık ölçüm, indirme onayı gerekir)

- **Amaç:** aynı sekiz paketin başka mimari (x86-64) ve başka derleyici sürümü (GCC 12, GCC 13) derlemelerinde kanal kesinliğini ve kapsamını ölçmek.
- **Önkoşul:** Berke'nin §4'teki liste için onayı; P-Ö6 bitmiş (Ghidra sırası).
- **Dosyalar (yazar):** yeni `$H/tabaka_indir.py` (yalnız dizin okur ve doğrular; indirmeyi onaydan sonra yapar); veri `~/karadul_olcum/n2_tabaka/{a,b}/`; `docs/arge/2026-11-19_mythos/olcu/P-O7_on_kayit.md`, `P-O7.md`.
- **Dokunmaz:** `~/karadul_olcum/n1_debian13/`, `~/karadul_olcum/downloads/` (yalnız yeni alt dizin açılır: `downloads/n2_tabaka/`), `targets/`.
- **Adımlar:**
  1. Dağıtımın `Packages` dizinlerinden (Debian 13 amd64; Debian 12 arm64; Ubuntu 24.04 arm64 ve bunların hata ayıklama arşivleri) sekiz paket + `-dbgsym` için ad, sürüm, boyut, sha256 oku; toplam boyutu Berke'ye sun (indirme henüz yok).
  2. Sürüm eşleşmesi: tabaka A'da kaynak sürümü geliştirme setindeki arm64 sürümüyle aynı olmalı (künye `~/karadul_olcum/n1_debian13/kosu_kunyesi.json`); değilse snapshot.debian.org'dan eşleşen sürüm; eşleşme yoksa paket tabakadan çıkar ve yazılır.
  3. Onaydan sonra indir; sha256 ve BuildID (ikili ↔ dbgsym) eşleşmesini doğrula; kilit belgelerindeki hiçbir paket adının listede olmadığını betikle denetle.
  4. Ön kaydı commit'le (aşağıda), sonra ürün koşusu (sıralı, koşuya özel önbellek).
  5. `urun_olc` (tabaka başına ayrı kol), `ad_bolgeleri` / tekil sayım, kanal tablosu; AArch64 tabanıyla yan yana.
  6. Güven tablosu okuması: kanal başına tabaka kesinliğinin tekil Wilson alt sınırı ↔ `MEASURED_PRE_NAME_PRECISION` değeri; `kalibrasyon_olc.py` (P-Ö5; yoksa `$H/kalibrasyon.py`) ile tabaka başına Brier / ECE; `catisma_olc.py` ile çatışma tablosu.
  7. `P-O7.md`.
- **Kabul ölçütü ve ön kayıt metni:**
  > Açık ölçüm; beklenen sayı yok, eşikler var. Tabaka başına, örnek ve tekil düzeyde: (a) ön ad kanalları (`on_ad:gnulib`, `on_ad:elf_onyuk`, `on_ad:main_giris`): kesinlik ≥ 0,95 (ad ≥ 10 ise) → "genelleşti"; < 0,90 → "genelleşmedi" (kanal o tabakada "kesin" sayılamaz; güven tablosu tabaka başına yazılır); arası "belirsiz". (b) `on_ad:gnulib` kapsamı: tabakadaki coreutils ad sayısı AArch64'teki 733'ün ≥ %50'si → kapsam genelleşti; < %25 → genelleşmedi (kuralların GCC 14 / AArch64'e özgü olduğu kabul edilir). (c) `ks1:*` kanalları: ad sayısı AArch64'tekinin ±%10'u içinde ve kesinlik ≥ 0,90. (d) Tam + biçim makro yanlış oranı tabaka başına raporlanır; "yanlış ≤ %10" kararı tabaka başına ayrı yazılır. (e) Çatışma ve kalibrasyon satırı: ön ad kanallarının yazılı güveni (geliştirme setinin Wilson alt sınırı) tabakada gerçekleşen kesinliğin en çok 0,05 üstündeyse "güven set dışında tutuyor"; 0,10'dan çok üstündeyse "tutmuyor" (kanal başına, ad ≥ 10). "Kazananı yanlış, yedeği doğru" sayısı raporlanır; ≥ 5 ise birleştirici kuralı (BULGULAR §5 kural 5) o veride oynatılır.
- **Sınama ve mutasyon:** `tabaka_indir.py`: kilitli ad süzgeci (kilit belgelerinden okunan ad listesiyle kesişim boş olmalı) ve sha256 doğrulaması için birim sınaması; mutant: süzgeç boş küme döner → sınama kırmızı (1 / 1).
- **Ürüne / ortak ölçüme girişi:** tabaka koşuları kalıcı veri olur; `scripts/measurement/urun_kos.py`'ye "tabaka" seçeneği eklenmesi bu paketin sonuç önerisidir (ayrı paket, sahibi ölçüm altyapısı).

### P-Ö8 — Tabaka D: keşif dışı set (G1; açık ölçüm, kura ve indirme onayı gerekir)

- **Amaç:** geliştirme setinde olmayan 10 programda, kuralları hiç görmemiş kodda aynı ölçüleri almak.
- **Dosyalar (yazar):** yeni `scripts/arge/olcu/kesif_disi_kura.py`; `docs/arge/2026-11-19_mythos/olcu/kesif_disi_seti.md` (liste, tohum, künye; sembol adı yazılmaz), `P-O8_on_kayit.md`, `P-O8.md`; veri `~/karadul_olcum/n2_tabaka/d/`.
- **Dokunmaz:** `scripts/measurement/test_seti_kura.py`, `dogrulama_seti_kura.py`, kilit belgeleri, `targets/`.
- **Adımlar:**
  1. Havuz kuralı: Debian 13 `main`, arm64, C programı (dbgsym'i var; C++ / Go / Rust değil), ölçülecek tek ikili, vekil boyut 100 KiB–5 MiB. Dışlananlar: geliştirme seti programları; `test_seti_kilidi.md` ve `dogrulama_seti_kilidi.md`'de adı geçen **her** program (ana, stres, korumalı ve korumasız yedekler).
  2. Çerçeve türü tabakaları (2'şer program): düz C komut satırı; ncurses arayüzlü; GLib / GTK; libevent ya da ağ sunucusu; gnulib'li. Tür, paketin `Depends` alanından ve (gnulib için) kaynak ağacındaki `gnulib` işaretinden mekanik okunur.
  3. Kura: tohum = SHA-256(`karadul-kesif-disi-kura-2026-11`) ilk 16 onaltılık basamağı; betik ve ön kayıt sonuç görülmeden commit'lenir (doğrulama setinin düzeni).
  4. Liste ve boyutlar Berke'ye sunulur; onaydan sonra indirme, sha256 / BuildID sabitleme.
  5. Ürün koşusu (sıralı); ölçüm P-Ö7 adım 5–6 ile aynı.
  6. Bu set "keşif dışı"dır: kural geliştirmede GT'sine bakılmaz; ama kapı seti de değildir (doğrulama setinin yerine geçmez). Her bakış `kesif_disi_seti.md`'ye kaydedilir.
- **Kabul ölçütü ve ön kayıt metni:**
  > Açık ölçüm. (a) "kesin" etiketli adların kesinliği program düzeyi makroda ≥ 0,95 → etiket genelleşti; < 0,90 → genelleşmedi. (b) Tam + biçim makro yanlış oranı ≤ %25 → geliştirme setinin yanlış oranı (tam + biçim %19,1) bu sette "aynı mertebede"; > %40 → geliştirme sayıları genellenmez. (c) Doğru ad kapsamı program başına raporlanır; ön kayıtlı okuma: 10 programın en az 7'sinde doğru ad kapsamı geliştirme setinin coreutils dışı makrosunun altındaysa "kapsam set içine özgü" yazılır. (d) Kanal başına tekil kesinlik, P-Ö7 (a) eşikleriyle.
- **Sınama ve mutasyon:** kura betiği için: aynı tohum aynı sonucu verir; dışlama listesiyle kesişim boş; tabaka kotası. Mutant: dışlama uygulanmaz → sınama kırmızı (1 / 1).
- **Ürüne / ortak ölçüme girişi:** set kalıcıdır; A3 hattının (üst veri) ve A5'in (GTK sinyal adları) bağımsız sınama nüfusu olarak da kullanılabilir (kendi ön kayıtlarıyla).

### P-Ö9 — İnsan etiket paketi İ-2 (Debian programları; kaynak indirme onayı gerekir)

- **Amaç:** taban koşusunun kalan tekil yanlış adlarını (mac/tmux dışı) ve P15c çiftlerini iki insan değerlendiriciyle etiketleyip ölçü ↔ insan uyumunu program bazlı ayar / sınama bölmesiyle ölçmek.
- **Önkoşul:** P-Ö4 ölçüt 1 tuttu (rubrik kullanılabilir); zstd, sqlite3, openssl, redis, coreutils, tmux (Debian sürümü), htop (Debian sürümü) kaynak paketleri için onay (§4).
- **Dosyalar:** `$H/paket_sec.py`'ye `--paket i2` seçeneği (P-Ö3 bittikten sonra; aynı dosya, sıralı); çıktı `$V/insan_i2/`; `docs/arge/2026-11-19_mythos/olcu/P-O9_on_kayit.md`, `P-O9.md`.
- **Adımlar:** (1) T1′: `$V/taban_puan.json` `yanlislar` içinde `bolge ∈ {kimlik_adayi, ortusen_diger, ayrik}` ve mac/tmux dışı adların tekil listesi (örnek düzeyinde 49: coreutils 9, debian/htop 1, openssl 2, redis-tools 3, sqlite3 7, debian/tmux 18, zstd 9); (2) T2′: P15c'nin 220 tekil çiftinden, kaynak gövdesi bulunanlar (pzstd hariç); (3) program başına `etiket_paketi.py uret`; (4) sızıntı denetimi; (5) P-Ö3'ün yönergesi ve dondurma düzeni; (6) puanlama P-Ö4 adımlarıyla; ölçü ↔ insan bölmesi: AYAR = tmux (İ-1 + İ-2), SINAMA = öbür programlar.
- **Kabul ölçütü ve ön kayıt metni:**
  > Açık ölçüm. P-Ö4 ölçüt 3'ün tam okuması: AYAR'da eşik var mı; varsa SINAMA'da kabul ≥ 20, kesinlik ≥ 0,85, Wilson alt ≥ 0,70. Taban koşusunun üçüncü hükmü: `tam + biçim + insan yakın` ile havuz, tekil ve makro yanlış oranı. Beklenen sayı yazılmıyor.
- **Sınama ve mutasyon:** P-Ö3'ün sınamalarına `--paket i2` durumu eklenir.
- **Ürüne / ortak ölçüme girişi:** ölçüt 3 "tutmadı" (yani bir ölçü eşik verdi) çıkarsa o ölçü ve eşiği P-Ö2'nin `ad_bolgeleri.py`'sine "yakın" bölgesi olarak eklenir (ayrı ön kayıt). Hipotez tutarsa sayım düzeni (§1) kalıcılaşır ve soru listesi B3 kapanır.

## 4. Set dışı tasarım ve indirme listesi (G1)

**İlke:** her tabaka tek etkeni değiştirir. Birim tekil kaynak fonksiyonudur; çok ikilili paket tek birimdir (nüfusun %53,3'ü coreutils'teki gnulib kopyası; OLGU bütçesi).

| Tabaka | Değişen etken | Sabit kalan | Hücreler | GT | Paket |
|---|---|---|---|---|---|
| A | mimari: x86-64 | kaynak, Debian 13, GCC 14, −O2 | geliştirme setinin 8 paketi | `-dbgsym` (amd64) | P-Ö7 |
| B | derleyici sürümü: GCC 12 (Debian 12), GCC 13 (Ubuntu 24.04) | program, AArch64 | aynı 8 paket × 2 dağıtım | dağıtımın dbgsym'i | P-Ö7 (Ubuntu coreutils'in 5 ikilisi diskte: `~/karadul_olcum/corpus`, LTO'lu) |
| C | derleyici ve iyileştirme: Apple clang 21; −O0 / −O1 / −O2 / −Os / −O3 / −O2 + LTO | kaynak (tmux 3.8, htop 3.5.3), arm64 Mach-O | 12 derleme | kendi sembolleri | P-Ö6 (indirme yok) |
| D | program (keşif dışı) | Debian 13, AArch64, GCC 14 | 5 çerçeve türü × 2 = 10 program | `-dbgsym` | P-Ö8 (kura) |
| E | dil / çerçeve üst verisi (ObjC, Swift, Go, Rust) | — | A3 hattının işi | — | bu hatta değil (`rustc`, `swiftc` kurulu; `go` yok) |

Linux'ta GCC / clang × mimari × iyileştirme matrisi (Docker ile) bu plana **alınmadı**: taban imgesi ve derleme bağımlılıkları indirme ister; tabaka A / B / C sonuçları bir etken gösterirse sonraki turda paketlenir.

**İndirme listesi (Berke onayı gerekir; bu turda hiçbir şey indirilmedi):**

| Ad | Kaynak | Boyut | Paket |
|---|---|---|---|
| `tmux_3.5a-3_amd64.deb` | deb.debian.org (trixie) | 490 296 bayt | P-Ö7 |
| `htop_3.4.1-5_amd64.deb` | aynı | 171 412 bayt | P-Ö7 |
| `zstd_1.5.7+dfsg-1_amd64.deb` | aynı | 756 244 bayt | P-Ö7 |
| `sqlite3_3.46.1-7+deb13u2_amd64.deb` | aynı | 384 144 bayt | P-Ö7 |
| `openssl_3.5.7-1~deb13u3_amd64.deb` | aynı | 1 508 068 bayt | P-Ö7 |
| `redis-tools_8.0.2-3+deb13u3_amd64.deb` | aynı | 1 247 524 bayt | P-Ö7 |
| `coreutils_9.7-3_amd64.deb` | aynı | 3 023 556 bayt | P-Ö7 |
| `tree_2.2.1-1_amd64.deb` | aynı | 59 392 bayt | P-Ö7 |
| bu 8 paketin `-dbgsym` (amd64) paketleri | deb.debian.org/debian-debug | okunmadı (P-Ö7 adım 1) | P-Ö7 |
| aynı 8 paket + dbgsym: Debian 12 arm64; Ubuntu 24.04 arm64 | deb.debian.org (bookworm); ports.ubuntu.com, ddebs.ubuntu.com | okunmadı (P-Ö7 adım 1) | P-Ö7 |
| keşif dışı 10 paket + dbgsym | deb.debian.org | kuradan sonra (P-Ö8 adım 4) | P-Ö8 |
| zstd, sqlite3, openssl, redis, coreutils, tmux, htop kaynak paketleri (geliştirme setindeki sürümler) | deb.debian.org (`Sources`) | okunmadı (P-Ö9) | P-Ö9 |

- Tabaka A'nın 8 ikili paketi toplam 7 640 636 bayt (7,29 MiB). Boyutlar packages.debian.org indirme sayfalarından 2026-11-19'da okundu (değişebilir: güvenlik güncellemesi sürümü yeniler); toplam bu oturumda betikle alındı.
- "Okunmadı" satırları için tahmin yazılmadı; ilgili paketin ilk adımı boyutu okur ve Berke'ye toplamıyla sunar.
- Disk kuralı (CLAUDE.md §28): her şey `~/karadul_olcum/` altına (Spotlight dışı).

## 5. Açık ölçümler (bu turda ölçülemedi; sonuç tahmini yok)

| # | Açık ölçüm | Neden ölçülemedi | Paket |
|---|---|---|---|
| 1 | İnsan–insan ve insan–vekil uyumu (kappa) | insan etiketi yok | P-Ö3, P-Ö4 |
| 2 | Ölçü ↔ **insan** hükmü uyumu (bu turdaki bütün AUC'ler vekil hükümle) | aynı | P-Ö4, P-Ö9 |
| 3 | Taban koşusunun 79 (tekil 73) belirsiz adından kaçı "amaçça doğru" | aynı | P-Ö4 (mac/tmux 30), P-Ö9 (kalan) |
| 4 | Kardeş (ikiz) adının insan gözünde yanıltıcı olup olmadığı | aynı | P-Ö4 (T3) |
| 5 | Ad verilmeyen fonksiyonlarda elenen adaylar arasında doğru ad var mı (B5'in öbür yarısı); iki **ölçülmüş** kanalın çatıştığı durumda kuralın kesinliği (geliştirme setinde yalnız 8 durum) | köken kaydı elenen adayları fonksiyon başına tutmuyor; ölçülmüş kanal çatışması yok denecek kadar az | ürün değişikliği gerekir (P-Ö5 son madde); çatışma tablosu P-Ö7 / P-Ö8 verisinde yeniden okunur |
| 6 | Güven ↔ gerçekleşen kesinlik (kalibrasyon, B2) **set dışında** (set içi ölçüldü: BULGULAR §8.2) | set dışı veri yok | P-Ö7, P-Ö8 (`kalibrasyon_olc.py` ile) |
| 7 | Kanalların x86-64, GCC 12 / 13, clang ve iyileştirme düzeylerinde kesinliği ve kapsamı (G1) | Ghidra koşulmadı, indirme yok | P-Ö6, P-Ö7 |
| 8 | Görülmemiş programlarda yanlış oranı ve kapsam (G1) | set yok | P-Ö8 |
| 9 | Kanıt satırının (e) ve ad ailesinin (a) analiste yararı; "aile" tanımının insan gözünde geçerliliği | analist görevi çalışması ister; bu planda **paket yok** | ikinci tur: aynı fonksiyon kümesinde dört koşul (ad / aile / kanıt / boş), ölçü = doğru amaç cümlesine ulaşma süresi ve doğruluğu; tasarımı insan etiket düzeni (P-Ö4) çalıştıktan sonra yazılır |
| 10 | CodeWordNet'li literatür ölçüsüyle doğrudan kıyas (G2) | CodeWordNet indirilemedi | karar bekler: indirme listesine eklenmedi; gömme tabanlı olduğu için ölçü adayı değil, yalnız kıyas sütunu olurdu |
| 11 | Çıplak Ghidra ve başka araçlarla aynı nüfusta kıyas (G2) | bu turun kapsamı dışında kaldı | P-Ö2'nin `belirtec_olc.py`'si hazır olunca, aynı OLGU tablosunda `ghidra_adi` üstünden ayrı küçük paket |
| 12 | İnsan etiketleme süresi (G3) | hiç insan etiketlemedi | P-Ö3 adım 6 (pilot 50 öğe) |

## 6. Başka hatlara devredilen (bu hattın paketi değil)

- **`oz_ad` güveni (onarım hattı):** kanalın yazdığı güven (0,80 / 0,85) gerçekleşen kesinliğin çok üstünde (ECE 0,36). Öneri: `string_context/oz_ad` için güven, güven sınıfı başına ölçülmüş kesinliğin Wilson alt sınırı olsun: tam eşitlikle 0,80 sınıfı 22 / 76 → 0,200, 0,85 sınıfı 71 / 121 → 0,498 (değerler `ks1_olc.oran` ile yeniden hesaplanır; biçim hükmü kabul edilirse 0,403 ve 0,695). Ön ad kanallarındaki AD-07 düzeninin aynısı; ön kayıtlı küçük ürün paketi.
- **`api_call` / `callee_based` adayları (onarım hattı, K-2):** ad kanalı olarak ölçülmüş kesinlikleri 1 / 1 298 ve 1 / 709. Ad adayı olarak değil kanıt satırı olarak yazılmaları önerilir (bugün zaten ad olmuyorlar; yedek listesinde ad gibi duruyorlar).
- **`oz_ad` harf düzeni (ÖZ KOD / onarım hattı):** kanal dizgiden çıkardığı tanımlayıcıyı küçük harfe çeviriyor; a62f15e'de 104 yanlışının 40'ı yalnız bu (zstd 37). Özgün yazım korunursa bu 40 ad tam eşitlikte doğru olur. Ölçüt önerisi: tam eşitlikte `oz_ad` 93 → 133 doğru, yeni yanlış 0; zstd yanlış oranı %83,6 → %16,4. Ön kayıtlı küçük ürün paketi (P12d ile birlikte ele alınabilir).
- **KİMLİK:** nüfusun tekil düzeyde %87,5'inin F1 ≥ 0,5 ikizi var; eşleme başarısı yalnız tam / biçim ile sayılmalı.

## 6b. Karar kuralının ürüne giriş yolu (bu planda ürün paketi yok)

Kural (BULGULAR §5) taslaktır. Ürün paketine dönüşmesi için sırayla: (1) Berke L'yi seçer (§7 madde 2); (2) set dışı okuma (P-Ö7 / P-Ö8) kanal alt sınırlarını tabaka başına verir; (3) "ad ailesi" düzeyi ancak açık ölçüm 9 (e ve a) ölçülünce açılır — o zamana kadar kural iki düzeylidir: **ad** eğer kanalın Wilson alt sınırı > 1 − 1 / L, değilse **kanıt satırı**. Bu iki düzeyli kuralın geliştirme setindeki karşılığı (`$V/karar.json` alt sınırlarından; örnek düzeyi): L = 5'te ad 1 593, kanıt 207; L = 10'da ad 1 560 (gnulib, ELF önyükü, `main`, `func_kalibi`), kanıt 240; L = 20'de ad 1 301, kanıt 499. Ürün paketi (sahibi onarım hattı): `karadul/core/naming_labels.py`'de düzey eşiği `MEASURED_PRE_NAME_PRECISION`'dan türetilir; bayrak arkasında; kendi ön kaydı; kabul ölçütü yukarıdaki sayıların yeniden üretimi ve doğru ad kaybı 0 (kanıt satırına düşen kanalın adı köken kaydında kalır).

## 7. Berke'nin kararını bekleyenler

1. İki insan değerlendirici (C okuyabilen; P-Ö3 paketi 302 öğe, kişi başı süre pilotla ölçülecek).
2. Yanlış ad eksik adın kaç katı kötü sayılacak (karar kuralındaki L; bugünkü "yanlış ≤ %10" hedefi L = 10'a denk).
3. İndirme onayı (§4): önce tabaka A (7,29 MiB + dbgsym), sonra B, D ve kaynak paketleri.
4. P-Ö4 ölçüt 4 tutarsa: "yanlış ≤ %10" kararı tam eşitlikle mi, tam + biçimle mi verilecek.
