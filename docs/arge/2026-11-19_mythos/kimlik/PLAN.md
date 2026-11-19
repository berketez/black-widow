# KİMLİK hattı — plan (tur 2; uygulayan: Opus ekibi, doğrulayan: ana oturum)

- Bu belge kendi başına uygulanabilir olacak biçimde yazıldı: bu turun araştırma ajanı sonraki oturumda yok.
- Dayanak: `BULGULAR.md` (her sayı betik çıktısı), `DEFTER.md` (bölme, ön kayıtlar, "neden olmadı").
- Taban: ürün a62f15e; main fc3c5c6 sonrası. Paketlerin dokunduğu ürün dosyaları o günkü main'den okunur;
  satır numaraları kayabilir, fonksiyon adları bağlayıcıdır.
- Kısaltmalar: `K/` = `~/karadul_olcum/runs/arge-2026-11-19/kimlik/`; `A/` = `scripts/arge/kimlik/`;
  `R/` = depo kökü. Komutlar depo kökünden, `PYTHONDONTWRITEBYTECODE=1`.
- Ortak kurallar her pakette geçerli: motor LLM'siz; kilitli setlere dokunma; ön kayıt ölçümden önce commit'lenir;
  her sayı betik çıktısı; ürüne giren her yeni yol bayrak arkasında ve öntanımı kapalı; aynı anda en çok 1 Ghidra
  koşusu, koşuya özel `KARADUL_CACHE_DIR`, `PYTHONHASHSEED=0`; git'te durumu değiştiren komutu yalnız ana oturum koşar.
- Karar kuralı (KARARLAR.md A-2, L = 10): ölçülmüş kesinliğinin Wilson alt sınırı ≥ 0,909 olan kanal **ad** yazar;
  altındaki **kanıt satırı** yazar. Hattın kendi hedefi (≥ 0,95) ayrıca raporlanır.

## 0. Hat özeti (liste §5 biçimi)

- **Hipotez:** bilinen bir başvuru derlemesine karşı, öğrenmesiz çapalı yayılım (tekil dizgi çapası + çağrı grafiği
  ve tablo komşuluğu + belirsizlik kapısı) fonksiyon adını ≥ 0,95 kesinlikle verir, **başvuru aynı kaynak sürümünden
  derlenmişse**; derleyici ve iyileştirme düzeyi farkı bunu bozmaz. Sürüm farklıysa ad kesinliği düşer çünkü adlar
  değişmiştir; eşleme yine doğru fonksiyonu bulur.
- **Literatürün beklediği cevap:** derleyiciler arası eşleme öğrenilmiş gömme ister; BSim eşiğini ayarla.
  **Aykırı öncül:** ad vermek sıralama değil doğrulamadır; doğru başvuru + tekillik + çekimserlik yeter.
  **Tur 1'in hükmü (ön kayıtlı, taze veri):** aynı sürüm, GCC ↔ clang: 0,990 [0,987–0,993], kapsam %80,1 (v2 ile
  %87,7); aynı sürüm, `-O0` ↔ `-O2`: 0,970 (alt 0,964). Sürüm farklı: 0,935 [0,925–0,944] (hedef tutmadı; karar
  kuralının 0,909 eşiğini geçiyor). BSim en iyi adayı aynı çiftlerde 0,59–0,78 (tmux sürüm farklı 0,610; `-O0` ↔
  `-O2` 0,592; `-O3` ↔ `-O2` 0,784); CFG bankası derleyiciler arası 0 eşleşme.
- **Bu yüzden turun asıl sorusu değişti:** "eşleyici yeter mi?" değil, **"doğru başvuru nasıl bulunur / üretilir
  ve bunun genel geçerliği (başka programlar, mimari) nedir?"** (PK-6, PK-9, PK-10, PK-11).
- **Ölçüt ve doğrulayıcı:** `scripts/measurement/kimlik_olc.py` (PK-3 ile taşınır; bugün `A/yayilim_olc.py`,
  `A/hata_dok.py`, `A/tanik.py`), iki tarafı GT'li çiftlerde nüfus içi tam ad kesinliği (Wilson) ve kapsam; yanlış
  sınıfı dökümü. "Tuttu" eşiği paket başına aşağıda.
- **Ön kayıt taslağı:** paket başına aşağıda (commit'lenecek hâliyle).
- **İş paketleri:** PK-1 … PK-11 (§2–§3).
- **Gerekli veri ve araç:** §4 (V1–V5). Bu turda indirme yapılmadı; GCC derlemeleri diskteki kaynaktan yapıldı.
- **Durma ölçütü:** (a) PK-6'da başka programlarda / mimaride, sürümü eşlenmiş başvuruyla tam ad kesinliği Wilson
  alt sınırı < 0,909 çıkarsa "tmux'a özgü" hükmü verilir; kanal o koşulda kanıt satırına iner ve hat yalnız aynı
  derleme yoluna (PK-5) daralır. (b) PK-4 + PK-5 ürüne girip set dışı tabakalarda (ÖLÇÜ P-Ö7 / P-Ö8) ölçüldüğünde
  ve PK-9 başvuru seçimini ≥ %90 doğrulukla yaptığında hattın araştırma sorusu kapanır; kalan iş bakım.
- **Riskler ve bilinmeyenler:** §6.

## 1. Tur 1'den plana taşınan olgular (sayılar `BULGULAR.md`)

| # | Olgu | Planı nasıl belirliyor |
|---|---|---|
| O1 | Ürünün var olan başvuru yolu yanlış ad yazıyor: `BinaryDiffer` tmux 328 / 174 (0,653), `size_params` 2 / 116, `cfg_fingerprint` 0 / 42; `ReferenceDiffer` 366 / 769 (0,322), `cfg_similarity` 58 / 725; beş grubun havuzunda 958 / 604 ve 2 056 / 1 359; `_add_refdiff` her ada 0,95 güven yazıyor | **PK-1** (ilk iş; yayından önce) |
| O2 | Çapalı yayılım, **aynı sürüm** (ön kayıtlı, taze): GCC ↔ clang 3 908 / 38 = 0,990 [0,987–0,993], kapsam %80,1; v2 4 281 / 36, %87,7; `-O3` ↔ `-O2` 0,981; `-O0` ↔ `-O2` 0,970; htop 0,984. **Sürüm farklı:** tmux 2 276 / 158 (0,935; alt 0,925), %51,8; coreutils ↔ Homebrew 0,871 | PK-2, PK-3, PK-4; genelleme PK-6 |
| O3 | Sürüm farkının bedeli yeniden adlandırma: "tek taraflı" yanlış sürüm farklıyken 99–105, aynı sürümde 0–10; 52 tekil çiftin 47'si 3.8 kaynağıyla tutarlı | PK-9 (sürüm tanıma, başvuru seçici), PK-10 (başvuru üretimi), PK-4'te sürüm etiketi |
| O4 | Kalan hata satır içi + komşu: aynı sürümde 29 / 38 (GCC ↔ clang), 93 / 110 (`-O0` ↔ `-O2`). Kütle dengesi kapısı olumsuz. "Çağıranın çağrılanı" tanığı bu türün %52–65'ini işaretliyor; tanıklı alt kanalın kesinliği 0,82–0,88 (alt 0,77–0,86 < 0,909), tanıksızların 0,98–0,997; ama "ucuz kapı" eşiği (T2) tutmadı | PK-7 (tanıklı alt kanal → kanıt satırı; ürün kararı) |
| O5 | Tablo yuvası kanıtı (v2) bağımsız sınamada tuttu: kapsam +7–9 puan, kesinlik düşmedi (`derleyici` %80,1 → %87,7; `-O3` %78,0 → %86,9; `-O0` %63,3 → %70,4) | PK-2'de v2 taşınır; PK-4 öntanımı `TUTUCU_V2`; PK-8 (koddan alınan adresler) |
| O6 | Ad ailesi küme isabeti: aynı derleyici 0,990; aynı sürüm GCC ↔ clang 0,941 [0,907–0,963]; sürüm farklı 0,819; tek üyeli "aile" güvenilmez | PK-4: aile yalnız kanıt satırı; ad değil |
| O7 | Aynı derleyici kopyası: birleşim 0,991, kapsam %47,7; çok başvuru gnulib 0,987, %55,9; CFG bankası sürümler arası 0 | ürüne ayrı kanal olarak GİRMEZ (aynı araç zinciri ister → pratikte PK-5); ölçüm PK-3'te kalır |
| O8 | Dağıtım ikilisinde build-id aynı derlemenin `.debug` dosyasını gösterir; üründe bu yol yok | **PK-5** |
| O9 | `VersionDetector` 118 ikilinin 4'ünde tespit veriyor (openssl, lua, sqlite3); tmux / htop / coreutils / zstd / tree için yok (`K/surum_tespit.txt`) | PK-9 |
| O10 | Nüfusun %63,0'ı set içi kopya, %19,5'i öbür platform derlemesinde, %16,8'i başvurusuz | A1 bütçesine girdi (OLGU ile tutarlı) |
| O11 | Başvurunun soyulmuş / sembollü analizi (fark ≤ %0,4) ve koşu kuşağı (fark 0) sonucu değiştirmiyor; `--stage static` çıktısı eşleyici için tam koşuyla aynı (609 / 609) | PK-4 ölçümü sembollü başvuruyla aynı sayıları bekler; başvuru analizi `--stage static` yeter (PK-10) |
| O12 | Gerçek "kitaplık kopyası" örneği sette var ama başvurusu yok: zstd ikilisine gömülü `lib/` (OLGU `proje_kitapligi` 720, bugün doğru 0); redis'e gömülü `deps/*` (881, doğru 0) | PK-11 (veri V5) |

## 2. Paket sırası, önkoşullar, dosya sahipliği

```
PK-1  var olan başvuru yollarına yöntem kapısı        önkoşul: yok                      (ürün; küçük; İLK)
PK-2  eşleyiciyi ürün modülü yap (bayraksız kitaplık) önkoşul: yok                      (yeni dosyalar)
PK-3  ortak ölçüm: kimlik_olc                          önkoşul: PK-2
PK-4  ürün bağlantısı: çapalı başvuru eşleme kanalı    önkoşul: PK-1, PK-2, PK-3         (PK-1 ile AYNI dosya → sıralı)
PK-5  build-id ile ayrık hata ayıklama dosyasından ad  önkoşul: yok                      (PK-4 ile config.py'de sıralı)
PK-6  açık ölçüm: sürüm ↔ derleyici ↔ mimari ayrımı    önkoşul: PK-3; veri V1, V2
PK-7  tanıklı alt kanal: ad yerine kanıt satırı        önkoşul: PK-4 (aynı yeni dosya: kimlik/kanal.py → sıralı)
PK-8  Ghidra dökümüne fonksiyon adresi başvuruları     önkoşul: PK-3; P16d main'de
PK-9  başvuru seçici (program + sürüm tanıma)          önkoşul: PK-3; veri V3
PK-10 başvuru çalışma alanı üretimi ve ref_db bağlantısı önkoşul: PK-4, PK-9
PK-11 açık ölçüm: gömülü kitaplık kopyası (zstd lib/)   önkoşul: PK-3; veri V5
```

Paralel koşabilecekler: {PK-1, PK-2, PK-5 (config.py hariç adımları)}; sonra {PK-3}; sonra {PK-4, PK-6, PK-8, PK-9, PK-11}
(PK-4 ürün dosyalarına, öbürleri ölçüm betiklerine ve kendi yeni dosyalarına yazar); sonra {PK-7}; sonra {PK-10}.
Aynı anda en çok 4 ajan. **Yayın için asgari küme:** PK-1 (yanlış ad yazan yolun onarımı) tek başına; PK-5 ve
PK-2 → PK-3 → PK-4 kapsam getiren kümedir.

| Dosya (tehlikeli = ortak) | PK-1 | PK-2 | PK-3 | PK-4 | PK-5 | PK-8 |
|---|---|---|---|---|---|---|
| `karadul/pipeline/steps/_feedback_naming_bindiff.py` | yazar | — | — | yazar (PK-1'den SONRA) | — | — |
| `karadul/pipeline/steps/_feedback_naming_refdiff.py` | yazar | — | — | — | — | — |
| `karadul/pipeline/steps/_feedback_naming_candidates.py` (**tehlikeli**; ÖZ KOD paketleri de dokunabilir) | yazar (`_add_bindiff`, `_add_refdiff`) | — | — | — | yazar (yeni K-4 kanalı; PK-1'den SONRA) | — |
| `karadul/config.py` (**tehlikeli**) | — | — | — | yazar (1 bayrak) | yazar (1 bayrak + 1 yol; PK-4'ten SONRA) | — |
| `karadul/core/naming_labels.py` (**tehlikeli**) | — | — | — | yazar (ölçülmüş satırlar) | — | — |
| `karadul/reconstruction/kimlik/` (yeni paket) | `__init__.py`, `yontem_kapisi.py` | `olgu.py`, `esleyici.py`, `ad_ailesi.py` | okur | `kanal.py` (PK-7 de buraya yazar, PK-4'ten SONRA; PK-9 `surum.py`, PK-10 `basvuru.py`) | — | `olgu.py`, `esleyici.py` (PK-2'den SONRA) |
| `karadul/analyzers/ayrik_debug.py` (yeni) | — | — | — | — | yazar | — |
| `karadul/pipeline/steps/_feedback_naming_merger.py` (**tehlikeli**) | — | — | — | — | yazar (yalnız `add_k4_channels` çağrısı) | — |
| `scripts/measurement/kimlik_*.py` (yeni) | — | — | yazar | — | — | — |
| `karadul/ghidra/` döküm betikleri | — | — | — | — | — | yazar |
| `tests/test_pk*_*.py` (yeni; paket başına ayrı dosya) | kendi | kendi | kendi | kendi | kendi | kendi |

Tabloda sütunu olmayan paketler: PK-6, PK-11 yalnız `scripts/measurement/kimlik_ciftler.py`'ye grup ekler (ikisi
aynı dosya → sıralı); PK-7 `kimlik/kanal.py`, `config.py` (PK-5'ten sonra), `naming_labels.py` (PK-4'ten sonra);
PK-9 yalnız yeni dosyalar (`kimlik/surum.py`, `scripts/arge/kimlik/surum_olc.py`); PK-10 `kimlik/basvuru.py` (yeni),
`_feedback_naming_refdiff.py` ve `_feedback_naming_bindiff.py` (PK-4 ve PK-7'den sonra).
`config.py` sırası: PK-4 → PK-5 → PK-7. `naming_labels.py` sırası: PK-4 → PK-7.

`karadul/analyzers/bindiff.py` ve `karadul/reconstruction/reference_differ.py`'ye **hiçbir paket yazmaz** (K-3 / K-10
silme kararı olmadan kod silinmez; yöntemler yerinde kalır, ad vermeleri PK-1'de durdurulur).

### Bu turun araştırma betiklerinden taşınacaklar (nereden → nereye)

| Kaynak (`A/`) | Hedef | Paket | Not |
|---|---|---|---|
| `esle.py` (`Param`, `norm_imp`, `statik_kanit`, `ad_capalari`, `tekil_dizgi_capalari`, `esle`, `Esleme`, `DONUK*`) | `karadul/reconstruction/kimlik/esleyici.py` | PK-2 | GT'siz çekirdek; `hukum` / `olc` ölçüme gider |
| `ikiz.py` (`AileParam`, `ortak_onek`, `ortak_sonek`, `aileler`) | `karadul/reconstruction/kimlik/ad_ailesi.py` | PK-2 | `olc` ölçüme gider |
| `veri.py` içindeki olgu çıkarımı (`Fonk`, `yukle`'nin GT'siz kısmı, `isaretci_yuvalari`, `yuva_komsulari`) | `karadul/reconstruction/kimlik/olgu.py` | PK-2 | girdi: bir çalışma alanının `static/` dizini + ikili yolu |
| `veri.py` içindeki GT bağlama (`norm_gt`, `_spec`, `_gt_korpus`, GT'li `yukle`) | `scripts/measurement/kimlik_veri.py` | PK-3 | `ks1_olc.gt_elf` / `gt_mac` içe aktarılır, kopyalanmaz |
| `ciftler.py` | `scripts/measurement/kimlik_ciftler.py` | PK-3 | grup adları aynı kalır |
| `envanter.py`, `yayilim_olc.py`, `hata_dok.py`, `ciplak.py`, `ayni_derleyici.py`, `urun_bindiff.py`, `bsim_temiz.py`, `satir_ici.py`, `tanik.py` (ölçüm kısmı) | `scripts/measurement/kimlik_olc.py` alt komutları: `envanter`, `yayilim`, `hata`, `ciplak`, `ayni-derleyici`, `urun-yolu`, `bsim`, `denge`, `tanik` | PK-3 | `esle.hukum`, `esle.olc`, `ikiz.olc` buraya |
| `ayar.py` | `scripts/measurement/kimlik_olc.py ayar` | PK-3 | yalnız keşif grubunda koşar (koruma: grup adı `kesif_*` değilse reddeder) |
| `a1_pay.py`, `olgu_capraz.py`, `surum_tespit.py` | yerinde kalır (`A/`) | — | tek seferlik sayımlar; OLGU hattının `olgu_butce.py`'si kalıcı araç |
| `tanik.py` (`taniklar`) | `karadul/reconstruction/kimlik/kanal.py` içine (`taniklar` işlevi) | PK-7 | ölçüm kısmı `kimlik_olc.py tanik` (PK-3) |
| `kos_bsim.sh`, `kos_bsim2.sh`, `derle_gcc.sh`, `derle_gcc_duzey.sh`, `kos_kuyruk.sh`, `son_olcum.sh`, `static_denetim.py`, `tek_tarafli_kaynak.py` | yerinde kalır | — | verisi `K/bsim/`, `K/gcc/`, `K/ek/` kalıcı (GCC derlemeleri, sembollü tmux analizi); PK-4 ve PK-6 kullanır. `kos_gcc.sh`, `kos_ek.sh`, `kos_duzey.sh` kullanılmadı (yerlerine `kos_kuyruk.sh`) |

## 3. Paketler

### PK-1 — Var olan başvuru yollarına yöntem kapısı (ürün; İLK)

- **Amaç (tek cümle):** `BinaryDiffer` ve `ReferenceDiffer`'ın ölçülmüş kesinliği karar kuralının altında kalan
  yöntemleri ad yazmayı bırakır, kanıt satırı yazar; ölçülmemiş 0,95 güveni kalkar.
- **Dokunur:** `karadul/pipeline/steps/_feedback_naming_bindiff.py` (var), `…/_feedback_naming_refdiff.py` (var),
  `…/_feedback_naming_candidates.py` (var; yalnız `_add_bindiff`, `_add_refdiff`),
  yeni `karadul/reconstruction/kimlik/__init__.py` + `yontem_kapisi.py` (PK-2 aynı pakete başka dosyalar ekler; kesişim yok),
  yeni `tests/test_pk1_basvuru_yontem_kapisi.py`, yeni `scripts/measurement/mutation_specs_pk1.json`,
  `docs/arge/2026-11-19_mythos/kimlik/PK-1_on_kayit.md`, `PK-1.md`.
- **Dokunmaz:** `karadul/analyzers/bindiff.py`, `karadul/reconstruction/reference_differ.py`, `karadul/config.py`,
  `tests/test_bindiff.py`, `tests/test_reference_differ.py` (yöntemlerin kendisi değişmez; bu testler yeşil kalmalı).
- **Adımlar:**
  1. `yontem_kapisi.py`: `OLCULMUS_YONTEM` tablosu (yöntem adı → (doğru, ad verilen, Wilson alt)) bu belgenin
     PK-1 ön kaydındaki "TÜM GRUPLAR" sayılarıyla (kaynak dizgisi `K/urun_bindiff.txt`; sınama tabloyu
     `baglama.wilson` ile yeniden hesaplayıp karşılaştırır, `tests/test_p12a_on_ad_guveni.py` örneğindeki gibi); `ad_verebilir(yontem: str) -> bool` = alt ≥ `AD_ESIGI` (0,909; tek sabit,
     KARARLAR A-2'ye atıfla). Tabloda olmayan yöntem ölçülmemiştir → `False`.
  2. `_feedback_naming_bindiff.py` `_config_source` ve `_refdb_source`: `differ.transfer_names_with_confidence`
     çıktısı yönteme göre ikiye ayrılır; `ad_verebilir` olanlar bugünkü gibi `bindiff_confidence_map` /
     `bindiff_names`'e, olmayanlar `stats["bindiff_evidence"]` listesine (anahtar, önerilen ad, yöntem, güven)
     ve `stats["bindiff_method_gate"]` sayaçlarına (`yöntem → {ad, kanit}`) gider. `update_unprotected` yalnız
     ad verenlerle çağrılır.
  3. `_feedback_naming_refdiff.py` `_match_against_db`: `ReferenceMatchResult.matches` (`FunctionMatch.method`)
     aynı kapıdan geçer; `refdiff_naming`'e yalnız ad verebilenler girer; kalan `stats["refdiff_evidence"]`.
  4. `_feedback_naming_candidates.py` `_add_refdiff`: sabit `0.95` kalkar; güven `yontem_kapisi`'ndaki ölçülmüş
     Wilson alt sınırı (yöntem bilgisi `refdiff_naming` ile birlikte taşınmıyorsa `stats`'tan okunur; taşımak için
     `refdiff_naming` değerine dokunma, yanına `refdiff_methods: dict[str, str]` ekle). `_add_bindiff`: güven
     yöntemin ölçülmüş alt sınırı (`conf` yerine); kaynak adı `bindiff_<yöntem>` aynı kalır.
  5. Kanıt satırı: köken kaydına (`naming_provenance.json`) yeni bölüm `reference_evidence`
     (`_feedback_naming_merger.py`'deki `name_merger` bölümünü yazan fonksiyonun yaptığı gibi; o fonksiyona dokunma,
     `_feedback_naming_bindiff.py`'de ayrı küçük yazıcı): `{anahtar: [{"ad", "yontem", "olculmus_alt", "neden": "yontem_kapisi"}]}`.
  6. Ölçüm (ürün kodunu çağıran araştırma betiği, değişmeden): `python A/urun_bindiff.py kesif_htop sinama_tmux sinama_cu_ic --json <yeni>`
     önce / sonra. Betik `BinaryDiffer.compare`'i doğrudan çağırdığı için kapıyı görmez; bu yüzden betiğe `--kapi`
     seçeneği eklenir (PK-1 `A/urun_bindiff.py`'ye yazabilir): eşleşmeler `yontem_kapisi.ad_verebilir` ile süzülür.
  7. Uçtan uca duman: `reference_binary` ayarlı bir ürün koşusu (Debian htop hedef, başvuru = `K/bsim/htop_dm/1_debian`
     çalışma alanının `static/` dizinine kopyalanmış sembollü htop yoksa bu adım "veri yok" yazılır ve atlanır;
     yeni Ghidra koşusu gerekiyorsa tek koşu).
- **Kabul ölçütü (sayı ve eşik):** `--kapi` ile tmux `config` kipi toplam = yalnız `string_refs` satırı:
  **326 doğru / 16 yanlış** (önce 328 / 174); `refdb` kipinde `call_pattern` adı 0 (önce 91 / 56);
  `refdiffer` kipinde yalnız `string_fingerprint`: **304 / 12** (önce 366 / 769). Beş grubun havuzunda
  414 / 24 ve 476 / 18. Yeni yanlış 0. Tam takım yeşil.
- **Ön kayıt metni (commit'lenecek):**
  > PK-1 ön kaydı. Taban: `K/urun_bindiff.json` / `.txt` (a62f15e çıktıları, 2026-11-19; komut
  > `python A/urun_bindiff.py kesif_htop sinama_tmux sinama_cu_mac sinama_cu_ic surum`). Yöntem kapısı tablosu =
  > "TÜM GRUPLAR" satırları (beş grubun havuzu; nüfus içi, tam eşitlik; doğru / ad verilen, Wilson alt):
  > `string_refs` 414 / 438 (0,920); `string_fingerprint` 476 / 494 (0,943); `call_pattern` 222 / 283 (0,733);
  > `cfg_fingerprint` 445 / 584 (0,726); `size_params` 99 / 540 (0,153); `cfg_similarity` 1 529 / 2 748 (0,538);
  > `size_constant` 43 / 157 (0,210); `call_propagation` 8 / 16 (0,280); `decompiled_hash` ölçülmedi (ad veremez).
  > Eşik 0,909 (KARARLAR A-2) → ad verebilen yalnız `string_refs` ve `string_fingerprint`. Beklenen: kapıdan sonra
  > tmux'ta `BinaryDiffer` adları 326 / 16 (önce 328 / 174), `ReferenceDiffer` adları 304 / 12 (önce 366 / 769);
  > beş grubun havuzunda `BinaryDiffer` (`config`) 958 / 604 → 414 / 24, `ReferenceDiffer` 2 056 / 1 359 → 476 / 18;
  > düşen adların hepsi `reference_evidence`'ta. H1: yeni yanlış = 0.
  > H2: kaybedilen doğru (kanıt satırına inen): havuzda `BinaryDiffer` `config` 958 − 414 = 544 (çoğu aynı
  > derleyicideki `cfg_fingerprint` 445), `ReferenceDiffer` 2 056 − 476 = 1 580 (`cfg_similarity` 1 529); giderilen
  > yanlış 580 ve 1 341. H3: aynı derleyici çiftinde (`sinama_cu_ic`) `cfg_fingerprint` 356 / 21 (alt 0,916) tabloya
  > AYRI koşul olarak yazılmaz: yöntem tek satırdır, derleyiciler arası 0 / 42 ve başvurunun derleyicisi bilinmiyor.
  > Aynı derleyici kopyalarının doğru adları PK-4 (çapalı eşleyici) ile geri gelir. Tutmazsa eşik değişmez.
- **Sınama ve mutasyon:** birim sınamaları: (a) `ad_verebilir` tablo dışı yöntemde `False`; (b) `_config_source`
  sahte `DiffResult` ile: `size_params` eşleşmesi `bindiff_names`'e girmez, `bindiff_evidence`'a girer;
  (c) `_add_refdiff` güveni 0,95 değil; (d) `update_unprotected` korunan ön adı ezmez (var olan davranış).
  Mutantlar (`mutation_specs_pk1.json`; `find` metni tekil, mutant metni farklı uzunlukta): m1 eşik `>=` → `>`
  değil **`0.909` → `0.0`** (her yöntem ad verir) → (b) kırmızı; m2 tablo dışı yöntem `True` → (a) kırmızı;
  m3 kanıt satırı yazılmaz → (b)'nin kanıt denetimi kırmızı; m4 `_add_refdiff` sabit 0,95 geri → (c) kırmızı. Beklenen 4 / 4.
- **Ürüne girişi:** bayrak yok; bu bir onarımdır (K-2: susturma değil, ölçülmüş kural: ad yerine kanıt satırı).
  Öntanımlı koşuda davranış aynı (`reference_binary` boş, `ref_db` yoksa yol çalışmıyor): birleşik 119 ölçümünde
  fark 0 beklenir; ön kayda H4 olarak yazılır ve yeniden oynatmayla (14 ikili) denetlenir.

### PK-2 — Eşleyiciyi ürün modülü yap (kitaplık; davranış değişmez)

- **Amaç:** bu turun çapalı yayılım prototipini GT'siz, sınanmış bir ürün modülüne taşımak; araştırma betiğiyle
  bit düzeyinde aynı eşlemeyi verdiğini kanıtlamak.
- **Dokunur (hepsi yeni):** `karadul/reconstruction/kimlik/olgu.py`, `esleyici.py`, `ad_ailesi.py`
  (`__init__.py` PK-1'de açıldıysa yalnız dışa aktarım satırı eklenir; PK-1 ile aynı anda koşuyorsa `__init__.py`'yi
  PK-1 yazar, PK-2 dokunmaz ve modülleri tam yolla içe aktarır), `tests/test_pk2_kimlik_esleyici.py`,
  `scripts/measurement/mutation_specs_pk2.json`, `docs/…/kimlik/PK-2_on_kayit.md`, `PK-2.md`.
- **Dokunmaz:** `A/` altındaki araştırma betikleri (karşılaştırma tabanı; değişmez), ürünün başka her dosyası.
- **Adımlar:**
  1. `olgu.py`: `Fonksiyon` veri sınıfı (`A/veri.py` `Fonk`'un GT'siz alanları: adres, ghidra_adi, bilinen, boyut,
     dizgiler, iceaktarim, cagrilan, cagiran, sabitler, blok, kenar, komutlar, cfg_kenarlari) ve
     `calisma_alanindan(static_dizini: Path, ikili_yolu: Path | None) -> IkiliOlgusu`. Girdi dosyaları:
     `ghidra_functions.json`, `ghidra_call_graph.json`, `ghidra_strings.json` (`xrefs[].from_func_addr`),
     `ghidra_xrefs.json` (`function_xrefs[].strings_used`; iki dizgi kaynağı birleştirilir), `ghidra_cfg.json`,
     `ghidra_output/pcode.jsonl` (sabit uzayı 2; `LOAD` / `STORE`'un ilk girdisi atlanır). Thunk çözümü
     `A/veri.py` `yukle` içindeki `coz` ile aynı. "Bilinen ad" ölçütü: ürünün jenerik ad ölçütü
     (`karadul` içinde `_is_unnamed` — `_feedback_naming_candidates.py`; ölçümdeki `function_f1.is_generic_name`
     ile aynı kümeyi verdiği 4 çalışma alanında sayılır, fark varsa deftere yazılır ve ölçümdeki tanım esas alınır).
  2. `olgu.py`: `isaretci_yuvalari` ve `yuva_komsulari` (`A/veri.py`'den; `lief`; ELF `R_AARCH64_RELATIVE`,
     Mach-O zincirli düzeltme). **Önce ara:** ÖZ KOD hattının ÖK-4a paketi aynı okumayı
     `karadul/reconstruction/tarif/veri_sozcukleri.py` olarak ürüne taşıyor (`grep -rn "R_AARCH64_RELATIVE\|chained" karadul`).
     O modül main'deyse yuva listesi oradan alınır ve burada yalnız `yuva_komsulari` yazılır (iki modülün aynı
     ikilide aynı (yuva, hedef) kümesini verdiği dört ikilide sayılır); değilse asgari okuyucu burada yazılır ve
     `PK-2.md`'ye "ÖK-4a gelince birleştirilecek" notu düşülür. İkinci bir tam okuyucu yazılmaz. Başka mimarinin yer değiştirme türü gelirse (`R_X86_64_RELATIVE` vb.) tür tablosu
     genişletilir; desteklenmeyen biçimde boş liste + durum `desteklenmiyor` (uydurma yok).
  3. `esleyici.py`: `Param` (alanlar ve öntanımlar `A/esle.py` ile aynı), `norm_imp` ve üç küme
     (`IMP_ES`, `IMP_GURULTU`, `IMP_OYNAK`), `statik_kanit`, `ad_capalari`, `tekil_dizgi_capalari`, `esle`,
     `Esleme`, `Sonuc`; sabit noktalar `KURAL`, `TUTUCU`, `KURAL_V2`, `TUTUCU_V2` (`A/esle.py` `DONUK*` değerleri).
     Başvurunun adları GT'den değil `Fonksiyon.ad` alanından (sembollü başvurunun Ghidra adı) okunur; sorgunun
     adları yalnız "bilinen" olanlar.
  4. `ad_ailesi.py`: `AileParam` (0,3 / 0,5 / pencere 0,2 / en çok 8), `ortak_onek`, `ortak_sonek`, `aileler`.
     Tek üyeli küme aile değildir (ayrı alan `tek_aday`).
  5. Belirlenimcilik: sözlük / küme dolaşımına bağlı hiçbir karar yok (adaylar `(−puan, −kütle, adres)` ile
     sıralı; eşleme adres sırasıyla işlenir; kanıt ağırlığı toplamları `math.fsum` ile — araştırma betiğinde de
     öyle, `DEFTER.md` §5.12). `PYTHONHASHSEED` 0 ve 1 ile aynı çıktı sınanır.
  6. Eşdeğerlik ölçümü (kabul): `A/yayilim_olc.py`'nin kullandığı çiftlerde ürün modülünün eşlemesi (q → r,
     aşama, tur) araştırma betiğininkiyle **aynı küme**. Karşılaştırma betiği `A/esdegerlik.py` (PK-2 yazar):
     iki eşleyiciyi aynı girdilerle koşar, fark sayısını yazar.
- **Kabul ölçütü:** eşdeğerlik farkı 0 şu gruplarda ve dört noktada: `kesif_htop`, `sinama_tmux`, `sinama_cu_mac`,
  `sinama_cu_ic`, `surum`, `derleme`, `derleyici`, `derleyici_htop`, `surum_gcc`, `iyilestirme_o3`, `iyilestirme_o0`,
  `sembollu`. Türetilen sayılar `BULGULAR.md` §3.1, §3.5, §3.6, §3.8 tablolarıyla aynı (ör. tmux kural 2 276 / 158;
  kural_v2 2 566 / 172; htop kural 515 / 16; `derleyici` kural 3 908 / 38, kural_v2 4 281 / 36).
- **Ön kayıt metni:**
  > PK-2 ön kaydı. Taşıma paketidir; davranış değişmez. Beklenen: `A/esdegerlik.py` farkı 12 grupta × 4 noktada 0;
  > tmux kural 2 276 doğru / 158 yanlış, kural_v2 2 566 / 172; htop kural 515 / 16, kural_v2 583 / 19;
  > coreutils içi kural 1 026 / 13; `derleyici` kural 3 908 / 38, tutucu_v2 4 170 / 26; `iyilestirme_o0` kural
  > 3 547 / 110. Fark çıkarsa taşıma hatasıdır; araştırma betiği değiştirilmez.
- **Sınama ve mutasyon:** elle kurulmuş küçük çizgelerle birim sınamaları: (a) tekil dizgi çapası iki tarafta tekil
  değilse eşlemez; (b) çelişen oylar eşlemez; (c) marj kapısı: iki eşit aday → eşleme yok, aday listesi dolu;
  (d) karşılıklı en iyi şartı; (e) df'nin eşlenenler düştükçe azalması (ikinci turda eşlenen örnek);
  (f) `norm_imp`: `___snprintf_chk` → dışarıda (oynak), `__errno_location` ≡ `___error`, `_fopen$DARWIN_EXTSN` → `fopen`;
  (g) tablo komşuluğu: aynı kayıttaki eşlenmiş komşu `k` kanıtı üretir, pencere dışındaki üretmez;
  (h) aile: 9 üyeli küme aile vermez, tek üyeli `tek_aday`. Mutantlar: m1 marj kapısı kalkar → (c);
  m2 karşılıklılık kalkar → (d); m3 df bütün fonksiyonlardan → (e); m4 `IMP_OYNAK` boş → (f);
  m5 pencere denetimi kalkar → (g); m6 `en_cok` denetimi kalkar → (h). Beklenen 6 / 6.
- **Ürüne girişi:** yalnız kitaplık; hiçbir akış çağırmaz (PK-4 bağlar).

### PK-3 — Ortak ölçüm: `kimlik_olc`

- **Amaç:** bu turun ölçümlerini `scripts/measurement/` altında, ürün modülünü (PK-2) çağıran tek araçta kalıcı
  ve yinelenebilir yapmak.
- **Dokunur (yeni):** `scripts/measurement/kimlik_veri.py`, `kimlik_ciftler.py`, `kimlik_olc.py`,
  `tests/test_pk3_kimlik_olc.py`, `scripts/measurement/mutation_specs_pk3.json`, `docs/…/kimlik/PK-3.md`.
- **Dokunmaz:** `scripts/measurement/ks1_olc.py`, `urun_olc.py`, `function_f1.py`, `macho_*.py` (içe aktarılır).
- **Adımlar:**
  1. `kimlik_veri.py`: `A/veri.py`'nin GT bağlama kısmı; olgu çıkarımı `karadul.reconstruction.kimlik.olgu`'dan.
     Kimlik sözdizimi aynı (`debian/<program>[/<ikili>]`, `mac/<program>`, `macgnu/<ad>`, `macgnu2/<ad>`,
     `macgcc/<ad>`, `macsym/<ad>`, `korpus/<korpus>/<ad>`); yeni kök eklemek için `KOKLER` sözlüğü (tabaka verileri:
     `n2_tabaka/{a,b,c}`).
  2. `kimlik_ciftler.py`: gruplar `A/ciftler.py` ile aynı + `taze_cu_ic` (`A/ayni_derleyici.py`'deki 5, 15, … seçimi).
  3. `kimlik_olc.py` alt komutları (her biri `--json`): `envanter`, `yayilim` (nokta başına; aşama kırılımı; aile),
     `hata` (sınıf dökümü; tavan içi kesinlik; tek taraflı çiftlerin karşılıklılığı), `ciplak` (tekil dizgi, CFG,
     BSim), `ayni-derleyici`, `urun-yolu` (`BinaryDiffer` / `ReferenceDiffer`; `--kapi`), `bsim` (temiz depolar),
     `tanik` (tanıklı / tanıksız alt kanal kesinliği), `denge`, `ayar` (yalnız `kesif_*`).
  4. Hüküm tek yerde: `hukum(Q, R, q, r)` (`A/esle.py`'deki tanım; tam eşitlik, Mach-O `_`, klon tabanı). KARARLAR
     A-3 gereği "tam + biçim" satırı da raporlanır: ÖLÇÜ hattının P-Ö1'i main'deyse onun işlevi çağrılır, değilse
     satır "P-Ö1 yok" diye boş bırakılır (uydurma tanım yazılmaz).
  5. Künye: her çıktıya ürün commit'i, betik sha256'ları, kullanılan koşu kökleri, `Param` değerleri.
  6. Yeniden üretim: bu turun bütün tabloları yeni araçla koşulur ve `BULGULAR.md` sayılarıyla karşılaştırılır.
- **Kabul ölçütü:** yeniden üretimde fark 0: §2.1 (ciplak), §2.2 (urun-yolu), §2.3 (bsim), §3.1, §3.3, §3.5–§3.9,
  §4, §5 tabloları. Beklenen anahtar sayılar: tmux kural 2 276 / 158; hata sınıfları 99 / 25 / 17 / 10 / 7;
  `derleyici` kural 3 908 / 38 (4 / 13 / 16 / 3 / 2); `iyilestirme_o0` kural 3 547 / 110; tanık `-O3` çiftinde
  197 / 36 düşüyor; birleşim 1 217 / 11; çok başvuru gnulib 660 / 9; `BinaryDiffer` tmux 328 / 174.
- **Ön kayıt metni:**
  > PK-3 ön kaydı. Yeniden üretim paketidir. Beklenen: yukarıdaki sayılar tam eşit. Fark taşıma hatasıdır.
- **Sınama ve mutasyon:** sentetik iki "ikili" (elle kurulmuş olgu + GT) ile: `hukum`'ün dört sonucu; nüfus dışı
  eşleme kesinliğe girmez; tavan sayımı; hata sınıfı sırası (tek taraflı / satır içi / komşu / aile / diğer);
  `ayar`'ın `kesif_*` dışı grupta reddi. Mutantlar: m1 `hukum` klon tabanını soymaz; m2 nüfus süzgeci kalkar;
  m3 `ayar` koruması kalkar; m4 tek taraflı ↔ satır içi ayrımı ters. Beklenen 4 / 4.
- **Ortak ölçüme girişi:** `scripts/measurement/kimlik_olc.py`; `urun_olc`'a dokunmaz. Ürün kanalı (PK-4)
  açıldığında ad kesinliği `urun_olc`'un kanal kırılımından ayrıca okunur (aynı sayıyı vermesi beklenir; PK-4 kabulü).

### PK-4 — Ürün bağlantısı: çapalı başvuru eşleme kanalı (bayrak arkasında, kapalı)

- **Amaç:** analist sembollü bir başvuru çalışma alanı verdiğinde adların `BinaryDiffer` yerine çapalı
  eşleyiciden gelmesi; ölçülmüş güvenle; ailelerin ve kapıda kalanların kanıt satırı olarak yazılması.
- **Dokunur:** `karadul/pipeline/steps/_feedback_naming_bindiff.py` (var; PK-1'den sonra), `karadul/config.py`
  (var; `BinaryReconstructionConfig`'e bir alan), `karadul/core/naming_labels.py` (var; ölçülmüş satırlar),
  yeni `karadul/reconstruction/kimlik/kanal.py`, yeni `tests/test_pk4_basvuru_kanali.py`,
  `scripts/measurement/mutation_specs_pk4.json`, `docs/…/kimlik/PK-4_on_kayit.md`, `PK-4.md`.
- **Dokunmaz:** `_feedback_naming_candidates.py` (adlar var olan `bindiff_confidence_map` yolundan girer; kaynak
  adı `bindiff_basvuru_<aşama>`), `_feedback_naming_merger.py`, `c_namer.py`.
- **Adımlar:**
  1. `config.py`: `enable_anchored_reference_matching: bool = False` (yorum: ölçüm kaynağı bu belge + PK-4.md).
     `reference_binary`'nin anlamı değişmez: başvuru ikilisinin yolu; yanındaki Ghidra çıktıları
     (`ghidra_functions.json` …) bugün aynı dizinden okunuyor (`_config_source`). Yeni eşleyici başvurunun
     `static/` dizinini ister: `reference_binary` bir çalışma alanının `raw/<ad>` yoluysa `../static`; değilse
     bugünkü "yanındaki JSON'lar" düzeni. Bulunamazsa durum `veri_yok` (P-S1 sözlüğü) ve neden.
  2. `kanal.py`: `basvuru_esle(hedef_static, hedef_ikili, basvuru_static, basvuru_ikili, nokta) -> KanalSonucu`:
     `olgu.calisma_alanindan` × 2 → `esleyici.esle` → adlar (yalnız başvuru adı jenerik olmayan eşlemeler),
     aileler (`ad_ailesi.aileler`), tek adaylar, sayaçlar (aşama başına; tur sayısı). Nokta öntanımı
     **`TUTUCU_V2`** (v2 bağımsız sınamada tuttu: `BULGULAR.md` §3.6 G6, §3.8); `lief` yoksa ya da ikili biçimi
     desteklenmiyorsa `TUTUCU`'ya iner ve durum alanına `tablo_kaniti: arac_yok | desteklenmiyor` yazar (sessiz düşüş yok).
  3. `_config_source`: bayrak açıksa `BinaryDiffer` yerine `kanal.basvuru_esle`; sonuç
     `bindiff_confidence_map[anahtar] = (ad, guven, "basvuru_<aşama>")`. `guven` = aşamanın ölçülmüş Wilson alt
     sınırı (`naming_labels`'tan). Korunan ön adlar ezilmez (`update_unprotected`, değişmeden).
  4. `naming_labels.py` `MEASURED_PRE_NAME_PRECISION`'a dört satır (kaynak `K/yayilim_v2_hepsi.json` ve
     `K/yayilim_gcc.json`, tutucu_v2 aşama kırılımı; (doğru, ad verilen, Wilson alt) PK-3'ün `yayilim` çıktısından
     okunur ve teste yazılır):
     `basvuru:dizgi` (737, 791, 0,912) ve `basvuru:yayilim` (1 683, 1 781, 0,933) — sürüm bilinmiyor / farklı
     (tmux 3.5a ↔ 3.8);
     `basvuru_esli:dizgi` (1 085, 1 085, 0,997) ve `basvuru_esli:yayilim` (3 085, 3 111, 0,988) — sürüm eşli
     (tmux 3.8, GCC ↔ clang). Hangi satırın kullanılacağını adım 5'teki sürüm durumu belirler; sürüm doğrulanamıyorsa
     tutucu satırlar (`basvuru:*`). `tests/test_p12a_on_ad_guveni.py` tabloyu belgeyle karşılaştırıyor; o testin
     beklenen tablosu da güncellenir (bu dosya PK-4'ün; başka paket dokunmaz). Uyarı: satırlar tek programdan
     (tmux); PK-6 başka programlarda ölçünce havuzlanmış değerle değiştirilir.
  5. Sürüm etiketi: `kanal.py`, hedef ve başvurunun sürüm dizgilerini (PK-9 hazırsa onun işlevi; değilse
     `VersionDetector` çıktısı; ikisi de yoksa `bilinmiyor`) köken kaydına yazar. Sürümler farklı ya da bilinmiyorsa
     ad kaydına `basvuru_surumu_farkli_olabilir: true` konur (rapor "başvurunun sürümündeki ad" diye gösterir);
     ad yine yazılır (karar kuralı: tmux'ta sürüm farkıyla tutucu_v2 alt sınırı 0,931 ≥ 0,909). Bilinen karşı
     örnek: coreutils 9.7 ↔ 9.12'de alt sınır 0,836 < 0,909 (`BULGULAR.md` §3.5); sürüm farkı büyüdükçe kanal
     eşiğin altına inebilir — bu yüzden etiket zorunlu ve PK-9'un sürüm uzaklığı ölçüsü açılma kararına girdidir.
  6. Kanıt satırları (`reference_evidence`, PK-1'in bölümü): aile (`adlar`, `onek`, `sonek`, üye sayısı),
     tek aday (`ad`, `neden: karsiliklilik`), kapıda kalan en iyi aday (`ad`, `puan`, `ikinci`). Bunlar ad
     haritasına GİRMEZ.
  7. Ürün ölçümü (Ghidra gerekir; sıralı). Başvuru hazır: Mac tmux 3.8'in sembollü analizi
     `K/ek/macsym/tmux/ws/workspaces/tmux/<zaman>/` (`--stage static` koşusu; `raw/` ve `static/` var).
     Hedefler: (i) GCC tmux 3.8 (`K/gcc/corpus/tmux/bin/tmux`; aynı sürüm), (ii) Debian tmux 3.5a
     (`~/karadul_olcum/n1_debian13/tmux/tmux/ws/workspaces/tmux/20261021_092848/raw/tmux`; sürüm farklı).
     Her hedef için bayrak kapalı ↔ açık (4 tam koşu). (i)'nin GT'si `K/gcc/corpus/tmux/gt/tmux.gt.json`
     (`urun_olc olc --kok-mac <koşu kökü> --mac-veri K/gcc`).
- **Kabul ölçütü:** (a) bayrak kapalıyken 119 yeniden oynatmada ad haritası bayt bayt aynı; (b) bayrak açık:
  `bindiff_basvuru_*` kanalının `urun_olc` kesinliği (i)'de Wilson alt ≥ 0,95, (ii)'de ≥ 0,909; doğru ad sayısı
  araştırma ölçümünün ±%5'i içinde ((i) 2 055, (ii) 1 192; fark nedeni `PK-4.md`'ye: korunan ön adlar, ad
  geçerliliği, birleştiricide başka kanalın kazanması); (c) yeni yanlış ad yalnız bu kanaldan; öbür kanalların
  adlarında değişen anahtar sayısı raporlanır (beklenen: yalnız bu kanalın yeni ad verdiği anahtarlar);
  (d) aile ve tek aday ad haritasında 0.
- **Ön kayıt metni:**
  > PK-4 ön kaydı. Kollar: bayrak kapalı ↔ `enable_anchored_reference_matching` açık (nokta `TUTUCU_V2`).
  > Başvuru: Mac tmux 3.8, sembollü analiz. Araştırma ölçümü (`K/yayilim_sembollu.txt`, tutucu_v2, nüfus içi):
  > (i) hedef GCC tmux 3.8 (aynı sürüm): 2 055 doğru / 11 yanlış (0,995, Wilson alt 0,991), kapsam 2 055 / 2 335;
  > (ii) hedef Debian tmux 3.5a (sürüm farklı): 1 192 / 74 (0,942, alt 0,927), kapsam 1 192 / 1 851.
  > H1: ürün kanalının kesinliği (i) Wilson alt ≥ 0,95; (ii) ≥ 0,909. H2: doğru ad sayısı (i) 1 952–2 158,
  > (ii) 1 132–1 252 (±%5). H3: bayrak kapalı kolda fark 0. H4: (ii)'de yanlışların en büyük sınıfı "tek taraflı"
  > (araştırmada 41 / 74); (i)'de "satır içi + komşu" (8 / 11; `K/hata_sembollu_tutucu_v2.txt`). H5: taban ürünün aynı hedefteki nüfus içi doğru adı (Debian tmux 136) bayrak açıkken
  > azalmaz (korunan ön adlar ezilmiyor). Tutmayan hipotez kural değiştirilmeden kayda geçer; H1 tutmazsa kanal o
  > koşulda kanıt satırına iner (bayrak kapalı kalır).
- **Sınama ve mutasyon:** (a) bayrak kapalı → `BinaryDiffer` yolu (PK-1 kapısıyla) aynen; (b) bayrak açık + sahte
  iki çalışma alanı → ad `bindiff_confidence_map`'te, yöntem `basvuru_dizgi`; (c) korunan ön ad ezilmez;
  (d) aile ad haritasına girmez, `reference_evidence`'a girer; (e) başvuru `static/` yoksa durum `veri_yok`;
  (f) güven `naming_labels` satırından. Mutantlar: m1 bayrak okunmaz (hep açık) → (a); m2 aile ad olarak yazılır → (d);
  m3 güven sabit 0,95 → (f); m4 jenerik başvuru adı (`FUN_…`) ad olarak aktarılır → (b)'nin ek denetimi;
  m5 `update_unprotected` atlanır → (c). Beklenen 5 / 5.
- **Ürüne girişi:** `binary_reconstruction.enable_anchored_reference_matching`, öntanım **kapalı**. Bayrak yalnız
  analist `reference_binary` verdiğinde etkilidir; kapalıyken PK-1 kapılı `BinaryDiffer` çalışır. Açılma koşulu
  (ana oturumun ayrı kararı): PK-4 H1 tuttu **ve** PK-6'da en az iki başka programda sürümü eşli çiftlerde Wilson
  alt ≥ 0,909.

### PK-5 — Build-id ile ayrık hata ayıklama dosyasından ad (bayrak arkasında, kapalı)

- **Amaç:** soyulmuş ELF'in GNU build-id'siyle eşleşen ayrık `.debug` dosyası analistin verdiği dizinde varsa
  fonksiyon adlarını oradan okumak (aynı derleme; eşleme yok).
- **Dokunur:** yeni `karadul/analyzers/ayrik_debug.py`; `karadul/pipeline/steps/_feedback_naming_candidates.py`
  (var; yeni K-4 kanalı `dwarf_ayrik`: `K4_CHANNEL_FLAGS`, `add_k4_channels`, yeni `_add_separate_debug`; PK-1'den
  sonra); `karadul/config.py` (var; `enable_separate_debug_naming: bool = False`, `debug_file_dirs: list[str]`;
  PK-4'ten sonra); `karadul/pipeline/steps/_feedback_naming_merger.py` (var; yalnız K-4 bayraklarının okunduğu ve
  `add_k4_channels`'ın çağrıldığı yer: `flags = {src: config_flag(br, flag) for src, flag in K4_CHANNEL_FLAGS.items()}`
  satırının çevresi — yeni `debug_file_dirs` argümanı geçirilir; başka satıra dokunulmaz);
  yeni `tests/test_pk5_ayrik_debug.py`, `scripts/measurement/mutation_specs_pk5.json`, `docs/…/kimlik/PK-5_on_kayit.md`, `PK-5.md`.
- **Dokunmaz:** `karadul/analyzers/dwarf_extractor.py` (yeniden kullanılır: `DwarfExtractor(path).extract_functions()`),
  ağ kodu (bu pakette indirme YOK; debuginfod ayrı karar).
- **Adımlar:**
  1. `ayrik_debug.py`: `build_id(ikili) -> str | None` (ELF `.note.gnu.build-id`; `lief` ya da `pyelftools`,
     hangisi üründe kullanılıyorsa); `debug_dosyasi_bul(build_id, dizinler) -> Path | None`: her dizinde
     `.build-id/xx/yyyy….debug` ve `usr/lib/debug/.build-id/xx/yyyy….debug`; bulunan dosyanın kendi build-id'si
     ikilininkiyle aynı olmalı (değilse reddet; durum `hata`, neden `build_id_uyusmuyor`).
  2. `_add_separate_debug`: `DwarfExtractor(debug_dosyasi).extract_functions()` → `_add_resolved(source="dwarf_ayrik",
     addr=…, confidence=0.95, …)` (adres ikilinin bağlama adresi; `GhidraFunctionIndex.delta` var olan yolla).
     DWARF `low_pc`'siz fonksiyon atlanır; ELF simge tablosu (`.symtab`) `.debug` dosyasında varsa o da okunur
     (ölçümün GT'si budur: `function_f1.extract_gt` — ürün koduna kopyalanmaz, aynı kaynak okunur).
  3. Durumlar P-S1 sözlüğüyle: `kapali`, `veri_yok` (build-id yok / dosya yok), `calisti`, `hata`.
     `UNMEASURED_SOURCES`'a eklenir (güven ölçülene dek `null`), ölçümden sonra PK-5.md'deki sayıyla çıkarılır.
  4. Düşman girdi (I4, açık soru): `.debug` dosyası güvenilmez girdidir. Bu pakette sınanır: kesik dosya, boş
     `.debug_info`, çok uzun `DW_AT_name` (ad `c_identifier` + ad geçerliliğinden geçer; uzunluk sınırı ürünün ad
     sınırı), ikilinin adres aralığı dışındaki `low_pc` (atlanır, sayaç). Dosya boyutu üst sınırı (öneri 512 MB) ve
     süre sınırı konur. Bozuk dosyada kanal `hata` yazar, akış sürer; `DwarfExtractor` içinde düzeltme gerekirse
     ayrı bulgu olarak yazılır (o dosya bu paketin değil).
  5. Ölçüm: geliştirme setinin 116 Debian ELF'i için `debug_file_dirs = [~/karadul_olcum/downloads/debian13]`
     ile yeniden oynatma (Ghidra'sız; birleştirici adımı) → `urun_olc olc`. **Bu ölçüm döngüseldir** (GT aynı
     dosyadan): amaç kesinlik kanıtı değil, adres bağlamanın ve boru hattının doğruluğu.
  6. Bağımsız denetim: Mach-O için eşdeğeri yok (Homebrew şişesinde `.dSYM` yok); yalnız ELF. PE / PDB var olan yol.
- **Kabul ölçütü:** (a) bayrak kapalı → fark 0; (b) bayrak açık, 116 ELF: `dwarf_ayrik` kanalından ad alan nüfus
  fonksiyonu ≥ nüfusun %99'u (Debian nüfusu 18 229 = 21 371 − Mac 3 142), yanlış 0 (döngüsel olduğu için yanlış
  > 0 bir adres bağlama hatasıdır); (c) yanlış build-id'li dosya reddedilir; (d) 119 koşuda süre artışı raporlanır.
- **Ön kayıt metni:**
  > PK-5 ön kaydı. Kollar: bayrak kapalı ↔ `enable_separate_debug_naming` açık + `debug_file_dirs`. Döngüsel
  > ölçüm (GT ile aynı kaynak): beklenen yanlış 0; ad alan nüfus ≥ 18 047 (18 229'un %99'u); eksikler nedenleriyle
  > listelenir (DWARF'sız araç zinciri nesneleri: OLGU `derleyici` / `dwarf_yok` 153; klon adları). H1: yanlış = 0.
  > H2: kapalı kolda fark 0. H3: build-id'si uyuşmayan dosya 0 ad üretir. Bu sayılar ürün başarı ölçüsüne
  > (kapsam, kesinlik) YAZILMAZ; ayrı satırda "aynı derlemenin hata ayıklama dosyası verildiğinde" diye raporlanır.
- **Sınama ve mutasyon:** küçük ELF + ayrık `.debug` düzeneği (testte `objcopy --only-keep-debug` yoksa test
  atlanır; ayrıca elle üretilmiş asgari bir `.debug` sabit dosyası `tests/fixtures/` altına — yeni dosya, boyutu
  < 100 KB): (a) bulma iki dizin düzeninde; (b) build-id uyuşmazlığı reddi; (c) adres bağlama (PIE delta);
  (d) bayrak kapalıyken kanal `kapali`. Mutantlar: m1 build-id karşılaştırması kalkar → (b); m2 delta uygulanmaz → (c);
  m3 bayrak okunmaz → (d). Beklenen 3 / 3.
- **Ürüne girişi:** `binary_reconstruction.enable_separate_debug_naming` (kapalı) + `debug_file_dirs`. Açık öneri:
  ölçüm kollarında hep kapalı kalır (GT sızıntısı); analist kullanımında açılması Berke kararı (öneri: dosya
  verildiyse aç — PDB kanalının "sembol varsa kullan" kuralıyla aynı gerekçe). debuginfod'dan indirme bu pakette
  yok; istenirse `network.enabled` + ayrı bayrakla ayrı paket.

### PK-6 — Açık ölçüm: sürüm ↔ derleyici ↔ mimari ayrımı (taze çiftler)

- **Amaç:** tam ad kesinliğini neyin bozduğunu tek etken değiştirerek saymak ve dondurulmuş eşleyicinin (v1 ve v2)
  bağımsız sınamasını yapmak.
- **Dokunur:** `scripts/measurement/kimlik_ciftler.py` (yeni gruplar), `docs/…/kimlik/PK-6_on_kayit.md`, `PK-6.md`;
  veri `~/karadul_olcum/runs/<tarih>/PK-6/`. Ürün koduna dokunmaz.
- **Tur 1'de ölçülen (artık "taze" değil; karşılaştırma tabanı):** tmux 3.8 GCC 16 `-O0` / `-O2` / `-O3` ve htop
  3.5.3 GCC 16 ↔ Homebrew clang (`K/gcc/`; `BULGULAR.md` §3.6, §3.8). Açık kalan: **başka programlar** ve **mimari**.
- **Girdi verisi:** (ii) ÖLÇÜ P-Ö6 tabaka C (`~/karadul_olcum/n2_tabaka/c/`: tmux 3.8 ve htop 3.5.3, clang, 6
  iyileştirme düzeyi — clang tarafının iyileştirme merdiveni; tmux GCC merdiveni ölçüldü, clang merdiveni yeni);
  (iii) ÖLÇÜ P-Ö7 tabaka A (x86-64, aynı kaynak sürümü) ve B (GCC 12 / 13); (iv) V1 (başka programların aynı
  sürüm, iki derleyici derlemeleri — hipotezin tmux dışı sınaması).
- **Adımlar:**
  1. Gruplar (sorgu ↔ başvuru; hepsi iki yön): `iyilestirme` = tabaka C'de `-O2` ↔ {`-O0`, `-O1`, `-Os`, `-O3`,
     `-O2 -flto`} (aynı sürüm, aynı derleyici); `mimari` = Debian 13 arm64 ↔ amd64 aynı paket sürümü (tabaka A);
     `derleyici_surumu` = Debian 13 (GCC 14) ↔ Debian 12 (GCC 12) / Ubuntu 24.04 (GCC 13) (tabaka B; sürüm de
     değişir — paket sürümleri künyeye yazılır); `surum_esli` = V1 (aynı sürüm, GCC ↔ clang, başka programlar).
  2. Her grupta dondurulmuş dört nokta (`KURAL`, `TUTUCU`, `KURAL_V2`, `TUTUCU_V2`); parametre değişmez.
  3. `kimlik_olc yayilim` + `hata` + `ciplak`; grup başına havuz ve program başına satır.
  4. x86-64 için `olgu.isaretci_yuvalari`'nın yer değiştirme türü (`R_X86_64_RELATIVE`) PK-2'de eklendiyse v2
     koşulur; değilse v2 o grupta "desteklenmiyor" yazılır.
  5. `PK-6.md`: etken başına tablo: kesinlik, tavan içi kesinlik, kapsam, hata sınıfları (tek taraflı / satır içi /
     komşu / aile / diğer).
- **Kabul ölçütü:** ölçüm paketidir; kabul = bütün gruplar koşuldu, künyeler tam, ön kayıtlı hükümler yazıldı.
- **Ön kayıt metni:**
  > PK-6 ön kaydı. Açık ölçüm; beklenen sayı yok, eşikler var. Grup başına, havuz ve program düzeyinde:
  > (a) tam ad kesinliği Wilson alt ≥ 0,95 → "hat hedefi tuttu"; ≥ 0,909 → "ad yazabilir (A-2)"; altı → "kanıt satırı".
  > (b) Sürümü eşli gruplarda (`iyilestirme`, `mimari`, `surum_esli`) "tek taraflı" yanlış payı ≤ %20 → "tek taraflı
  > sınıf sürüm kaynaklıdır" okuması destek bulur; > %50 → çürür (sınıf başka bir şeydir; tur 1 yorumu geri çekilir).
  > (c) `iyilestirme` grubunda satır içi + komşu türü yanlış sayısı düzey farkıyla artar (`-O0` ↔ `-O2` en çok;
  > tur 1'de GCC ile 93 ↔ 50); artmıyorsa "satır içi" sınıflaması yanlış adlandırılmıştır. (d) v2'nin kapsamı v1'den
  > büyük ve kesinlik farkı Wilson aralıkları içinde (tur 1: dört taze çiftte tuttu) → v2 öntanım kalır; tutmayan
  > program çıkarsa PK-4 öntanımı `TUTUCU`'ya döner. (e) **Genelleme hükmü:** `surum_esli` grubunda (tmux dışı
  > programlar) program başına Wilson alt ≥ 0,909 olan program sayısı / toplam; ≥ 3 programın en az 2'si → "tmux'a
  > özgü değil". Tur 1 değerleri (karşılaştırma için, beklenti değil): tmux 0,990 [0,987–0,993], htop 0,984
  > [0,974–0,990]. Eşikler sonradan değişmez.
- **Sınama ve mutasyon:** kod yok (grup tanımı); `kimlik_ciftler` sınaması: her grubun iki ikilisi farklı sha256,
  aynı program adı; kilitli ad süzgeci (kilit belgelerindeki adlarla kesişim boş). Mutant: süzgeç boş → kırmızı (1 / 1).
- **Ortak ölçüme girişi:** gruplar `kimlik_ciftler.py`'de kalıcı; sonraki birleşik ölçümlerde "kimlik" satırı.

### PK-7 — Tanıklı alt kanal: satır içi şüphesinde ad yerine kanıt satırı (bayrak arkasında)

- **Amaç:** sürüm eşlendikten sonra kalan yanlışların ana sınıfını (satır içine alma kayması, O4) azaltmak:
  "çağıranın çağrılanı" tanığını taşıyan eşleme ad yazmaz, kanıt satırı yazar.
- **Tur 1'de ölçülen** (`BULGULAR.md` §3.9; `A/tanik.py`; `-O3` / `-O0` çiftleri dondurulmuş sınama):
  tanıklı alt kanalın kesinliği `-O3` 0,845 [0,793–0,886], `-O0` 0,821 [0,773–0,860], `derleyici` 0,869
  [0,808–0,912]: her çiftte Wilson alt < 0,909. Tanıksız kalan: 0,991, 0,983, 0,996. Bedel: kapsam 2,9–4,3 puan
  (kural noktası). "Ucuz kapı" ön kaydı (düşen doğru / düşen yanlış ≤ 1,0) **tutmadı** (4,6–5,5): bu paket bir
  kapı iyileştirmesi değil, karar kuralının (A-2) alt kanala uygulanmasıdır; açılması ürün kararıdır.
- **Dokunur:** `karadul/reconstruction/kimlik/kanal.py` (PK-4'ün dosyası; PK-4'ten sonra), `karadul/config.py`
  (bir bayrak; PK-5'ten sonra), `karadul/core/naming_labels.py` (iki satır), `tests/test_pk7_tanik.py`,
  `scripts/measurement/mutation_specs_pk7.json`, `docs/…/kimlik/PK-7_on_kayit.md`, `PK-7.md`.
- **Dokunmaz:** `esleyici.py` (tanık eşleme bittikten sonra hesaplanır; eşlemeyi değiştirmez).
- **Tanım (uygulanacak hâliyle; `A/tanik.py` `taniklar`, `kmax` süzgeci yok):** eşleme `M: Q → R` bittikten sonra,
  kabul edilmiş her (q, r) için `C_q` = q'nun eşlenmiş çağrılanlarının R'deki karşılıkları, `C_r` = r'nin eşlenmiş
  çağrılanları.
  - **K1:** q'nun bir çağıranı p var ve `(C_p \ C_q) ∩ C_r ≠ ∅` (r hariç): r, q'nun çağıranının çağırıp q'nun
    çağırmadığı bir fonksiyonu çağırıyor.
  - **K2:** r'nin bir çağıranı p′ var ve `(C_p′ \ C_r) ∩ C_q ≠ ∅`: simetriği.
  - K1 ya da K2 → eşleme "tanıklı".
- **Adımlar:**
  1. `kanal.py`: `taniklar(hedef_olgu, basvuru_olgu, sonuc) -> dict[int, str]` (`A/tanik.py`'den; sıralı dolaşım).
  2. `config.py`: `anchored_reference_witness_gate: bool = False`.
  3. `kanal.basvuru_esle`: bayrak açıksa tanıklı eşlemeler ad listesinden çıkar, `reference_evidence`'a
     `{"ad", "neden": "satir_ici_tanigi", "tanik": "K1|K2|K1+K2"}` olarak yazılır. Bayrak kapalıyken ad yazılır
     ama köken kaydına `satir_ici_suphesi: true` düşülür (rapor işaretler).
  4. `naming_labels.py`: `basvuru_esli:tanikli` ve `basvuru_esli:taniksiz` satırları, PK-3'ün `tanik` alt komutunun
     tutucu_v2 çıktısından (`K/tanik_sinama_tutucu_v2.json`; bugünkü değerler `derleyici`: tanıksız 4 035 / 13,
     tanıklı 135 / 13).
  5. Ölçüm: PK-4'ün (i) ve (ii) ürün koşuları, kapı kapalı ↔ açık.
- **Kabul ölçütü:** (a) eşdeğerlik: `kanal.taniklar` çıktısı `A/tanik.py` ile aynı küme (PK-2'nin 12 grubunda);
  (b) kapı açıkken (i)'de kalan adların kesinliği Wilson alt ≥ 0,99 ve kapsam kaybı ≤ 5 puan; (c) düşen adların
  hepsi kanıt satırında; (d) kapı kapalıyken ad haritası PK-4 ile aynı.
- **Ön kayıt metni:**
  > PK-7 ön kaydı. Araştırma ölçümü (tutucu_v2, nüfus içi; `K/tanik_sinama_tutucu_v2.txt`): `derleyici` 4 170 / 26 →
  > tanıksız 4 035 / 13 (0,997 [0,995–0,998]), kapsam %85,5 → %82,7; `-O3` 3 852 / 68 → 3 657 / 34; `-O0`
  > 3 762 / 86 → 3 534 / 37. Ürün ölçümünün araştırma karşılığı (`K/tanik_sembollu_tutucu_v2.txt`; hedef GCC tmux
  > 3.8 → başvuru Mac tmux 3.8 sembollü): 2 055 / 11 → tanıksız 1 989 / 6 (0,997 [0,994–0,999]), kapsam %88,0 →
  > %85,2; tanıklı 66 doğru / 5 yanlış (alt kanal 0,930 [0,846–0,970]). Sürüm farklı hedefte (Debian tmux 3.5a):
  > 1 192 / 74 → 1 121 / 63. H1 (ürün, aynı sürüm hedefi): kapı açıkken yanlış ad sayısı en az %40 azalır
  > (araştırmada 11 → 6, %45). H2: kapsam kaybı ≤ 5 puan (araştırmada 2,8). H3: tanıklı alt kanalın kesinliği
  > Wilson alt < 0,909 (alt kanal kararının dayanağı; araştırmada 0,846). H4 (genelleme, PK-6 verisi gelince): tmux dışı en az bir programda H3 yeniden tutar; tutmazsa kapı
  > öntanımı kapalı kalır. Eşikler sonradan değişmez.
- **Sınama ve mutasyon:** elle kurulmuş 6 düğümlü çizge: K1 olumlu / olumsuz, K2 olumlu / olumsuz; r'nin kendisi
  tanık sayılmaz; eşlenmemiş çağrılan tanık üretmez. Mutantlar: m1 `- C_q` kalkar (her ortak çağrılan tanık) →
  olumsuz örnek kırmızı; m2 `r` hariç tutulmaz; m3 bayrak okunmaz; m4 düşen ad kanıt satırına yazılmaz. Beklenen 4 / 4.
- **Ürüne girişi:** `binary_reconstruction.anchored_reference_witness_gate`, öntanım **kapalı**. Karar ana oturumun:
  kesinlik 0,994 → 0,997 karşılığı kapsam −2,8 puan (tutucu_v2, `derleyici`).
- **Açık araştırma (paket değil):** tanık satır içi türünün %35–48'ini kaçırıyor ve yakaladıklarının çoğu doğru.
  Daha seçici bir tanım (ör. tanık fonksiyonunun q'nun gövdesindeki çağrı sırasıyla desteklenmesi; satır içine
  alınan fonksiyonun kendi tekil kanıtının r'de "fazladan" görünmesi) sonraki araştırma turunun konusudur; veri:
  `-O0` ↔ `-O2` çifti (satır içi türü 93 yanlış; `K/hata_duzey_kural.json`).

### PK-8 — Ghidra dökümüne fonksiyon adresi başvuruları (koddan alınan adresler)

- **Amaç:** tablo yuvası kanıtının göremediği çağıransız fonksiyonları (adresi kod içinde alınan geri çağrılar)
  kanıt kümesine katmak.
- **Olgu:** htop'ta çağıransız nüfusun yer değiştirme tablosunda yuvası olanı Debian 127 / 184, Mac 133 / 217;
  kalan 57 ve 84 fonksiyonun adresi kodda alınıyor (`BULGULAR.md` §3.5). `ghidra_xrefs.json` bugün fonksiyona
  çağrı dışı başvuruyu taşımıyor (`function_xrefs[*]` alanları: `strings_used`, `functions_called`, `called_by`).
- **Dokunur:** `ghidra_xrefs.json`'ı yazan döküm kodu: `karadul/ghidra/headless.py` (PyGhidra yolu) ve
  `karadul/ghidra/scripts/xref_analysis.py` (`grep -rln "strings_used" karadul/ghidra` bu ikisini veriyor; hangisinin
  etkin akışta koştuğu `PK-8.md`'ye yazılır, yalnız etkin olan değiştirilir, öbürü biçim uyumu için aynı alanla güncellenir); `karadul/reconstruction/kimlik/olgu.py`
  (yeni alan `adres_alan: set[int]`); `karadul/reconstruction/kimlik/esleyici.py` (yeni kanıt türü `a`: "adresimi
  alan eşlenmiş fonksiyon"); `tests/test_pk8_adres_basvurusu.py`; `docs/…/kimlik/PK-8_on_kayit.md`, `PK-8.md`.
- **Dokunmaz:** `pcode.jsonl` biçimi (P16d'nin alanı); döküm sırası P16d'nin kuralına uyar.
- **Önkoşul:** P16d (Ghidra döküm sırası) main'de; aksi hâlde iki paket aynı döküm kodunda çakışır.
- **Adımlar:**
  1. Döküme alan: fonksiyon başına `address_taken_by: [{"from_func_addr", "ref_type": "DATA" | "READ" | "PARAM"}]`
     (Ghidra `ReferenceManager.getReferencesTo(giriş)` içinde çağrı olmayanlar; kaynak adresi bir fonksiyon
     gövdesindeyse o fonksiyon). Sıra: (kaynak adres) artan. Kayıp sayacı `losses`'a.
  2. `olgu.py`: alan okunur (yoksa boş; eski koşularla uyum).
  3. `esleyici.py`: kanıt `("a", eşlenmiş_alan_fonksiyon_kimliği)`; çarpan 1,0 (ayar yok; `v` / `^` ile aynı aile).
     Yeni sabit nokta `KURAL_V3`; v1 / v2 değişmez.
  4. Ölçüm: 4 Ghidra koşusu (Debian / Mac htop, tmux; sıralı) → `kimlik_olc yayilim` v2 ↔ v3.
  5. Belirlenimcilik: iki ardışık koşuda `ghidra_xrefs.json` bayt bayt aynı (P16d kabul ölçütüyle aynı).
- **Kabul ölçütü / ön kayıt metni:**
  > PK-8 ön kaydı. htop (ayar çifti) ve tmux (ikinci bakış) çiftlerinde v2 ↔ v3. H1: çağıransız nüfusta en az bir
  > `address_taken_by` kaydı olan fonksiyon, yuvası olmayanların ≥ %50'si (htop Debian 57, Mac 84 fonksiyonun).
  > H2: v3 kapsamı v2'den büyük (htop'ta ≥ +10 doğru). H3: v3 kesinliğinin Wilson aralığı v2'ninkiyle örtüşür
  > (yanlış oranı artmaz). H4: öbür çıktılarda (ad haritası, bayrak kapalı) fark 0. H1 tutmazsa paket dökümü
  > geri almaz (alan zararsız), eşleyici değişikliği girmez.
- **Sınama ve mutasyon:** `olgu` alanı eski biçimli JSON'da boş kalır; kanıt `a` yalnız eşlenmiş alan için üretilir.
  Mutantlar: m1 eşlenmemiş alan da kanıt üretir; m2 çağrı başvurusu da `address_taken_by`'a yazılır. Beklenen 2 / 2.
- **Ürüne girişi:** döküm alanı her koşuda yazılır (ek veri); eşleyicide yalnız `KURAL_V3` seçilirse kullanılır
  (PK-4 bayrağının arkasında; öntanım nokta değişmez).

### PK-9 — Başvuru seçici: program ve sürüm tanıma (açık ölçüm + küçük modül)

- **Amaç:** "hangi başvuru" sorusunu ölçülebilir yapmak: ikilinin program adı ve sürümünü dizgilerden okumak ve
  birden çok aday başvuru arasından doğru sürümü seçmek.
- **Olgu:** `VersionDetector.detect_from_strings` 118 ikilinin 4'ünde tespit veriyor; tmux / htop / coreutils /
  zstd / tree için kalıp yok (`K/surum_tespit.txt`). Sürüm dizgileri ikililerde var (htop `3.4.1`, gcat `9.12`).
- **Dokunur:** yeni `karadul/reconstruction/kimlik/surum.py`; yeni `scripts/arge/kimlik/surum_olc.py`;
  `tests/test_pk9_surum.py`; `docs/…/kimlik/PK-9_on_kayit.md`, `PK-9.md`. `reference_differ.py`'ye dokunmaz.
- **Adımlar:**
  1. `surum.py` `surum_dizgileri(strings_json) -> list[str]`: yalnız sürüm biçimli dizgiler
     (`^\d+\.\d+(\.\d+)?[a-z]?$` ve `<ad> <sürüm>` / `<ad>-<sürüm>` kalıpları); kural listesi küçük ve yazılı.
  2. `basvuru_sec(hedef_olgu, aday_olgular) -> (aday, puan, ikinci)`: aday başına tekil dizgi çapası sayısı ve
     çapaların hedef dizgilerine oranı; en iyi ile ikinci arasında marj yoksa `belirsiz`. (Sürüm dizgisi eşitse
     doğrudan o aday.) Öğrenme yok.
  3. Ölçüm A (sürüm dizgisi): geliştirme seti + tabaka verileri; GT = paket sürümü (künye). Doğru / yanlış / yok.
  4. Ölçüm B (seçici): V3 sürüm merdiveni (aynı programın ≥ 3 sürümü): her hedef için adaylar arasından seçilen
     sürüm doğru mu.
  5. `PK-9.md`.
- **Kabul ölçütü / ön kayıt metni:**
  > PK-9 ön kaydı. Açık ölçüm. A: sürüm dizgisi çıkarımı — yanlış sürüm oranı ≤ %5 (yok saymak yanlış değildir);
  > kapsam raporlanır. B: seçici — seçim yaptığı durumlarda doğru sürüm ≥ %90 (n ≥ 10 ise), `belirsiz` oranı
  > raporlanır. İkisi de tutarsa PK-4'ün sürüm etiketi bu modülü kullanır; tutmazsa etiket `bilinmiyor` kalır.
- **Sınama ve mutasyon:** kalıp sınamaları (olumlu / olumsuz dizgiler: IP adresi, tarih, `1.0` gibi yalın sayılar
  bağlam yoksa sürüm sayılmaz); seçicide eşit puan → `belirsiz`. Mutantlar: m1 marj denetimi kalkar; m2 bağlamsız
  yalın sayı sürüm sayılır. Beklenen 2 / 2.
- **Ürüne girişi:** kitaplık; PK-4 köken kaydına yazmak için çağırır. Ad kararını etkilemez.

### PK-10 — Başvuru çalışma alanı üretimi ve `ref_db` bağlantısı

- **Amaç:** "doğru sürümün sembollü derlemesi" elde edildiğinde (analist verdi ya da ürünün var olan
  `ReferencePopulator`'ı derledi) onu çapalı eşleyicinin okuyabileceği biçimde saklamak ve `ref_db` yolunu
  (`_refdb_source`, `run_reference_differ`) yeni eşleyiciye bağlamak.
- **Olgu:** `karadul/reconstruction/reference_populator.py` (sqlite3, zlib; `allow_reference_download` arkasında)
  başvuruyu indirir, derler, Ghidra ile analiz eder ve `ReferenceDBEntry` olarak yalnız fonksiyon / dizgi / çağrı
  grafiği / CFG JSON'u saklar; çapalı eşleyici ayrıca `ghidra_xrefs.json` ve `pcode.jsonl` ister. Eşleşmeyi bugün
  `ReferenceDiffer` yapıyor (tmux'ta 366 / 769; PK-1 kapılıyor).
- **Dokunur:** yeni `karadul/reconstruction/kimlik/basvuru.py`; `karadul/pipeline/steps/_feedback_naming_refdiff.py`
  (var; PK-1'den sonra) ve `_feedback_naming_bindiff.py` `_refdb_source` (var; PK-4'ten sonra);
  `tests/test_pk10_basvuru.py`; `scripts/measurement/mutation_specs_pk10.json`; `docs/…/kimlik/PK-10_on_kayit.md`, `PK-10.md`.
- **Dokunmaz:** `reference_populator.py`'nin indirme / derleme mantığı ve ağ kapıları (`network.enabled`,
  `allow_reference_download`); `ReferenceDB` dizin biçimi (yanına yeni alt dizin eklenir, var olan dosyalar değişmez).
- **Adımlar:**
  1. `basvuru.py`: `BasvuruAlani` (ikili yolu, `static/` dizini, program, sürüm, derleyici künyesi, sha256) ve
     `alan_bul(yol) -> BasvuruAlani | None`: (a) Karadul çalışma alanı (`raw/` + `static/`), (b) `ref_db` girdisi
     + yanında `static/` (yeni), (c) yalnız JSON'lu eski `ref_db` girdisi → `eksik: ["xrefs", "pcode"]`.
  2. Başvuru analizi `--stage static` yeter (tur 1: eşleyicinin okuduğu olgu tam koşuyla aynı). `basvuru.py`
     `analiz_et(ikili, hedef_dizin)`: ürünün var olan statik aşamasını çağırır (yeni Ghidra sürücüsü yazılmaz;
     `reference_populator._analyze_with_ghidra` yerine ürün boru hattının `--stage static` eşdeğeri — çağrı biçimi
     `karadul/cli.py` `analyze` komutundan okunur ve `PK-10.md`'ye yazılır).
  3. `_refdb_source` ve `_match_against_db`: PK-4 bayrağı açıksa ve girdi `static/` taşıyorsa `kanal.basvuru_esle`;
     taşımıyorsa bugünkü yol (PK-1 kapılı) ve durum `eksik_basvuru_olgusu`.
  4. Sürüm: `BasvuruAlani.surum` ile hedefin sürümü (PK-9) karşılaştırılır; PK-4 adım 5'in etiketi buradan.
  5. Ölçüm: sette statik bağlı kitaplık kopyası olan tek temiz örnek zstd (PK-11); bu paket PK-11'in başvurusunu
     `BasvuruAlani` olarak kullanır ve ürün yolundan aynı sayıyı üretmelidir.
- **Kabul ölçütü:** (a) `alan_bul` üç biçimi doğru sınıflar; (b) PK-4'ün (i) ölçümü `reference_binary` yerine
  `ref_db` girdisi olarak verildiğinde aynı ad haritasını üretir (fark 0); (c) eksik olgulu girdide ad yazılmaz,
  durum yazılır; (d) ağ kapalıyken hiçbir indirme denenmez (var olan P-GÜV testleri yeşil).
- **Ön kayıt metni:**
  > PK-10 ön kaydı. Bağlantı paketidir. Beklenen: PK-4 (i) çıktısı ile `ref_db` yolundan üretilen ad haritası aynı
  > (fark 0); eski biçimli girdide yeni kanal 0 ad, durum `eksik_basvuru_olgusu`. PK-11 verisi geldiyse: zstd hedefinde
  > ürün yolu ile araştırma ölçümü (PK-11) arasındaki doğru ad farkı ≤ %5.
- **Sınama ve mutasyon:** sahte dizin ağaçlarıyla `alan_bul`; eski girdide yeni eşleyicinin çağrılmadığı; sürüm
  etiketinin köken kaydına yazıldığı. Mutantlar: m1 eksik olgu denetimi kalkar; m2 bayrak okunmaz; m3 sürüm
  karşılaştırması hep "aynı". Beklenen 3 / 3.
- **Ürüne girişi:** PK-4'ün bayrağının arkasında; yeni bayrak yok. İndirme ve derleme davranışı değişmez.

### PK-11 — Açık ölçüm: gömülü kitaplık kopyası (Berke'nin hipotezinin birinci kolunun asıl örneği)

- **Amaç:** bir programa statik gömülmüş kitaplık kodunu, kitaplığın dağıtımdaki sembollü derlemesinden tanımanın
  kesinliğini ve kapsamını ölçmek.
- **Olgu:** OLGU bütçesi: zstd ikilisinde `proje_kitapligi` (zstd'nin `lib/` dizini = libzstd) nüfusu 720, taban
  üründe doğru 0, yanlış 23. Tur 1'de bu kod için başvuru yoktu (`a1_pay`: zstd 919'un 919'u "set içinde başvurusu yok").
- **Veri:** V5 (Debian 13 arm64 `libzstd1` + `libzstd1-dbgsym`, zstd ikilisiyle aynı kaynak sürümü; aynı derleyici).
  İndirmeden önce kilit belgeleriyle ad kesişimi denetlenir (ÖLÇÜ P-Ö7'nin `tabaka_indir.py` süzgeci).
  redis'e gömülü `deps/lua` için başvuru liblua olurdu; **`lua` kilitli test setinin stres alt kümesinde**
  (`docs/arge/test_seti_kilidi.md` §2) → bu çift kilit açılana dek ölçülmez. `deps/hiredis` için aynı denetim yapılır.
- **Dokunur:** `scripts/measurement/kimlik_ciftler.py` (grup `gomulu_kitaplik`), `docs/…/kimlik/PK-11_on_kayit.md`,
  `PK-11.md`; veri `~/karadul_olcum/n2_tabaka/kitaplik/`. Ürün koduna dokunmaz.
- **Adımlar:**
  1. `libzstd.so.1`'in soyulmuş hâli (paketteki) + dbgsym → GT (`ks1_olc.gt_elf` düzeni: `x_*-dbgsym_*/usr/lib/debug/.build-id/…`).
  2. Ürün koşusu `--stage static` (1 Ghidra koşusu), `KARADUL_CACHE_DIR` koşuya özel.
  3. `kimlik_veri` köküne `debian13lib/libzstd` kimliği; grup: (debian/zstd/zstd → libzstd) tek yön (sorgu program,
     başvuru kitaplık).
  4. `kimlik_olc yayilim` (dört nokta) + `hata` + `tanik`; OLGU `kaynak_sinifi` başına (`proje_kitapligi` ↔ `program`).
  5. Ek: aynı ölçüm `BinaryDiffer` / `ReferenceDiffer` ile (`urun-yolu`), karşılaştırma satırı.
- **Kabul ölçütü:** ölçüm paketidir; künye tam, ön kayıtlı hükümler yazıldı.
- **Ön kayıt metni:**
  > PK-11 ön kaydı. Açık ölçüm; beklenen sayı yok, eşikler var. `proje_kitapligi` sınıfında (nüfus 720): (a) tam ad
  > kesinliği Wilson alt ≥ 0,95 → "kitaplık kopyası bu yolla ad alır (hat hedefi)"; ≥ 0,909 → "ad yazabilir";
  > altı → "kanıt satırı". (b) Kapsam (doğru / 720) raporlanır; ≥ %40 → "A2'nin kitaplık kolu için kullanılabilir".
  > (c) `program` sınıfında (zstd'nin kendi `programs/` kodu; başvuruda YOK) verilen ad sayısı: her biri yanlıştır
  > (çekimserlik sınaması); nüfusa oranı ≤ %2 → "başvuruda olmayan koda ad yakıştırmıyor". Karşılaştırma için
  > (beklenti değil): aynı derleyici, farklı program ölçümü tur 1'de 0,987–0,991, kapsam %48–56 (coreutils / gnulib).
- **Sınama ve mutasyon:** kod yok (grup tanımı); kilitli ad süzgeci sınaması PK-6'dakiyle aynı.
- **Ortak ölçüme girişi:** grup `kimlik_ciftler.py`'de kalıcı.

## 4. Veri istekleri (ana oturum Berke'ye sorar; KARARLAR A-4'ün kapsamına girip girmediğine ana oturum karar verir)

| # | Ne | Kaynak | Boyut | Neden | Hangi paket |
|---|---|---|---|---|---|
| V1 | Sürümü eşli, derleyicisi farklı **başka program** çiftleri: geliştirme setindeki Debian programlarının (tree, zstd, sqlite3, redis) aynı sürüm kaynak paketleri; macOS'ta Homebrew GCC 16 ve Apple clang ile yerel derleme (tur 1'deki `derle_gcc.sh` düzeni) | Debian kaynak arşivi (`.orig.tar.*`; sürüm dbgsym paket adından okunur: `python A/veri.py debian/<program>` çıktısındaki `kunye.debug` yolu, ör. `x_tmux-dbgsym_3.5a-3_arm64`) | indirilmeden bilinmiyor (dizinden okunup `PK-6_on_kayit.md`'ye yazılacak) | tur 1'in "aynı sürümde 0,99" sonucu yalnız tmux ve htop'ta; hipotezin genelliği | PK-6 (e), PK-7 H4 |
| V2 | ÖLÇÜ P-Ö6 tabaka C derlemeleri (indirme yok; kaynak diskte) | `~/karadul_olcum/n2_tabaka/c/` (P-Ö6 üretir) | — | clang tarafının iyileştirme merdiveni | PK-6 |
| V3 | Sürüm merdiveni: tmux ve htop'un Debian 12 dbgsym'leri — ÖLÇÜ P-Ö7 tabaka B ile aynı indirme; ek olarak aynı programların iki ara sürümü (snapshot.debian.org) | Debian arşivi / snapshot | Debian 13'teki karşılıkları: tmux `.debug` 2 258 632 bayt, htop 784 008 bayt (ölçüldü; `downloads/debian13` altında) | başvuru seçici: aday sürümler arasından doğru sürümü seçme | PK-9, PK-6 |
| V4 | x86-64 derlemeleri (ÖLÇÜ P-Ö7 tabaka A) | Debian 13 amd64 + dbgsym | P-Ö7'nin listesi | mimari farkı (tur 1'de ölçülemedi) | PK-6 |
| V5 | `libzstd1` + `libzstd1-dbgsym` (Debian 13 arm64; zstd ikilisiyle aynı kaynak paketi sürümü) | Debian arşivi | indirilmeden bilinmiyor (dizinden okunacak) | gömülü kitaplık kopyasının gerçek örneği (nüfus 720, bugün doğru 0) | PK-11, PK-10 |

- V2–V4 ÖLÇÜ hattının paketleriyle aynı veridir; ayrıca indirme istenmez, o paketlerin çıktısı beklenir.
- V1 ve V5 yeni isteklerdir. Kaynak yalnız dağıtımın resmî arşivi; sha256 dizinle doğrulanır; hiçbir indirilen
  dosya çalıştırılmaz (kaynak yalnız yerel kopyada derlenir; derleme çıktısı çalıştırılmaz, yalnız analiz edilir).
- Kilit denetimi: indirmeden önce program adları kilit belgelerindeki listelerle karşılaştırılır
  (`docs/arge/test_seti_kilidi.md`, `dogrulama_seti_kilidi.md`); `lua` (liblua) kilitli olduğu için istenmiyor.
- Tur 1'in ürettiği kalıcı veri (yeniden üretmek gerekmez): `K/gcc/` (tmux 3.8 `-O0` / `-O2` / `-O3`, htop 3.5.3
  GCC derlemeleri: kaynak kopyası, sembollü ve soyulmuş ikililer, GT, statik koşular), `K/ek/macsym/tmux`
  (sembollü Mac tmux analizi), `K/ek/macgnu2/` (Homebrew coreutils üçlüsünün a62f15e koşusu), `K/bsim/` (temiz BSim depoları).

## 5. Açık ölçümler (bu turda neden ölçülemedi)

| # | Ne | Neden ölçülemedi | Nerede ölçülecek |
|---|---|---|---|
| A1 | Mimari farkı (x86-64 ↔ AArch64) | elde çift yok; yerel çapraz derleme araç zinciri kurulu değil (indirme ister) | PK-6 (V4) |
| A2 | "Aynı sürümde 0,99" sonucunun tmux / htop dışı programlarda geçerliliği | sette aynı sürümün iki derlemesi yalnız kaynağı diskte olan iki program için üretilebildi | PK-6 (V1) |
| A3 | "Tek taraflı" sınıfın tam doğrulaması (3.5a kaynağıyla) | tmux 3.5a kaynağı diskte yok; kısmi denetim yapıldı (47 / 52 tutarlı; sürüm eşlenince 99 → 4) | gerekirse V3 kaynak paketleriyle; öncelik düşük (iki bağımsız ölçüm aynı yönde) |
| A4 | Gömülü kitaplık kopyası (zstd `lib/`, redis `deps/*`) | başvuru kitaplığının sembollü derlemesi sette yok | PK-11 (V5) |
| A5 | Derleyiciler arası kitaplık işaretleme kesinliği (C5) | tmux `compat/` 95 fonksiyon; sayı az | PK-11 + ÖLÇÜ P-Ö8 tabaka D (gnulib'li programlar) |
| A6 | Linux GCC ↔ macOS clang, **aynı sürüm** | Debian tmux 3.5a'nın kaynağı / 3.5a'nın clang derlemesi yok; tur 1 aynı sürüm ölçümünü macOS üstünde GCC ↔ clang ile yaptı (platform sabit) | PK-6 (V1: Debian'ın sürümünü macOS'ta derle ya da V3) |
| A7 | BSim yerel ↔ lite ad katkısı farkı (E5) | lite kipi bu turda koşulmadı; yalnız yerel kipin ad kesinliği ve süresi ölçüldü | onarım hattı (E5); `kimlik_olc bsim` aracı hazır |
| A8 | Ürün yolundan uçtan uca ad ölçümü (birleştirici, korunan ön adlar, ad geçerliliği dahil) | ürün koduna dokunulmadı; eşleyici araştırma betiği olarak ölçüldü | PK-4 adım 7 |
| A9 | İmza VT'nin bu çiftlerdeki kesinliği | P11 / P15b ölçtü (0 / 208; uygulanan ad farkı 0); yinelenmedi | — |
| A10 | C++ ikilileri | tam ad eşitliği tanımsız (ölçü dışı; `pzstd`) | ÖLÇÜ hattının ölçü tanımından sonra |

## 6. Riskler ve bilinmeyenler

1. **Tek program riski:** "aynı sürümde 0,99" sonucu tmux'un dört derlemesi ve htop'un bir derlemesiyle ölçüldü;
   ikisi de tablo ağırlıklı C uçbirim programı. Başka türde (kitaplık ağırlıklı, sayısal, C++) kapsam ve tablo
   kanıtının (v2) kazancı farklı olabilir. PK-6 (e) bunu sınar; o zamana dek kanal öntanımı kapalı.
2. **Aşırı uyum:** parametreler tek çiftte (htop 3.4.1 ↔ 3.5.3) ayarlandı; kural noktası ızgaranın kenarında.
   Taze çiftlerde tuttu, ama PK-4 yine tutucu noktayı kullanır.
3. **Başvuru bulunabilirliği:** yöntem aynı kaynağın sembollü bir derlemesini ister. Kapalı kaynak programın kendi
   kodunda yok; orada yalnız gömülü açık kaynak kitaplıklar için işe yarar (PK-11 bunu ölçer). Kapsam bütçesinde
   (A1) bu yol "kaynağı başka yerde bulunan kod" payına işler.
4. **Sürüm seçimi kritik:** yanlış sürümle ad kesinliği 0,99 → 0,94 (tmux), sürüm farkı büyüdükçe 0,87
   (coreutils 9.7 ↔ 9.12). PK-9 başarısız olursa kanal "sürüm bilinmiyor" satırlarıyla çalışır ve rapor adı
   "başvurunun sürümündeki ad" diye göstermek zorundadır (PK-4 adım 5).
5. **`lief` bağımlılığı:** tablo yuvası kanıtı `lief` ister (üründe isteğe bağlı); yoksa v2 sessizce v1'e inmemeli,
   durum yazmalı (PK-4 adım 2).
6. **Dosya çakışması:** `_feedback_naming_candidates.py`, `_feedback_naming_merger.py`, `config.py`,
   `naming_labels.py` ÖZ KOD ve ÖLÇÜ paketlerinin de hedefi olabilir; ana oturum üç hattın paketlerini bu dosyalarda
   sıraya koymalı. İşaretçi yuvası okuyucusu ÖZ KOD ÖK-4a ile ortak (`veri_sozcukleri.py`); tek modül kalmalı.
7. **GT'nin kendisi:** Mach-O GT'si `nm`'den; satır içine alınan statik fonksiyonların adı GT'de yok. "Satır içi" /
   "komşu" sınıfı GT'den dolaylı çıkarılıyor; `-O0` ↔ `-O2` çiftinde 50 → 93'e çıkması tanımı destekliyor ama
   kaynak düzeyinde doğrulanmadı.
8. **Ölçüm koşulları:** ek koşular yük altındaki makinede ve `--stage static` ile yapıldı; eşleyicinin okuduğu olgu
   tam koşuyla aynı (denetlendi), ama süre sayıları (BSim, koşu süreleri) hükümsüzdür.
