# BAYRAK — bayrak ön paketi (KARARLAR A-19 a, A-13) — ilerleme

- Taban: `e996200` (main; `git merge --ff-only main` ile).
- Worktree: `/Users/apple/Black_Widow/.claude/worktrees/agent-a9659944b32ed01ff`; `karadul.__file__` worktree yolunu gösteriyor.
- Başlangıç: 2026-11-20 08:14 (`uptime` yük ortalaması 4,86 / 5,46 / 5,19).
- Ghidra koşusu yok (gönderim metni).

## Durum

- [x] 1. Envanter
- [x] 2. Alanları ekle
- [x] 3. `INERT_SETTINGS` + bağlama tablosu
- [x] 4. `naming_labels.py` sabitleri
- [x] 5. Testler
- [x] 6. Davranış değişmedi kanıtı
- [ ] 7. Mutasyon

## 1. Envanter

Kaynaklar (hepsi `docs/arge/2026-11-19_mythos/` altında): `karsi/CAKISMA.md` §2.1, `kimlik/PLAN.md`, `ozkod/PLAN.md`,
`ustveri/PLAN.md`, `olcek/PLAN.md`, `hiz/PLAN.md`. `olcu/PLAN.md` `config.py`'ye alan eklemiyor (taranarak denetlendi).
Dalga numaraları `SONRAKI_OTURUM.md` §3'ten. "Plan satırı" = alanın tanımlandığı satır.

Öntanım kuralı (gönderim metni): yeni yöntem bayrağı **kapalı**; sayısal bütçe / eşik alanı bugünkü davranışı korur
("sınır yok" / "kapalı" anlamına gelen değer). Alanlar bu pakette okunmaz. "Plan öntanımı" sütunu bağlayan paketin
ölçümle önereceği değerdir; değiştirmek bağlayan paketin işidir (yama), bu paketin değil.

### 1.1 Alanlar (49)

| # | Alan (bölüm.alan) | Tür | Öntanım (bu paket) | Plan öntanımı | Anlamı | Bağlayacak | Dalga | Plan satırı |
|---|---|---|---|---|---|---|---|---|
| 1 | `binary_reconstruction.enable_anchored_reference_matching` | bool | False | False | başvuru verilince adlar `BinaryDiffer` yerine çapalı eşleyiciden | PK-4 | 3 | kimlik 289 |
| 2 | `binary_reconstruction.enable_separate_debug_naming` | bool | False | False | build-id ile eşleşen ayrık `.debug` dosyasından ad | PK-5 | 3 | kimlik 360 |
| 3 | `binary_reconstruction.debug_file_dirs` | list[str] | [] | (yok) | ayrık hata ayıklama dosyalarının aranacağı dizinler | PK-5 | 3 | kimlik 360 |
| 4 | `binary_reconstruction.anchored_reference_witness_gate` | bool | False | False | satır içi tanığı olan başvuru eşlemesi ad değil kanıt satırı yazar | PK-7 | 3 | kimlik 468 |
| 5 | `binary_reconstruction.oz_ad_verbatim` | bool | False | False | kanıt dizgisi tek tanımlayıcıysa ad dönüştürülmeden yazılır | ÖK-1 | 1 | ozkod 93 |
| 6 | `binary_reconstruction.oz_ad_uniqueness_gate` | bool | False | False | R1 teklik kapısı: tutmayan `oz_ad` adayı kanıt satırına iner | ÖK-2 | 2 | ozkod 234 |
| 7 | `binary_reconstruction.enable_unique_identifier_names` | bool | False | False | G1: fonksiyonun tek andığı tanımlayıcı dizgi ad olur | ÖK-3 | 3 | ozkod 267 |
| 8 | `binary_reconstruction.enable_record_affix_names` | bool | False | False | K1: kayıt tablosu ekinden ön ad | ÖK-4b | 3 | ozkod 305 |
| 9 | `binary_reconstruction.enable_module_prefix_evidence` | bool | False | False | komşu adlı fonksiyonlardan modül öneki kanıt satırı (ad yok) | ÖK-6 | 3 | ozkod 342 |
| 10 | `binary_reconstruction.enable_go_metadata_recovery` | bool | False | False | Go `pclntab` üretici adımı | P-ÜV1 (okur), P-ÜV6 (Faz 1'e ekler) | 2 | ustveri 146, 162, 363 |
| 11 | `binary_reconstruction.enable_objc_metadata_recovery` | bool | False | False | Objective-C yöntem listesi üretici adımı | P-ÜV2 (okur), P-ÜV6 | 2 | ustveri 191, 363 |
| 12 | `binary_reconstruction.enable_swift_metadata_recovery` | bool | False | False | Swift tip üst verisi üretici adımı | P-ÜV3 (okur), P-ÜV6 | 2 | ustveri 220, 363 |
| 13 | `binary_reconstruction.enable_go_pclntab_naming` | bool | False | False | Go `pclntab` ad kanalı | P-ÜV6 | 3 | ustveri 162, 363 |
| 14 | `binary_reconstruction.enable_objc_metadata_naming` | bool | False | False | Objective-C ad kanalı | P-ÜV6 | 3 | ustveri 191, 363 |
| 15 | `binary_reconstruction.enable_swift_metadata_naming` | bool | False | False | Swift erişim fonksiyonu ad kanalı | P-ÜV6 | 3 | ustveri 220, 363 |
| 16 | `binary_reconstruction.enable_macho_entry_main` | bool | False | False | Mach-O `LC_MAIN` girişine `main` adı | P-ÜV5 | 1 | ustveri 267, 285 |
| 17 | `binary_reconstruction.enable_go_metadata_integrity` | bool | False | False | Go tutarlılık damgası (`go_metadata_recovery` içinde) | P-ÜV6 | 3 | ustveri 315, 363 |
| 18 | `analysis.cozumleyici_takilma_sn` | int | 0 (kapalı) | 600 | aynı Ghidra çözümleyicisi bu kadar sn tepedeyse kapatılıp sürdürülür | ÖL-1 | 1 | olcek 174, 183 |
| 19 | `analysis.bekci_aralik_sn` | int | 15 | 15 | çözümleyici bekçisinin okuma aralığı (sn) | ÖL-1 | 1 | olcek 173, 183 |
| 20 | `timeouts.ghidra_adim` | int | 0 (sınırsız) | 3 600 | Ghidra köprüsünün her çıkarım adımına süre bütçesi (sn) | ÖL-2 | 2 | olcek 213, 223 |
| 21 | `bsim.bos_depoda_sorgu_atla` | bool | False | açık | depoda başka program yoksa BSim sorgusu atlanır | ÖL-2 | 2 | olcek 214, 223 |
| 22 | `bsim.ingest_butcesi_sn` | int | 0 (sınırsız) | 900 | BSim ingest süre bütçesi (sn) | ÖL-2 | 2 | olcek 215, 223 |
| 23 | `analysis.akis_yazimi` | bool | False | açık | büyük Ghidra çıktıları akış biçiminde dosyaya | ÖL-3 | 2 | olcek 246 |
| 24 | `analysis.istihbarat_butcesi_sn` | int | 0 (sınırsız) | 300 | ikili istihbarat aşaması süre bütçesi (sn) | ÖL-3b | 2 | olcek 260, 267 |
| 25 | `paket.yonetici` | bool | False | açık | `.app` paket yöneticisi (yineleme ayıklama, öncelik, bütçe, kuyruk) | ÖL-5a | 2 | olcek 289 |
| 26 | `paket.genis_kapsam` | bool | False | False | `Resources` / `Helpers` / `PlugIns` / `Frameworks/*.dylib` da kuyruğa | ÖL-5a | 2 | olcek 278, 289 |
| 27 | `paket.toplam_butce_sn` | int | 0 (sınırsız) | 7 200 | paket analizinin toplam süre bütçesi (sn) | ÖL-5a | 2 | olcek 280, 289 |
| 28 | `paket.bilesen_butce_sn` | int | 0 (sınırsız) | 3 600 | bileşen başına süre bütçesi (sn) | ÖL-5a | 2 | olcek 280, 289 |
| 29 | `paket.bilinen_bilesen` | bool | False | False | üçüncü taraf çalışma zamanını kimlikten tanıyıp ucuz katmanda bırak | ÖL-11 | 4 | olcek 358 |
| 30 | `kaynak.disk_on_denetim` | bool | False | açık | koşudan önce disk tahmini; yetmezse ret | ÖL-6 | 2 | olcek 300, 308 |
| 31 | `kaynak.disk_guvenlik_carpani` | float | 1.5 | 1,5 | boş alan < tahmin × çarpan ise ret | ÖL-6 | 2 | olcek 300, 308 |
| 32 | `kaynak.azami_bellek_orani` | float | 0.0 (kapalı) | 0,85 | süreç tepe belleği RAM'in bu oranını aşarsa kısmi bitiş | ÖL-6 | 2 | olcek 301, 308 |
| 33 | `reconstruct.ara_kopyalar` | bool | True (bugünkü) | "ölçümden sonra karar" | okuyucusu olmayan ara `.c` kopyaları yazılsın mı | ÖL-7 | 4 | olcek 329, 331 |
| 34 | `onbellek.ghidra_kosusu` (planda `onbellek.ghidra`; §1.3) | bool | False | False | sha256 anahtarlı Ghidra projesi + `ghidra_output` önbelleği | ÖL-9 | 3 | olcek 342, 344 |
| 35 | `onbellek.azami_gb` | float | 0.0 (sınır yok) | (yok) | önbelleğin disk sınırı (GB) | ÖL-9 | 3 | olcek 342 |
| 36 | `buyuk_ikili.tembel` | bool | False | False | büyük ikili kipi: decompile ve ad hattı yalnız seçilen fonksiyonlarda | ÖL-10 | 4 | olcek 351 |
| 37 | `buyuk_ikili.esik_mb` | int | 0 (eşik yok) | "ÖLÇ-2'den" | kipin devreye girdiği kod baytı eşiği (MB) | ÖL-10 | 4 | olcek 349 |
| 38 | `perf.ayrilmis_bellek_mb` | int | 0 | 0 | aynı belleği paylaşan başka süreç için ayrılan bellek (yığın formülü) | HZ-5 | 3 | hiz 119, 135 |
| 39 | `perf.decompile_verim_cekirdegi` | bool | False | False | decompile iş parçacığına verim çekirdekleri de katılsın (`V`) | HZ-5 | 3 | hiz 117, 135 |
| 40 | `perf.jvm_cds` | bool | False | açık (koşullu) | JVM AppCDS arşivi | HZ-5 adım 8 (koşullu) | 3 | hiz 130, 135 |
| 41 | `bsim.paralel_tarama` | bool | False | açık | BSim ingest / sorguda Ghidra'nın paralel taraması | HZ-2 | 2 | hiz 156 |
| 42 | `analysis.decompile_parti_boyu` | int | 0 (statik parçalama) | 8 | dinamik decompile dağıtımında parti boyu | HZ-3 | 2 | hiz 167, 178 |
| 43 | `analysis.dokum_tek_gecis` | bool | False | açık | çağrı grafı / xref / CFG dökümünde tek başvuru geçişi | HZ-4a | 2 | hiz 200 |
| 44 | `analysis.dokum_java_yardimci` | bool | False | False | döküm Java yardımcı sınıfıyla | HZ-4b (koşullu) | — (hiz planı: Dalga 6 koşullu) | hiz 211 |
| 45 | `perf.desen_onbellegi_ust_sinir` | int | 200 000 | 200 000 | düzenli ifade deseni önbelleğinin girdi üst sınırı | HZ-7a | 4 | hiz 245 |
| 46 | `perf.metin_onbellegi_mb` | int | 0 (kapalı) | `min(1024, bellek_mb // 16)` | `.c` metni önbelleğinin bayt sınırı (MB) | HZ-7b | 4 | hiz 265, 275 |
| 47 | `binary_reconstruction.pipeline_tek_tur_kosulu` | bool | False | False | ölçülmüş koşulda ikinci `feedback_loop` turu atlanır | HZ-7c (koşullu) | 4 | hiz 284 |
| 48 | `perf.ortak_havuz` | bool | False | False (ölçümden sonra açılır) | koşu boyunca tek süreç havuzu | HZ-7d | 4 | hiz 294 |
| 49 | `perf.forkserver` | bool | False | False | süreç havuzunda `forkserver` | HZ-7d | 4 | hiz 294 |

Yeni bölümler (planın adıyla): `paket` → `PaketConfig` (ÖL-5a), `kaynak` → `KaynakConfig` (ÖL-6), `onbellek` →
`OnbellekConfig` (ÖL-9), `buyuk_ikili` → `BuyukIkiliConfig` (ÖL-10), `reconstruct` → `ReconstructConfig` (ÖL-7; planda
sınıf adı yok, bölüm adından).

### 1.2 Plan öntanımından ayrılan alanlar (gerekçe: gönderim metninin öntanım kuralı)

- Planda "öntanım açık" olan yöntem bayrakları burada **kapalı**: `bsim.bos_depoda_sorgu_atla`, `analysis.akis_yazimi`,
  `paket.yonetici`, `kaynak.disk_on_denetim`, `perf.jvm_cds`, `bsim.paralel_tarama`, `analysis.dokum_tek_gecis`.
  Açmak, bağlayan paketin ölçümüyle (S8 / 119 eşitliği) ve yamayla olur.
- Bütçe / eşik alanlarında "sınır yok / kapalı" değeri: `analysis.cozumleyici_takilma_sn` 0 (planın kendi "0 = kapalı"
  tanımı), `bsim.ingest_butcesi_sn` 0, `analysis.istihbarat_butcesi_sn` 0 (planın "0 = sınırsız" tanımı),
  `kaynak.azami_bellek_orani` 0 (planın "0 = kapalı" tanımı), `analysis.decompile_parti_boyu` 0 (planın "0 = bugünkü
  statik parçalama" tanımı), `perf.metin_onbellegi_mb` 0 (planın "0 = kapalı" tanımı).
- Planda 0 anlamı tanımlanmamış bütçeler: `timeouts.ghidra_adim`, `paket.toplam_butce_sn`, `paket.bilesen_butce_sn`
  → 0 = **sınırsız** (aynı plandaki öbür bütçelerin sözleşmesi; en dar güvenli tanım: bugün bu sınırların hiçbiri yok).
  Bağlayan paket (ÖL-2, ÖL-5a) bu anlamı uygular.
- Değeri yalnız bir yöntem açıkken anlam taşıyan alanlarda planın değeri korundu: `analysis.bekci_aralik_sn` 15,
  `kaynak.disk_guvenlik_carpani` 1,5, `perf.desen_onbellegi_ust_sinir` 200 000 (HZ-7a çıktıyı değiştirmez),
  `perf.ayrilmis_bellek_mb` 0.

### 1.3 Planda tanımı olmayan ya da çelişen alanlar (uydurulmadı; en dar güvenli tanım)

1. **`onbellek.ghidra` → `onbellek.ghidra_kosusu`.** Plan adı (`ghidra`) `tests/test_p15a_etkisiz.py`'nin okuma
   denetiminde (alan adıyla `.ghidra` arar) `timeouts.ghidra` okumalarıyla çakışıyor: kayda girerse
   `test_inert_registry_is_accurate` kırmızı, girmezse alan YAML'da yazılınca etkisizlik uyarısı çıkmaz (MEK-05'in
   kapattığı kusur). Denetim betiği: 49 adın 48'i serbest, tek çakışma `ghidra` (5 dosyada okunuyor). Ad, anlamı
   değişmeden uzatıldı; ÖL-9 bu adı kullanır.
2. **`reconstruct.ara_kopyalar`** türü planda yok, öntanımı "ölçümden sonra karar". Bool; `True` = bugünkü davranış
   (ara kopyalar yazılır), `False` = yeni yöntem (okuyucusu olmayan kopya yazılmaz). Adın anlamıyla "yeni yöntem kapalı"
   kuralı bu yönde aynı sonucu verir.
3. **`onbellek.azami_gb`** öntanımı planda yok: 0 = sınır yok; önbellek kapalıyken okunmaz. ÖL-9 önbelleği açmadan önce
   ölçülmüş değeri verir (açık önbellekte sınırsız disk kullanımı istenmez; bağlama tablosunda not).
4. **`buyuk_ikili.esik_mb`** öntanımı "ÖLÇ-2'den": 0 = eşik yok, kip hiçbir ikilide devreye girmez (bugünkü davranış).
   ÖL-10 tasarım turunda (A-18; OL10 paketi `olcek/OL10_TASARIM.md`) alanlar değişebilir.
5. **`pipeline_tek_tur_kosulu`** planda bölümsüz: `binary_reconstruction` (aynı kavramın alanları
   `pipeline_iterations`, `pipeline_convergence_threshold` orada).
6. **ÖK-2 / ÖK-3 / ÖK-4b / ÖK-6 / PK-7** bayraklarının bölümü planda yazılı değil: `binary_reconstruction` (c_namer ve
   ad kanalı bayraklarının hepsi orada; ÖK-1 açıkça orayı söylüyor).
7. **Tür seçimleri** (planda yok): süreler `int` saniye (mevcut `Timeouts` gibi), oranlar ve çarpanlar `float`,
   `onbellek.azami_gb` `float` (kesirli GB), `buyuk_ikili.esik_mb` `int`.
8. **Yerleşim:** ÖK-1 alanı "`enable_subchannel_silencing` satırının altına" diyor; burada bütün yeni alanlar her
   bölümün sonunda tek blokta (en az çakışma). Anlam aynı.

### 1.4 Bu pakete alınmayanlar (alan değil ya da adı tanımsız)

- **HZ-5 donanım künyesi** (`DonanimKunyesi` dataclass + `donanim_kunyesi()`, `hiz` 123) ve formül sabitleri
  (`YIGIN_OOPS_TAVAN_MB`, `YIGIN_ORAN`, `REZERV_MB`, `YIGIN_TABAN_MB`, `ISCI_*`): YAML ayarı değil; algılama kodu
  `_detect_cpu_cores` / `_detect_available_memory_mb` / `GHIDRA_HEAP_MB`'nin (var olan davranış) değişmesiyle birlikte
  yazılır. Gönderim metni bunu açıkça dışarıda bırakıyor ("HZ-5'in işçi / JVM yığını formülleri bu paketin işi
  DEĞİL"). HZ-5'in `config.py` yaması yine gerekecek; yalnız üç `perf.*` alanı buradan hazır.
- **PK-5** "dosya boyutu üst sınırı (öneri 512 MB) ve süre sınırı": ad yok, ayar mı sabit mi belirtilmemiş.
- **PK-4 / PK-7** eşleme noktası (`TUTUCU_V2`): planda kanal modülünün öntanımı, ayar değil.
- **ÖL-10** seçim sayısı ("ör. ilk 5 000 fonksiyon; kural ön kayıtlı"): ad yok; tasarım turunda belirlenecek.
- **HZ-7c** koşulunun eşiği (`k`): "koşul ölçümden önce yazılmaz".
- Onarım paketleri (P03b, P08b, P10b, P23, P24): `config.py`'yi "dokunmaz / yama" diye anıyor (CAKISMA §1); önceden
  adı verilmiş alan yok.
- ÖLÇÜ planı: `config.py` alanı yok.

### 1.5 Ad eşiğini başka yerde tanımlayan kod (`grep -rn "0\.909\|AD_ESIGI" karadul scripts`; değiştirilmedi)

- `scripts/arge/ustveri/tablo.py:186` — `w[0] >= 0.909` (araştırma betiği; üst veri kanal tablosu). İleride
  `naming_labels.AD_ESIGI`'yi içe aktarmalı (sahibi ÜST VERİ hattı; bu pakette değiştirilmedi).
- `scripts/run_mock_benchmark.py:36,48,51` — `0.909` / `0.9091` bir F1 değeri; eşikle ilgisi yok.
- `karadul/` altında eşiği tanımlayan kod yok.

## 2. Alanlar eklendi (`karadul/config.py`)

- Var olan bölümlerin sonuna tek blok (`# --- Bayrak ön paketi (KARARLAR A-19 a) ...` başlığıyla): `timeouts` 1,
  `analysis` 7, `binary_reconstruction` 18, `bsim` 3, `perf` 7 alan.
- Yeni bölümler (dataclass + `Config` alanı): `paket` (`PaketConfig`, 5), `kaynak` (`KaynakConfig`, 3), `reconstruct`
  (`ReconstructConfig`, 1), `onbellek` (`OnbellekConfig`, 2), `buyuk_ikili` (`BuyukIkiliConfig`, 2). YAML yükleyici
  bölümleri `Config`'in dataclass alanlarından türettiği için (`_config_sections`) yükleme, tür denetimi ve bilinmeyen
  anahtar hatası yeni bölümlerde ek kod olmadan çalışıyor.
- Her alan: üstte tek satır Türkçe açıklama, satırda `# ETKİSİZ: <paket> bağlayacak (INERT_SETTINGS)`.
- Toplam 49 alan (envanterle aynı; denetim: işaretli alan 49, bekleyen INERT kaydı 49, ad kümeleri eşit).
- Kalem 2 ve 3 tek commit: alanlar INERT kaydı olmadan eklenirse `test_p15a_etkisiz::test_every_unread_field_is_registered`
  kırmızı kalırdı (ara commit kırık olmasın diye).

## 3. `INERT_SETTINGS` ve bağlama tablosu

- Yardımcı `_pending_binding(paket)` gerekçe metnini üretir: "henüz hiçbir kod okumuyor: alan önceden eklendi (bayrak ön
  paketi), <paket> bağlayacak". YAML'da yazılırsa `config validate` ve `analyze` bunu "etkisiz" uyarısı olarak basar.
- `INERT_SETTINGS`'in sonunda tek blok; **alan başına tek satır**, bağlayan pakete göre gruplu (her grubun üstünde
  `# <paket> (Dalga N)` yorum satırı: paketlerin silme yamaları birbirine bitişmesin diye).
- Bağlayan paket **iki satır** değiştirir, ikisi de `config.py`'de, ikisi de tek satır (yamayı ana oturum uygular):
  1. aşağıdaki tablodaki INERT satırını siler;
  2. alan satırındaki `# ETKİSİZ: <paket> bağlayacak (INERT_SETTINGS)` yorumunu kaldırır (gerekirse öntanımı plan
     değerine çeker — §1.1 "Plan öntanımı" sütunu; öntanım değişikliği bağlayan paketin ölçümüyle).
  `tests/test_bayrak_on_paketi.py` bu iki satırın birlikte değiştiğini denetler (biri kalırsa kırmızı); bağlanan alanın
  öntanım / tür kilidi kalkar, bağlayan paket kendi testinde kilitler. `tests/test_p15a_etkisiz.py` ise alan okunmaya
  başlayınca INERT satırının silinmesini zorlar (`test_inert_registry_is_accurate`; `getattr(…, "<ad>")` dizgisi de
  okuma sayılır).
- **Not (ÜST VERİ):** P-ÜV1 / P-ÜV2 / P-ÜV3 üretici adımları bayrağı `getattr` ile okuyacak (plan ustveri 146) →
  `test_p15a` o pakette INERT satırını sildirir; ama adımlar Faz 1 listesine ancak P-ÜV6'da girer. P-ÜV1–3 ile P-ÜV6
  arasında alan "okunuyor" görünür ama ürün akışında etkisizdir ve YAML uyarısı da çıkmaz. Ana oturum bu aralığı kısa
  tutmalı ya da P-ÜV1–3'ün adım dosyası Faz 1'e girene kadar ayrı dalda beklemeli.
- **Not (P-ÜV4):** var olan `binary_reconstruction.enable_rtti_recovery` (INERT'te) için aynı durum: P-ÜV4'ün
  `rtti_recovery` adımı bayrağı okursa satırı P-ÜV6 değil P-ÜV4 silmek zorunda kalır (plan "P-ÜV6'da kaldırılır" diyor).
- Koşullu alanlar (`perf.jvm_cds` HZ-5 adım 8, `binary_reconstruction.pipeline_tek_tur_kosulu` HZ-7c,
  `analysis.dokum_java_yardimci` HZ-4b): paket açılmaz ya da "tutmadı" diye kapanırsa alan INERT'te kalır (silinmez:
  kapsam küçültülmez; uyarı gerçeği söyler).

### 3.1 Bağlama tablosu (alan → bağlayacak paket → dalga → silinecek INERT satırı)

Tablo `config.py`'den betikle üretildi (49 satır). Dalga `SONRAKI_OTURUM.md` §3'ten; "—" = koşullu, dalgası yok.

| Alan | Bağlayacak | Dalga | Silinecek INERT satırı |
|---|---|---|---|
| `binary_reconstruction.oz_ad_verbatim` | ÖK-1 | 1 | `"binary_reconstruction.oz_ad_verbatim": _pending_binding("ÖK-1"),` |
| `binary_reconstruction.enable_macho_entry_main` | P-ÜV5 | 1 | `"binary_reconstruction.enable_macho_entry_main": _pending_binding("P-ÜV5"),` |
| `analysis.cozumleyici_takilma_sn` | ÖL-1 | 1 | `"analysis.cozumleyici_takilma_sn": _pending_binding("ÖL-1"),` |
| `analysis.bekci_aralik_sn` | ÖL-1 | 1 | `"analysis.bekci_aralik_sn": _pending_binding("ÖL-1"),` |
| `binary_reconstruction.oz_ad_uniqueness_gate` | ÖK-2 | 2 | `"binary_reconstruction.oz_ad_uniqueness_gate": _pending_binding("ÖK-2"),` |
| `binary_reconstruction.enable_go_metadata_recovery` | P-ÜV1 | 2 | `"binary_reconstruction.enable_go_metadata_recovery": _pending_binding("P-ÜV1"),` |
| `binary_reconstruction.enable_objc_metadata_recovery` | P-ÜV2 | 2 | `"binary_reconstruction.enable_objc_metadata_recovery": _pending_binding("P-ÜV2"),` |
| `binary_reconstruction.enable_swift_metadata_recovery` | P-ÜV3 | 2 | `"binary_reconstruction.enable_swift_metadata_recovery": _pending_binding("P-ÜV3"),` |
| `timeouts.ghidra_adim` | ÖL-2 | 2 | `"timeouts.ghidra_adim": _pending_binding("ÖL-2"),` |
| `bsim.bos_depoda_sorgu_atla` | ÖL-2 | 2 | `"bsim.bos_depoda_sorgu_atla": _pending_binding("ÖL-2"),` |
| `bsim.ingest_butcesi_sn` | ÖL-2 | 2 | `"bsim.ingest_butcesi_sn": _pending_binding("ÖL-2"),` |
| `bsim.paralel_tarama` | HZ-2 | 2 | `"bsim.paralel_tarama": _pending_binding("HZ-2"),` |
| `analysis.akis_yazimi` | ÖL-3 | 2 | `"analysis.akis_yazimi": _pending_binding("ÖL-3"),` |
| `analysis.dokum_tek_gecis` | HZ-4a | 2 | `"analysis.dokum_tek_gecis": _pending_binding("HZ-4a"),` |
| `analysis.decompile_parti_boyu` | HZ-3 | 2 | `"analysis.decompile_parti_boyu": _pending_binding("HZ-3"),` |
| `analysis.istihbarat_butcesi_sn` | ÖL-3b | 2 | `"analysis.istihbarat_butcesi_sn": _pending_binding("ÖL-3b"),` |
| `paket.yonetici` | ÖL-5a | 2 | `"paket.yonetici": _pending_binding("ÖL-5a"),` |
| `paket.genis_kapsam` | ÖL-5a | 2 | `"paket.genis_kapsam": _pending_binding("ÖL-5a"),` |
| `paket.toplam_butce_sn` | ÖL-5a | 2 | `"paket.toplam_butce_sn": _pending_binding("ÖL-5a"),` |
| `paket.bilesen_butce_sn` | ÖL-5a | 2 | `"paket.bilesen_butce_sn": _pending_binding("ÖL-5a"),` |
| `kaynak.disk_on_denetim` | ÖL-6 | 2 | `"kaynak.disk_on_denetim": _pending_binding("ÖL-6"),` |
| `kaynak.disk_guvenlik_carpani` | ÖL-6 | 2 | `"kaynak.disk_guvenlik_carpani": _pending_binding("ÖL-6"),` |
| `kaynak.azami_bellek_orani` | ÖL-6 | 2 | `"kaynak.azami_bellek_orani": _pending_binding("ÖL-6"),` |
| `binary_reconstruction.enable_separate_debug_naming` | PK-5 | 3 | `"binary_reconstruction.enable_separate_debug_naming": _pending_binding("PK-5"),` |
| `binary_reconstruction.debug_file_dirs` | PK-5 | 3 | `"binary_reconstruction.debug_file_dirs": _pending_binding("PK-5"),` |
| `binary_reconstruction.enable_go_pclntab_naming` | P-ÜV6 | 3 | `"binary_reconstruction.enable_go_pclntab_naming": _pending_binding("P-ÜV6"),` |
| `binary_reconstruction.enable_objc_metadata_naming` | P-ÜV6 | 3 | `"binary_reconstruction.enable_objc_metadata_naming": _pending_binding("P-ÜV6"),` |
| `binary_reconstruction.enable_swift_metadata_naming` | P-ÜV6 | 3 | `"binary_reconstruction.enable_swift_metadata_naming": _pending_binding("P-ÜV6"),` |
| `binary_reconstruction.enable_go_metadata_integrity` | P-ÜV6 | 3 | `"binary_reconstruction.enable_go_metadata_integrity": _pending_binding("P-ÜV6"),` |
| `binary_reconstruction.enable_anchored_reference_matching` | PK-4 | 3 | `"binary_reconstruction.enable_anchored_reference_matching": _pending_binding("PK-4"),` |
| `binary_reconstruction.anchored_reference_witness_gate` | PK-7 | 3 | `"binary_reconstruction.anchored_reference_witness_gate": _pending_binding("PK-7"),` |
| `binary_reconstruction.enable_record_affix_names` | ÖK-4b | 3 | `"binary_reconstruction.enable_record_affix_names": _pending_binding("ÖK-4b"),` |
| `binary_reconstruction.enable_unique_identifier_names` | ÖK-3 | 3 | `"binary_reconstruction.enable_unique_identifier_names": _pending_binding("ÖK-3"),` |
| `binary_reconstruction.enable_module_prefix_evidence` | ÖK-6 | 3 | `"binary_reconstruction.enable_module_prefix_evidence": _pending_binding("ÖK-6"),` |
| `onbellek.ghidra_kosusu` | ÖL-9 | 3 | `"onbellek.ghidra_kosusu": _pending_binding("ÖL-9"),` |
| `onbellek.azami_gb` | ÖL-9 | 3 | `"onbellek.azami_gb": _pending_binding("ÖL-9"),` |
| `perf.ayrilmis_bellek_mb` | HZ-5 | 3 | `"perf.ayrilmis_bellek_mb": _pending_binding("HZ-5"),` |
| `perf.decompile_verim_cekirdegi` | HZ-5 | 3 | `"perf.decompile_verim_cekirdegi": _pending_binding("HZ-5"),` |
| `perf.jvm_cds` | HZ-5 | 3 | `"perf.jvm_cds": _pending_binding("HZ-5"),` |
| `buyuk_ikili.tembel` | ÖL-10 | 4 | `"buyuk_ikili.tembel": _pending_binding("ÖL-10"),` |
| `buyuk_ikili.esik_mb` | ÖL-10 | 4 | `"buyuk_ikili.esik_mb": _pending_binding("ÖL-10"),` |
| `reconstruct.ara_kopyalar` | ÖL-7 | 4 | `"reconstruct.ara_kopyalar": _pending_binding("ÖL-7"),` |
| `paket.bilinen_bilesen` | ÖL-11 | 4 | `"paket.bilinen_bilesen": _pending_binding("ÖL-11"),` |
| `perf.desen_onbellegi_ust_sinir` | HZ-7a | 4 | `"perf.desen_onbellegi_ust_sinir": _pending_binding("HZ-7a"),` |
| `perf.metin_onbellegi_mb` | HZ-7b | 4 | `"perf.metin_onbellegi_mb": _pending_binding("HZ-7b"),` |
| `binary_reconstruction.pipeline_tek_tur_kosulu` | HZ-7c | 4 | `"binary_reconstruction.pipeline_tek_tur_kosulu": _pending_binding("HZ-7c"),` |
| `perf.ortak_havuz` | HZ-7d | 4 | `"perf.ortak_havuz": _pending_binding("HZ-7d"),` |
| `perf.forkserver` | HZ-7d | 4 | `"perf.forkserver": _pending_binding("HZ-7d"),` |
| `analysis.dokum_java_yardimci` | HZ-4b | — | `"analysis.dokum_java_yardimci": _pending_binding("HZ-4b"),` |

## 4. `karadul/core/naming_labels.py`: ad eşiği tek yerde

- Dosyanın sonuna iki sabit (var olan satır değişmedi; `MEASURED_PRE_NAME_PRECISION` dahil):
  `MALIYET_ORANI_L: int = 10`, `AD_ESIGI: float = MALIYET_ORANI_L / (MALIYET_ORANI_L + 1)` (= 10 / 11 = 0,909090…).
  Ana oturum hükmü (2026-11-20): A-13'teki "0,909" bu kesrin yuvarlanmış yazımı; sabit kesirle tanımlı.
- Belge dizgisi (sabitin altındaki dizgi): A-2 / A-13 / A-14 kuralı — Wilson %95 alt sınırı ≥ `AD_ESIGI`, örnek düzeyi,
  yön başına, en az 3 bağımsız programda ölçülmüş; şartı sağlamayan kanal kanıt satırı yazar ya da bayrak arkasında;
  `1 − e / L` (0,900) kullanılmaz; var olan ön ad kanalları geriye dönük susturulmaz.
- Yerleşim: dosya sonu. PK-4 / ÖK-4b `MEASURED_PRE_NAME_PRECISION`'a, P-ÜV6 etiket sözlüğüne satır ekleyecek;
  yeni satırlar onların değiştireceği yerlere bitişik değil.
- Eşiği başka yerde yazan kod: §1.5 (`scripts/arge/ustveri/tablo.py:186` `0.909`; değiştirilmedi).
- Doğrulama: `naming_labels`'ı içe aktaran 12 test dosyası 199 geçti.

## 5. Testler: `tests/test_bayrak_on_paketi.py` (160 test)

| Grup | Ne denetler | Sayı |
|---|---|---|
| (a) | 49 alan var; **bağlanmamışken** tür (`_field_type_hints`) ve öntanım (değer + tam tür: `False` ≠ `0`, `0` ≠ `0.0`) envanterdeki gibi; yeni bölümlerin sınıf adı planınki | 49 + 2 |
| (b) | bağlanmamış alan INERT'te, gerekçe `_pending_binding(<paket>)`, satırda `# ETKİSİZ: <paket> bağlayacak`; bağlanmışsa işaret de kalkmış olmalı; `_pending_binding` gerekçeli her kayıt envanterde | 49 + 2 |
| (c) | boş YAML: yeni alanlar dışındaki görünüm `Config()` ile aynı, yeni alanlar öntanımda, `yaml_keys` boş, uyarı yok; depodaki örnek ayar dosyası (`docker/measurement/karadul.yaml`): `yaml_keys` = dosyanın anahtarları, görünüm = öntanım + dosyanın değerleri (var olan `_coerce_value` ile), yeni anahtar uyarısı yok | 2 |
| (d) | her yeni alana YAML'dan öntanım dışı değer → alan değişir, `yaml_keys`'te, bağlanmamışsa paket adlı "etkisiz" uyarısı; beş yeni bölüm tek dosyada; yeni bölümde tür hatası, bilinmeyen anahtar (öneriyle), bool dizgi hatası; `config validate` CLI yeni alanı "etkisiz" basıyor | 49 + 3 |
| (e) | `MALIYET_ORANI_L == 10` (int); `AD_ESIGI == L / (L + 1) == 10 / 11`; yuvarlanmış değil (`> 0.909`, `≠ 0.9`); belge dizgisi A-2 / A-13 / A-14 kuralını yazıyor | 4 |

- **Bağlama dostu:** tür / öntanım kilidi alan INERT'teyken geçerli; bağlayan paket INERT satırını ve `# ETKİSİZ`
  yorumunu birlikte kaldırınca test kendiliğinden uyar (bu dosyaya dokunması gerekmez); yalnız birini kaldırırsa
  kırmızı.
- **Eski kodda kırmızı:** taban `e996200`'ün `config.py` + `naming_labels.py`'siyle 159 kaldı / 1 geçti (yalnız
  envanter sayımı); yeni kodla 160 geçti. Dosyalar geri alındı (`git status` temiz).
- (c) için not: "önce ↔ sonra" eşitliği kalıcı testte değil (§6'da taban koduyla bir kez karşılaştırıldı); kalıcı bir
  anlık görüntü, sonraki paketlerin meşru öntanım değişikliklerinde (ÖL-1, HZ-5 …) bu dosyayı değiştirmeyi zorlardı.

## 6. Davranış değişmedi kanıtı

### 6.1 Taban ↔ yeni ayar karşılaştırması (bir defalık betik; Ghidra yok)

Taban `e996200`'ün `karadul/config.py` ve `karadul/core/naming_labels.py`'si ayrı modül olarak yüklendi, yeni ağacınkiyle
karşılaştırıldı (betik `scratchpad/taban_karsilastir.py`; `KARADUL_SIG_DATA_DIR` sabit — `data_root` öntanımı modül
dosyasının yerine bağlı olduğu için; `PYTHONPATH` worktree — betik başka dizinden koşunca `karadul` ana ağaçtan
yükleniyordu, ilk koşu bu yüzden geçersiz sayıldı).

| Denetim | Boş YAML | `docker/measurement/karadul.yaml` |
|---|---|---|
| Var olan alan (bölüm.alan) | 237 | 237 |
| Değeri farklı | 0 | 0 |
| Türü farklı | 0 | 0 |
| Eksik | 0 | 0 |
| Eklenen | 49 | 49 |
| Bölüm içi alan sırası bozulan | 0 | 0 |
| `yaml_keys` eşit | evet | evet |
| Etkisizlik uyarıları eşit | evet | evet |

- Bölümler: eski 18 aynı sırada başta; sonda 5 yeni (`paket`, `kaynak`, `reconstruct`, `onbellek`, `buyuk_ikili`).
- `INERT_SETTINGS`: eski 54 kaydın hiçbiri değişmedi; 54 → 103 (+49).
- Modül düzeyi sabitler: yalnız `INERT_SETTINGS` (büyüdü), `_TYPE_HINT_CACHE` (önbellek içeriği) ve `logger` (nesne
  kimliği) farklı; `GHIDRA_HEAP_MB`, `CPU_PERF_CORES` vb. aynı.
- `naming_labels`: var olan her ad aynı değerde; yeni adlar yalnız `AD_ESIGI`, `MALIYET_ORANI_L`.
- `git diff e996200 -- karadul/config.py karadul/core/naming_labels.py`: yalnız ekleme satırları (silinen / değişen 0).

### 6.2 Yeni alanlar hiçbir yerde okunmuyor

- `grep -rlw --include=*.py <ad> karadul ui scripts` (`karadul/config.py` hariç), 49 ad: 47 adda isabet yok. İki isabet
  okuma değil: `ghidra_adim` → `scripts/arge/hiz/taban_ayrinti.py:52`, `zaman_cizelgesi.py:363,391` (zaman çizelgesi
  JSON'unda sözlük anahtarı; ayar nesnesiyle ilgisi yok); `tembel` → `karadul/decompilers/ghidra_backend.py:40`,
  `ui/server.py:181` (Türkçe yorum sözcüğü).
- Kod tarafında mekanik denetim: `tests/test_p15a_etkisiz.py::test_inert_registry_is_accurate` (kayıttaki hiçbir alan
  `karadul/` ya da `ui/` altında `.ad` ya da `getattr(…, "ad")` ile okunmuyor) yeşil.

### 6.3 Testler

- `tests/test_p15a_etkisiz.py`, `test_p15b_etkisiz_bayraklar.py`, `test_config_*.py`, `test_p17_ayar.py` ve öbür
  `test_p15a_*.py`: 140 geçti (kalem 2-3'ten sonra); `naming_labels`'ı içe aktaran 12 dosya: 199 geçti (kalem 4'ten
  sonra); `tests/test_bayrak_on_paketi.py`: 160 geçti.
- Tam takım: §8'de (sonda bir kez).
