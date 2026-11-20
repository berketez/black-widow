# BAYRAK — bayrak ön paketi (KARARLAR A-19 a, A-13) — ilerleme

- Taban: `e996200` (main; `git merge --ff-only main` ile).
- Worktree: `/Users/apple/Black_Widow/.claude/worktrees/agent-a9659944b32ed01ff`; `karadul.__file__` worktree yolunu gösteriyor.
- Başlangıç: 2026-11-20 08:14 (`uptime` yük ortalaması 4,86 / 5,46 / 5,19).
- Ghidra koşusu yok (gönderim metni).

## Durum

- [x] 1. Envanter
- [ ] 2. Alanları ekle
- [ ] 3. `INERT_SETTINGS` + bağlama tablosu
- [ ] 4. `naming_labels.py` sabitleri
- [ ] 5. Testler
- [ ] 6. Davranış değişmedi kanıtı
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
