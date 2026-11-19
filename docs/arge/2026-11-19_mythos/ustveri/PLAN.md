# ÜST VERİ hattı — plan (tur 1 sonrası, 2026-11-19)

Bu belge kendi başına uygulanabilir olacak biçimde yazıldı: uygulayan Opus ajanları bu turun oturumunu görmeyecek. Kanıt ve sayılar `BULGULAR.md`'de, günlük `DEFTER.md`'de. Araştırma betikleri `scripts/arge/ustveri/`, çıktıları `~/karadul_olcum/runs/arge-2026-11-19/ustveri/` (aşağıda `$V`).

## 0. Bir bakışta

**Hat:** ÜST VERİ (soru kimlikleri A3, I2, I4; yayın kapısı G4).

**Hipotez (bu turdan sonra).** Go, Objective-C, Swift ve C++ taşıyan ikililerde fonksiyon adının bir kısmı ikilinin içinde yazılıdır ve Ghidra'ya gerek kalmadan, biçim belgesine göre okunabilir. Go ve ObjC'de bu "tam ad"dır; Swift ve C++'ta "tip adı + yuva sırası"dır. Okunan ad derleyicinin yazdığı hâliyle doğrudur, ama ad metni çalışma için zorunlu olmadığından **doğrulanamaz**; bu yüzden ayrı bir etiketle yazılmalıdır.

**Literatürün beklediği cevap (yasak):** "üst veri güvenilirdir, oku ve yaz"; "Mac'te ad sorunu çözülmüş sorundur".

**Aykırı öncüller ve hüküm (ölçüldü):**

| Öncül | Hüküm | Sayı |
|---|---|---|
| Gerçek uygulamada doğru adın çoğu üst veriden gelir | Go'da tuttu; Swift / C++ / C'de tutmadı | Ollama uygulaması 10 751 / 12 952 (%83,0); Go araçları %92,2–%100; Rectangle (Swift) %26,5; C++ ve C 0 |
| Üst verinin bir kısmı zorunlu, bir kısmı serbest metin | tuttu | Bozma deneyi: ikinci kaynağı olmayan fonksiyonda ad değişikliği 0 / 134, 0 / 116; tutarlı sahtecilik 0 / 86, 0 / 451 |
| Mach-O'da `LC_MAIN` girişi zaten `main` | tuttu | GT'li 8 / 8; Homebrew 1 169 / 1 169; ürün 0 / 8 |

**Ürünün bugünkü durumu (ölçüldü):** Go kanalı `nm` sembollerini okuyor, soyulmuş ikilide 0–2 fonksiyon; `GoBinaryAnalyzer` `strings` + düzenli ifadeye düşüyor (adres yok); `cpp_rtti.py` `_ZTI` / `_ZTV` sembolü ister, soyulmuş ikilide vtable 0; ObjC ve Swift üst verisini okuyan kod yok; Mach-O'da `main` 0 / 8.

**Paketler:**

| Paket | İş | Önkoşul |
|---|---|---|
| P-ÜV0 | İkili görüntü okuyucu (Mach-O zincirli düzeltme; ELF yeniden konumlama) | — |
| P-ÜV1 | Go `pclntab` okuyucu + üretici adım (Go 1.18–1.27) | P-ÜV0 |
| P-ÜV2 | Objective-C yöntem listesi okuyucu + üretici adım | P-ÜV0 |
| P-ÜV3 | Swift tip üst verisi okuyucu + üretici adım | P-ÜV0 |
| P-ÜV4 | C++ RTTI sembolsüz tarama + üretici adım (IMZA-16) | P-ÜV0 |
| P-ÜV5 | Mach-O `main` (`LC_MAIN` girişi) | — |
| P-ÜV7 | Go tutarlılık denetimi (I4) | P-ÜV1 |
| P-ÜV8 | Ölçüm birimi ve kabul ölçümü (sembollü ikiliden GT) | P-ÜV0–4 (kanal düzeyi); P-ÜV6 (ürün düzeyi) |
| P-ÜV6 | Kanal bağlama, bayraklar, etiket ve güven kuralı, adım kaydı | P-ÜV1, 2, 3, 4, 5, 7 main'de |
| P-ÜV9 | Açık ölçümler (Ghidra adları, tohumlama kararı, ELF / PE) | gösteri koşusu bitmiş; P-ÜV6 |

**Sıra (aynı anda en çok 4 ajan; dosya kümeleri dalga içinde ayrık):**

```
Dalga 0:  P-ÜV0                      (tek ajan; öbürleri bunun arayüzüne yaslanır)   +  P-ÜV5 (stages.py; ayrık)
Dalga 1:  P-ÜV1, P-ÜV2, P-ÜV4        (yalnız yeni dosya)                              +  P-ÜV8 kalem 1–3 (ölçüm seti)
Dalga 2:  P-ÜV3, P-ÜV7               (yalnız yeni dosya)                              +  P-ÜV8 kalem 4 (kanal düzeyi kabul)
Dalga 3:  P-ÜV6                      (tek ajan; ortak dosyalar: config.py, stages.py, naming_labels.py, birleştirici)
Dalga 4:  P-ÜV8 kalem 5–7 (ürün düzeyi), P-ÜV9
```

`karadul/stages.py`, `karadul/config.py`, `karadul/core/naming_labels.py`, `karadul/pipeline/steps/_feedback_naming_candidates.py`, `karadul/pipeline/steps/_feedback_naming_merger.py`, `karadul/reconstruction/tarif/baglama.py` ortak ve tehlikeli dosyalardır. Bu planda onlara yalnız P-ÜV5 (`stages.py`, Dalga 0) ve P-ÜV6 (Dalga 3) dokunur; ikisi aynı anda koşmaz. Başka hatların (ÖZ KOD ÖK-1…, KİMLİK) aynı dosyalara dokunan paketleriyle sıra ana oturumca kurulur.

**Durma ölçütü (hat için).** (a) P-ÜV8'in kanal düzeyi kabulünde bir kanalın Wilson alt sınırı < 0,909 çıkarsa (karar A-2) o kanal ad yazmaz, yalnız kanıt satırı yazar. (b) P-ÜV6'nın birleşik ölçümünde üst veri kanalları geliştirme setinin 119 ikilisinde tek bir adı değiştirirse (beklenti 0: set düz C) paket durur ve neden bulunur. (c) Hat, dört kanal bayrak arkasında main'de, kanal düzeyi kabul tabloları yazılı ve P-ÜV9'un Ghidra karşılaştırması sayılmış olunca kapanır; kanalların öntanımda açılması ayrı karardır (K-4).

**Ortak kurallar (her paket için):**
- Depo kökünden `PYTHONDONTWRITEBYTECODE=1 python -m …` / `python scripts/…`. Kabuk zsh: komutu ya da listeyi değişkende tutma.
- PATH'te `otool`, `nm`, `lipo`, `strip`, `strings` conda sürümleri önde (`/opt/anaconda3/bin`). Her yerde `/usr/bin/…` tam yolunu yaz.
- Hiçbir hedef ikili çalıştırılmaz. Hedefler yerinde değiştirilmez; kopya üstünde çalışılır.
- Kilitli setler (`targets/test_seti/`, `targets/dogrulama_seti/` ve koşu çıktıları) açılmaz, listelenmez.
- Kapalı kaynak uygulama analiz edilmez (depo herkese açık). Kullanılabilecek ikililer §9'daki listedir. Depoya üçüncü taraf ikilisi ya da onlardan çıkarılmış ad listesi **commit'lenmez**; testler sentetik baytlarla kurulur (aşağıda).
- Ön kayıt metni ölçümden **önce** commit'lenir: `docs/arge/2026-11-19_mythos/ustveri/on_kayit_<paket>.md` (her pakette hazır metin var). Tutmayan beklenti silinmez.
- Sayılar betikten; Wilson %95 (`scripts/measurement/ks1_olc.py` `oran`).
- Ghidra: aynı anda en çok 1 koşu; `PYTHONHASHSEED=0`; koşuya özel `KARADUL_CACHE_DIR`; `GHIDRA_INSTALL_DIR=$HOME/Library/BlackWidowBuild/ghidra_12.1.2_PUBLIC`.
- Mutasyon: `PYTHONDONTWRITEBYTECODE=1 python scripts/mutation_probe.py --spec scripts/measurement/mutation_specs_<paket>.json`. `find` metni dosyada tekil, `replace` farklı uzunlukta; aynı worktree'de eşzamanlı mutasyon yok. Biçim örneği: `scripts/measurement/mutation_specs_ps3b.json`.
- Sahte veri yok: kanal bir şey okuyamadıysa durum `veri_yok` / `desteklenmiyor` / `tutarsiz` + neden yazar; ad uydurmaz.
- Git: commit'i ana oturum atar; `Co-Authored-By` satırı yok. Sürüm numarasını ana oturum belirler.
- Türkçe metinlerde Türkçe karakter; kod sembolleri İngilizce ya da var olan biçemde.

**Test verisi kuralı (bütün okuyucu paketleri).** Okuyucular dosya yolu değil bir **görüntü nesnesi** alır (P-ÜV0 arayüzü). Birim testleri, `struct.pack` ile kurulan küçük sentetik görüntüler üstünde koşar (sahte `pcHeader` + `ftab` + iki `_func`; sahte sınıf + yöntem listesi; sahte typeinfo + vtable). Gerçek ikili üstündeki denetimler ayrı bir "yerel doğrulama" betiğindedir (`scripts/measurement/ustveri_olc.py`, P-ÜV8) ve dosya yoksa atlanır; `tests/` altında gerçek ikiliye bağlı test olmaz.

**Taşınacak araştırma betikleri (nereden → nereye).** Araştırma betikleri çalışan başvurudur; ürün kodu onlardan **yeniden yazılır** (kopyalanmaz): hata yolları, sınır denetimleri ve durum sözlüğü eklenir.

| Araştırma betiği (`scripts/arge/ustveri/`) | Ürün modülü | Paket |
|---|---|---|
| `macho.py` | `karadul/analyzers/ustveri/goruntu.py` | P-ÜV0 |
| `go_pclntab.py`, `go_say.py` (K1–K9) | `karadul/analyzers/ustveri/go_pclntab.py` | P-ÜV1 |
| `objc_meta.py` | `karadul/analyzers/ustveri/objc.py` | P-ÜV2 |
| `swift_meta.py`, `swift_ad_dogrula.py` | `karadul/analyzers/ustveri/swift.py` | P-ÜV3 |
| `cpp_rtti_tara.py` | `karadul/analyzers/ustveri/cpp_rtti_tara.py` | P-ÜV4 |
| `macho_main.py` | (ölçüm betiği olarak kalır) | P-ÜV5 |
| `go_tip.py`, `go_tutarlilik.py`, `dusman_deney.py` | `karadul/analyzers/ustveri/go_tip.py`, `tutarlilik.py`; deney `scripts/measurement/ustveri_bozma.py` | P-ÜV7 |
| `butce.py`, `tablo.py`, `envanter.py` | `scripts/measurement/ustveri_olc.py` | P-ÜV8 |

**Başvuru çıktıları.** Her okuyucu paketinin kabul ölçütü "araştırma betiğinin çıktısıyla aynı" biçimindedir. Başvuru dosyaları: `$V/envanter.json`, `$V/go/<ad>.json` + `<ad>.tsv`, `$V/objc/<ad>.json` + `.tsv`, `$V/swift/<ad>.json`, `$V/rtti/<ad>.json`, `$V/dusman/<ad>_taban.json` + `<ad>.deney.json`, `$V/butce.json`. `$V` silinmişse aynı dosyalar BULGULAR.md'deki komutlarla yeniden üretilir (hedef kopyaları §9'daki yollardan).

---

## P-ÜV0 — İkili görüntü okuyucu

**Amaç.** Üst veri okuyucularının ortak zemini: adresten bayt okuma, gösterici çözme (zincirli düzeltme / yeniden konumlama / içe aktarım bağı), bölümler, kod bölümleri, fonksiyon başlangıçları, semboller, giriş adresi. Ghidra'sız; yalnız dosya baytları.

**Dokunacağı dosyalar (hepsi yeni):**
- `karadul/analyzers/ustveri/__init__.py`
- `karadul/analyzers/ustveri/goruntu.py`
- `tests/test_puv0_goruntu.py`
- `scripts/measurement/mutation_specs_puv0.json`
- `docs/arge/2026-11-19_mythos/ustveri/on_kayit_PUV0.md`, `P-UV0.md` (ilerleme)

**Dokunmayacağı:** `karadul/` altındaki var olan bütün dosyalar; `scripts/arge/`.

**Kalemler:**
1. Arayüz: `Goruntu` soyut sınıfı — `oku(adres, n) -> bytes | None`, `u32`, `i32`, `u64`, `cstr(adres, azami)`, `gosterici(adres) -> int | Bag | None` (`Bag(ad)` içe aktarım bağı), `bolumler` (ad, adres, boyut, kod mu), `bolum_adli(ad)`, `kod_bolumleri`, `fonksiyon_baslangiclari() -> list[int] | None`, `semboller()` (ad, adres, tür, dışa açık mı), `giris_adresi`, `mimari`, `gosterici_boyutu`, `bicim` (`macho` / `elf` / `pe`).
2. Mach-O 64 uygulaması: yük komutları, bölütler / bölümler, `LC_SYMTAB`, `LC_MAIN`, `LC_FUNCTION_STARTS` (ULEB128 farkları), `LC_DYLD_CHAINED_FIXUPS` (gösterici biçimi 2 ve 6: hedef 36 bit, `high8`, sonraki 12 bit × 4; içe aktarım tablosu biçim 1 / 2 / 3). Başvuru: `scripts/arge/ustveri/macho.py`; yapı tanımları SDK `<mach-o/fixup-chains.h>`. arm64e gösterici biçimi (1) ve çok başlangıçlı sayfa: `desteklenmiyor` durumu, istisna değil.
3. Evrensel dosya: dilim seçimi ürünün seçtiği dilimle aynı olmalı (ürün ince dilimi `raw/<ad>_<mimari>` olarak yazar; okuyucu `binary_for_byte_match` yapıtındaki ince dosyayı alır). Evrensel dosya verilirse dilim adı zorunlu parametre.
4. ELF 64 uygulaması: bölümler, `PT_LOAD` eşlemesi, `.symtab` / `.dynsym`, giriş adresi; **yeniden konumlama**: `R_*_RELATIVE` (RELA'da değer ek alanındadır; dosyadaki sözcük 0 olabilir) ve `R_*_GLOB_DAT` / `JUMP_SLOT` / mutlak sembol bağları `gosterici()` içinde çözülür. Fonksiyon başlangıcı kaynağı: `.eh_frame` FDE başlangıçları (yoksa `None`). `pyelftools` kullanılabilir (depoda bağımlılık olarak var: `scripts/measurement/ks1_olc.py` kullanıyor).
5. PE: bu pakette yalnız iskelet (`bicim = "pe"`, bölümler, `oku`, mutlak göstericiler görüntü tabanıyla); Go PE ve MSVC RTTI kabulü P-ÜV9'da.
6. Sağlamlık: bozuk / kesik dosyada her yöntem `None` ya da boş döner; sonsuz döngü yok (zincir yürüyüşünde adım sınırı = bölüt boyutu / 4). Bellek: dosya `mmap` ya da tek `bytes`; zincirli düzeltme sözlüğü ilk istekte kurulur.
7. Yerel doğrulama betiği girdisi: `python -m karadul.analyzers.ustveri.goruntu <ikili> [--dilim]` özet JSON basar (bölüm sayısı, sembol sayısı, fonksiyon başlangıcı, düzeltme yeri, yeniden konumlama, içe aktarım).

**Kabul ölçütü (sayı ve eşik).** `$V/envanter.json`'daki her dilim için özet JSON alanları bire bir aynı: `LC_FUNCTION_STARTS`, `sembol`, `duzeltme_yeri`, `yeniden_konumlama`, `ice_aktarim`, `giris`. Başvuru değerlerinden örnek: Ollama arm64 12 952 / 899 / 54 161 / 53 480 / 352; limactl 40 917 / 812 / 176 519 / 176 034 / 368; iTerm2 arm64 109 608 / 815 811 / 297 272 / 228 652 / 4 539; `gh` düzeltme 0, başlangıç tablosu yok. 18 dilimin 18'i aynı olmalı. ELF: geliştirme setinden `~/karadul_olcum/n1_debian13/` altındaki 5 ikilide (cat, expr, ls, tree, pzstd) bölüm ve sembol sayıları `/usr/bin/…` yerine `pyelftools` ile bağımsız sayımla aynı; `R_*_RELATIVE` sayısı `readelf` yoksa `pyelftools` yeniden konumlama tablosu sayımıyla aynı.

**Ön kayıt metni (`on_kayit_PUV0.md`):**
> H1: 18 Mach-O diliminin 18'inde altı alan araştırma başvurusuyla aynı. H2: Ollama arm64'te `__objc_classlist`'in ilk girdisi için `gosterici()` kod / veri bölümlerinden birine düşen yerel adres döndürür; `__got` girdisi için `Bag` döndürür. H3: 5 ELF ikilisinde bölüm ve sembol sayıları bağımsız sayımla aynı. H4: kesik dosyada (ilk 4 096 bayt) hiçbir yöntem istisna atmaz. Tutmazsa: fark yazılır, başvuru betiği de denetlenir (hata iki yanda da olabilir).

**Sınama ve mutasyon.** Testler sentetik: elle kurulmuş tek bölütlü Mach-O (bir zincir: iki yeniden konumlama + bir bağ), ULEB fonksiyon başlangıcı, evrensel başlık, kesik dosya; sentetik ELF (bir `R_AARCH64_RELATIVE`). En az 12 test. Mutantlar (≥ 6, hepsi ölmeli): `high8` kaydırması atlanır; biçim 6'da görüntü tabanı eklenmez; zincirde `sonraki × 4` yerine `× 8`; ULEB devam biti yok sayılır; RELA ek alanı yerine dosyadaki sözcük okunur; bağ biti ters yorumlanır.

**Ürüne nasıl girer.** Kitaplık modülü; bayrak yok, tek başına ürün davranışını değiştirmez.

---

## P-ÜV1 — Go `pclntab` okuyucu ve üretici adım

**Amaç.** Soyulmuş Go ikilisinde fonksiyon adresi → tam ad, kaynak dosya yolu, paket sınıfı; Go 1.18–1.27. Ghidra'nın desteklemediği 1.26+ dahil.

**Dokunacağı dosyalar (hepsi yeni):**
- `karadul/analyzers/ustveri/go_pclntab.py`
- `karadul/pipeline/steps/go_metadata_recovery.py`
- `tests/test_puv1_go_pclntab.py`, `tests/test_puv1_adim.py`
- `scripts/measurement/mutation_specs_puv1.json`
- `docs/arge/2026-11-19_mythos/ustveri/on_kayit_PUV1.md`, `P-UV1.md`

**Dokunmayacağı:** `karadul/analyzers/go_binary.py`, `go_demangler.py`, `karadul/reconstruction/go_reconstructor.py` (var olan Go kodu; emekliye ayırma kararı P-ÜV6'da), `karadul/stages.py`, `karadul/config.py`, `_feedback_naming_*.py`.

**Biçim (doğrulanmış; kaynak Go kaynak ağacı `release-branch.go1.26` / `go1.27`, 2026-11-19):**
- `pcHeader` (72 bayt): imza u32 (`0xfffffff0` = 1.18–1.19, `0xfffffff1` = 1.20+), 2 dolgu baytı (0), `minLC` u8, `ptrSize` u8, `nfunc` u64, `nfiles` u64, **eski `textStart` u64 (1.26+'da 0)**, `funcnameOffset`, `cuOffset`, `filetabOffset`, `pctabOffset`, `pclnOffset` (hepsi başlığa göre ofset).
- `ftab`: `pclnOffset`'te `(nfunc + 1)` × (`entryoff` u32, `funcoff` u32); `entryoff` metin tabanına, `funcoff` `pclnOffset`'e göre.
- `_func` (44 bayt sabit): `entryOff` u32, `nameOff` i32, `args` i32, `deferreturn` u32, `pcsp` u32, `pcfile` u32, `pcln` u32, `npcdata` u32, `cuOffset` u32, `startLine` i32, `funcID` u8, `flag` u8, dolgu u8, `nfuncdata` u8.
- Metin tabanı: `moduledata.text`. `moduledata`, ilk sözcüğü `pcHeader` adresi olan ve ikinci sözcüğü `pcHeader + funcnameOffset` olan veri nesnesidir; sözcük sırası: 0 `pcHeader`, 1–3 `funcnametab`, 4–6 `cutab`, 7–9 `filetab`, 10–12 `pctab`, 13–15 `pclntable`, 16–18 `ftab`, 19 `findfunctab`, 20 `minpc`, 21 `maxpc`, 22 `text`, 23 `etext`, …, 37 `types`; 1.27'de 38 `typedesclen`, 39 `etypes`, 40 `itaboffset`, 41 `itabsize`; 1.26'da 38 `etypes`.
- pc-değer tablosu: değer farkı (zikzak) ve pc farkı (× `minLC`) çiftleri, değişken uzunluklu; ilk çift dışında 0 değer farkı bitirir (`runtime.pcvalue` / `step`).
- Dosya yolu: `pcfile` tablosunun ilk değeri → `cutab[cuOffset + değer]` → `filetab` ofseti (`0xffffffff` = yok).
- `__go_buildinfo`: 14 baytlık imza `\xff Go buildinf:`, 15. baytta bayrak (bit 1 = satır içi), 32. bayttan itibaren değişken uzunluklu sürüm dizgisi ve modül bilgisi (ilk ve son 16 bayt nöbetçi).
- Başka sürüm görürsen (imza bu ikisi değilse ya da `moduledata` bulunamadıysa) **tahmin etme**: durum `desteklenmiyor` + neden. Biçimi ezberden genişletme; resmî kaynağı oku, kaynağı ve tarihi ilerleme belgesine yaz.

**Kalemler:**
1. Okuyucu: `GoPclntab(goruntu)`; `pclntab`'ı bul (Mach-O `__gopclntab`, ELF `.gopclntab`; bölüm adı yoksa imza taraması + başlık akıl sağlığı), `moduledata`'yı bul, metin tabanını seç (kaynağı kaydet: `moduledata.text` / `pcHeader.textStart`).
2. Fonksiyon listesi: giriş, bitiş, ad (özgün, değiştirilmeden), dosya yolu, başlangıç satırı, `funcID`, `flag`, paket, paket sınıfı (`kendi` / `ucuncu_taraf` / `standart` / `calisma_zamani` / `derleyici` / `paketsiz`; kural `scripts/arge/ustveri/go_pclntab.py` `sinif`: ana modülün `vendor/` dizini üçüncü taraftır).
3. Yapı denetimleri (hepsi zorunlu alanlardan): K1 girişler artan; K2 girişler kod bölümünde ve `text…etext` içinde; K4 `pcsp` tablosu fonksiyon boyunu kaplıyor (hizalama dolgusu = giriş adreslerinin en büyük ortak böleni; birleştirici dili bayraklı fonksiyon ayrı); K5 `findfunctab` alt kovaları; K6 girişler fonksiyon başlangıcı (tablo varsa); K7 arm64 `bl` hedefleri (Duff gövdesi ayrık); K8 özel `funcID` taşıyan fonksiyon `runtime.` önekli ve kimlik tekil; K9 `minpc` / `maxpc`. Sonuç `go_integrity` sözlüğü (denetim başına bakılan / ihlal).
4. Karar: K1, K2, K5, K9'dan biri ihlal veriyorsa ya da K4 ihlali fonksiyonların %1'ini aşıyorsa durum `tutarsiz` ve adım **ad listesi üretmez** (yalnız kanıt: neden + sayılar).
5. Üretici adım `go_metadata_recovery` (`@register_step`; örnek `karadul/pipeline/steps/pdb_symbol_recovery.py`): `requires=["binary_for_byte_match"]`; `produces=["go_functions", "go_buildinfo", "go_integrity", "go_status", "go_functions_path"]`; durum sözlüğü `calisti` / `veri_yok` (Go değil) / `desteklenmiyor` / `tutarsiz` / `kapali` / `hata` + neden. Çıktı `static/go_functions.json`. Bayrak kapalıyken iş yapmaz (bayrak P-ÜV6'da tanımlanır; bu pakette `getattr(…, "enable_go_metadata_recovery", False) is True`).
6. Satır içi ad sayımı (yalnız sayaç): `funcnametab`'da hiçbir girişe bağlı olmayan ad sayısı `go_integrity`'ye yazılır; ağaç çözümü yapılmaz (P-ÜV9 açık kalemi).
7. Süre ve bellek ölçümü: 11 dilimde okuma + denetim süresi ve tepe bellek ilerleme belgesine.

**Kabul ölçütü.**
- 11 Go diliminde (`gh`, `limactl`, Ollama arm64 / x86_64, ollama-cli arm64 / x86_64, `colima`, docker-brew, `arduino-cli`, docker-cli, docker-compose) (adres, ad, dosya) üçlülerinin tamamı `$V/go/<ad>.tsv` ile aynı: 11 / 11 dilim, satır farkı 0. Giriş sayıları: 40 384, 40 321, 10 601, 10 676, 25 164, 25 267, 13 082, 35 749, 29 711, 35 049, 90 078.
- Sembollü iki ikilide ad = sembol (yazım kuralları: `.abi0` eki, orta nokta): docker-cli 35 048 / 35 048, docker-compose 90 077 / 90 077. Eşik: Wilson alt sınırı ≥ 0,999.
- K1, K2, K5, K9 ihlali 11 dilimde 0; K7 "başka gövde içi hedef" 0; 1.26+ dilimlerinde metin tabanı kaynağı `moduledata.text`.
- Süre: dilim başına ≤ 10 sn (araştırma betiği 0,8–1,7 sn).
- Adım: bayrak kapalıyken `go_status = kapali`, yapıt boş; Go olmayan ikilide (htop) `veri_yok`.

**Ön kayıt metni (`on_kayit_PUV1.md`):**
> H1: 11 / 11 dilimde (adres, ad, dosya) listesi araştırma başvurusuyla aynı. H2: sembollü iki ikilide adı olan girişlerin 125 125 / 125 125'inde ad sembolle aynı (iki yazım kuralıyla). H3: 9 dilimde (Go ≥ 1.26) başlıktaki eski `textStart` alanı 0'dır ve okuyucu `moduledata.text` kullanır; başlığa güvenen mutant bu dilimlerde 0 doğru adres üretir. H4: yapı denetimleri bozulmamış 11 dilimde `tutarsiz` vermez. H5: P-ÜV7'nin E türü bozuk kopyasında (komşu `_func` takası) K4 ihlal sayısı > 0. H6: Go olmayan 5 ikilide (htop, tmux, cat, ls, pzstd) durum `veri_yok`, ad 0. Tutmayan hüküm silinmez.

**Sınama ve mutasyon.** Sentetik görüntü kur: 3 fonksiyonlu `pclntab` (1.20+ imzası, `textStart` 0, ayrı `moduledata`) ve aynısının 1.18 imzalı, `textStart` dolu hâli; `pcsp` tablosu olan / olmayan fonksiyon; `filetab` `0xffffffff`. En az 16 test. Mutantlar (≥ 10, hepsi ölmeli): metin tabanı başlıktan alınır; `funcoff` `pclnOffset` yerine başlığa eklenir; `ftab`'da `nfunc + 1` yerine `nfunc`; zikzak çözümü ters; `minLC` çarpanı atlanır; `nameOff` 0 iken ad okunur; K1 karşılaştırması `<` yerine `<=`; `vendor/` kuralı kaldırılır; `tutarsiz` kararı ad listesini yine de döndürür; bayrak denetimi `is True` yerine doğruluk değeri.

**Ürüne nasıl girer.** Adım bayrağı `binary_reconstruction.enable_go_metadata_recovery` (öntanım **kapalı**; P-ÜV6 tanımlar ve Faz 1 listesine ekler). Ad kanalı ayrı bayrak: `enable_go_pclntab_naming` (öntanım kapalı; P-ÜV6).

---

## P-ÜV2 — Objective-C yöntem listesi okuyucu ve üretici adım

**Amaç.** Sınıf, kategori ve yöntem listelerinden uygulama adresi → `-[Sınıf seçici]` / `+[Sınıf seçici]`.

**Dokunacağı dosyalar (hepsi yeni):** `karadul/analyzers/ustveri/objc.py`; `karadul/pipeline/steps/objc_metadata_recovery.py`; `tests/test_puv2_objc.py`; `scripts/measurement/mutation_specs_puv2.json`; `docs/arge/2026-11-19_mythos/ustveri/on_kayit_PUV2.md`, `P-UV2.md`.

**Dokunmayacağı:** var olan bütün `karadul/` dosyaları (özellikle `swift_binary.py`, `macho.py`, `stages.py`, `config.py`).

**Biçim (kaynak apple-oss-distributions/objc4 `runtime/objc-runtime-new.h`, 2026-11-19):** `__objc_classlist` / `__objc_nlclslist` sınıf göstericileri; sınıf: `isa`, `superclass`, önbellek (2 sözcük), veri (maske `0x00007ffffffffff8`; düşük bitler Swift işareti); `class_ro_t`: bayraklar u32 × 4, `ivarLayout`, `name` (+24), `baseMethods` (+32), `baseProtocols` (+40), …; yöntem listesi: `entsizeAndFlags` u32 (bayrak maskesi `0xffff0003`; `0x80000000` küçük biçim; `0x40000000` seçici doğrudan), `count` u32; küçük kayıt 12 bayt (üç int32 göreli: ad → **seçici başvurusu**, tip, IMP; her ofset kendi alanına göre), büyük kayıt 24 bayt (üç gösterici); sınıf yöntemleri (`+`) `isa`'nın gösterdiği meta sınıfın yöntem listesinden; kategori: ad, sınıf (yerel ya da `_OBJC_CLASS_$_X` bağı), örnek yöntemleri, sınıf yöntemleri, protokoller; protokol: `mangledName` (+8), dört yöntem listesi (+24 … +48).

**Kalemler:**
1. Okuyucu: sınıflar, üst sınıflar, kategoriler, protokoller; her yöntem kaydı için (tür `-` / `+`, sınıf adı, kategori adı, seçici, tip kodlaması, IMP, Swift sınıfı mı, benimsenen protokolde mi).
2. Denetimler: IMP kod bölümünde; IMP fonksiyon başlangıcı (tablo varsa); arite (seçicideki `:` sayısı = tip kodlamasındaki argüman sayısı − 3; çözücü `scripts/arge/ustveri/objc_meta.py` `tip_arguman_sayisi`); aynı IMP'e birden çok ad.
3. Ad biçimi: `-[Sınıf seçici]`; kategori yöntemi için sınıf adı kullanılır, kategori adı ayrı alanda (kategori adı serbest metin: BULGULAR §6.1). Swift sınıfının köprüsü (`swift = true`) ayrı işaretlenir: bu adres Swift yönteminin gövdesi değil, ObjC köprüsüdür.
4. Üretici adım `objc_metadata_recovery`: `produces=["objc_methods", "objc_classes", "objc_status", "objc_methods_path"]`; çıktı `static/objc_methods.json`; durum sözlüğü P-ÜV1 ile aynı.
5. Sağlamlık: yöntem sayısı üst sınırı (liste başına 100 000), döngüsel üst sınıf zinciri, bölüm dışına gösteren göreli ofset → kayıt atlanır, sayaç artar; istisna yok.
6. Eski `LC_DYLD_INFO` düzenli ikili (Rectangle): göstericiler ham; P-ÜV0 `gosterici()` bunu saydam yapar; ayrıca doğrula.

**Kabul ölçütü.** 6 hedefte sayılar `$V/objc/<ad>.json` ile aynı: terminal-notifier 32, iTerm2 arm64 41 305, Ollama arm64 151, Ollama x86_64 151, limactl 102, Rectangle arm64 450 yöntem kaydı; IMP'lerin tamamı fonksiyon başlangıcı (6 / 6 hedef). (adres, ad) listesi `$V/objc/<ad>.tsv` ile aynı. Sembollü iki ikilide ad = sembol: iTerm2 33 611 / 33 611, terminal-notifier 32 / 32 (kategori yazımı kuralıyla); eşik Wilson alt sınırı ≥ 0,999. Okuma hatası sayaçları 0.

**Ön kayıt metni:**
> H1: 6 / 6 hedefte yöntem kaydı sayısı ve (adres, ad) listesi başvuruyla aynı. H2: iTerm2'de ObjC sembolü olan 33 611 IMP'in tamamında ad sembolle aynı; farklı ad 0. H3: iTerm2'de ObjC sembolü olmayan IMP'lerin (7 694) en az %95'i Swift sınıfı kaydıdır. H4: seçici başvurusu yerine doğrudan dizgi okuyan mutant küçük biçimli listelerde 0 doğru seçici üretir. H5: ObjC olmayan ikilide (`gh`) durum `veri_yok`.

**Sınama ve mutasyon.** Sentetik görüntü: bir sınıf + meta sınıfı, küçük biçimli 2 yöntem (seçici başvurusu üstünden), büyük biçimli 1 yöntem, dış sınıfa kategori (bağ), protokol. En az 12 test. Mutantlar (≥ 8): göreli ofset alanın kendisine değil kaydın başına eklenir; veri maskesi uygulanmaz; küçük biçimde boyut 24 alınır; `0x40000000` bayrağı yok sayılır; meta sınıf yöntemleri `-` diye yazılır; kategori sınıfı bağından ön ek soyulmaz; arite denetiminde `− 3` yerine `− 2`; sayı üst sınırı kaldırılır.

**Ürüne nasıl girer.** Adım bayrağı `enable_objc_metadata_recovery`, ad kanalı bayrağı `enable_objc_metadata_naming` (ikisi de öntanım kapalı; P-ÜV6).

---

## P-ÜV3 — Swift tip üst verisi okuyucu ve üretici adım

**Amaç.** Tip adları ve tip başına erişim fonksiyonu (tam ad); vtable ve tanık tablosu yuvaları için **kanıt satırı** (tip + tür + sıra). Swift üst verisi yöntem adı taşımaz: bu paket yöntem adı üretmez.

**Dokunacağı dosyalar (hepsi yeni):** `karadul/analyzers/ustveri/swift.py`; `karadul/pipeline/steps/swift_metadata_recovery.py`; `tests/test_puv3_swift.py`; `scripts/measurement/mutation_specs_puv3.json`; `on_kayit_PUV3.md`, `P-UV3.md`.

**Dokunmayacağı:** `karadul/analyzers/swift_binary.py` ve var olan bütün dosyalar.

**Biçim (kaynak swiftlang/swift `include/swift/ABI/MetadataValues.h`, `Metadata.h`, `GenericContext.h`; 2026-11-19; `docs/ABI/TypeMetadata.rst`'nin betimleyici bölümü güncel değil, kullanma):** `__swift5_types`: int32 göreli kayıtlar (düşük bit dolaylı); bağlam betimleyicisi: bayrak u32 (tür `& 0x1F`: 0 modül, 1 uzantı, 2 adsız, 3 protokol, 16 sınıf, 17 yapı, 18 enum; `0x80` genel; `0x20` ters çevrilebilir protokoller; türe özgü bayraklar üst 16 bit), üst bağlam (dolaylı olabilen göreli); tip: ad (+8), erişim fonksiyonu (+12), alanlar (+16); sınıf sabit kısmı 44 bayt; artçılar sırayla: genel bağlam başlığı (16 bayt + parametre baytları 4'e hizalı + 12 baytlık gereksinimler [+ paket biçimi başlığı]), dirençli üst sınıf (4; bit 13), yabancı / tekil başlatma (4 / 12; bit 0–1), vtable başlığı (ofset u32, boyut u32; bit 15), yöntem betimleyicileri (bayrak u32: tür `& 0x0F` 0 yöntem, 1 init, 2 getter, 3 setter, 4 modify, 5 read; `0x10` örnek; `0x20` dinamik; `0x40` zaman uyumsuz; uygulama int32 göreli), geçersiz kılma tablosu (sayı u32 + 12 baytlık kayıtlar; bit 14). `__swift5_proto`: uyum betimleyicileri (protokol, tip başvurusu, tanık tablosu, bayrak; tip başvuru türü bit 3–5); tanık tablosunun ilk sözcüğü betimleyiciye gösterir.

**Kalemler:**
1. Okuyucu: tipler (tür, nitelikli ad, erişim fonksiyonu, genel mi), sınıf vtable yöntem betimleyicileri (tür, örnek mi, uygulama adresi; zaman uyumsuzda adres kod değilse atla), geçersiz kılma kayıtları, uyumlar ve tanık tablosu kod göstericileri (yerel protokolde gereksinim sayısı kadar; dış protokolde "ardışık kod göstericisi" kuralı, başka tanık tablosunun başlangıcında dur).
2. **Nitelikli adın üç eksiği** (bugünkü araştırma okuyucusunda tam eşitlik 2 444 / 3 659): (a) adsız bağlam (`private` tipler): bağlamın ayraç adını oku ve `Modül.(Tip in <ayraç>)` biçimini kur; kurulamıyorsa ad verme; (b) uzantı bağlamı: uzatılan tipin adı; (c) içe aktarım bilgisi (`HasImportInfo`, bit 2): addan sonraki ek dizgilerden ABI adını oku. Her biri resmî kaynaktan doğrulanarak yazılır (kaynak dosya ve tarih ilerleme belgesine).
3. Çıktı ayrımı: `swift_types` (ad verilebilen erişim fonksiyonları: `type metadata accessor for <Tip>`) ve `swift_slots` (kanıt: tip, tür, sıra, adres). `swift_slots` **ad adayı değildir**.
4. Üretici adım `swift_metadata_recovery`: `produces=["swift_types", "swift_slots", "swift_status", "swift_types_path"]`; çıktı `static/swift_metadata.json`.
5. Sağlamlık: vtable boyutu üst sınırı (20 000), desteklenmeyen genel bayrak → o tipin artçıları çözülmez (sayaç), tip adı ve erişim fonksiyonu yine okunur.
6. Kendi kendini doğrulama sayaçları: erişim fonksiyonu kod bölümünde ve fonksiyon başlangıcı; tanık tablosu ilk sözcüğü betimleyiciye eşit.

**Kabul ölçütü.** Rectangle arm64 ve iTerm2 arm64'te sayılar `$V/swift/<ad>.json` ile aynı (tip 186 / 3 659; erişim fonksiyonu 186 / 3 659; vtable betimleyicisi 961 / 12 258; kodda ayrık uygulama 106 / 2 264; tanık kod göstericisi 39 / 741). iTerm2'de: erişim fonksiyonlarının 3 659 / 3 659'unda sembol `Ma` ekli; tanıkların 741 / 741'inde `TW` ekli. **Nitelikli ad tam eşitliği** (`xcrun swift-demangle` çıktısına karşı; ölçüm betiği `scripts/arge/ustveri/swift_ad_dogrula.py`'nin ürün okuyucusuna bağlanmış hâli): ad verilen tiplerde doğru ≥ %99 **ve** ad verilen tip ≥ 3 477 / 3 659 (%95). İkisinden biri tutmazsa kanal yalnız tutan alt küme için ad üretir (ör. adsız bağlam çözülemiyorsa o tiplere ad verilmez) ve sayı raporlanır.

**Ön kayıt metni:**
> H1: iki hedefte sayılar başvuruyla aynı. H2: iTerm2'de erişim fonksiyonu sembol eki 3 659 / 3 659, tanık eki 741 / 741. H3: üç eksik giderildikten sonra nitelikli ad tam eşitliği ≥ 3 477 / 3 659; ad verilenlerde yanlış ≤ %1. H4 (beklenen olumsuz): vtable yuvalarından yöntem adı üretilemez; kanal `swift_slots` için ad adayı yazmaz (0). H5: Swift olmayan ikilide durum `veri_yok`.

**Sınama ve mutasyon.** Sentetik: modül + sınıf (vtable 3 yöntem) + iç içe yapı + genel sınıf + adsız bağlamda tip + bir uyum. En az 14 test. Mutantlar (≥ 8): genel bağlam parametre hizalaması atlanır; bit 13 yok sayılır; tekil başlatma 12 yerine 4 bayt atlanır; yöntem betimleyicisi 8 yerine 12 bayt; dolaylı bit maskelenmez; `swift_slots` ad adayı olarak döner; tanık taraması başka tablonun başlangıcında durmaz; içe aktarım adı yerine kısa ad yazılır.

**Ürüne nasıl girer.** `enable_swift_metadata_recovery`, `enable_swift_metadata_naming` (öntanım kapalı; P-ÜV6). Ad kanalı yalnız erişim fonksiyonlarını adlandırır; yuvalar rapor ve KaradulLM için kanıt satırıdır.

---

## P-ÜV4 — C++ RTTI sembolsüz tarama ve üretici adım (IMZA-16)

**Amaç.** Soyulmuş ikilide sınıf adları, vtable'lar ve yuva işlevleri. Bugünkü `cpp_rtti.py` `_ZTI` / `_ZTV` sembolü istediği için soyulmuş ikilide 0 veriyor (Ollama arm64: vtable 0; tarama: 8 vtable, 68 işlev).

**Dokunacağı dosyalar (hepsi yeni):** `karadul/analyzers/ustveri/cpp_rtti_tara.py`; `karadul/pipeline/steps/rtti_recovery.py`; `tests/test_puv4_rtti.py`; `scripts/measurement/mutation_specs_puv4.json`; `on_kayit_PUV4.md`, `P-UV4.md`.

**Dokunmayacağı:** `karadul/analyzers/cpp_rtti.py` (sembollü yol ve MSVC ayrıştırıcısı; `karadul rtti` komutu onu kullanıyor), `stages.py`, `config.py`, `_feedback_naming_candidates.py` (`_add_rtti` hazır; P-ÜV6 bağlar).

**Yöntem (Itanium ABI; kaynak https://itanium-cxx-abi.github.io/cxx-abi/abi.html §2.5, §2.9.5 ve llvm-project `libcxxabi/src/private_typeinfo.h`):**
- typeinfo nesnesi = ilk sözcüğü `__ZTVN10__cxxabiv117__class_type_infoE` / `…120__si_class_type_infoE` / `…121__vmi_class_type_infoE` adına **içe aktarım bağı** olan nesne (ELF'te baştaki alt çizgi tek). İkinci sözcük ad dizgisi (Apple arm64'te en üst bit "tekil değil" işareti: maskele, işareti kaydet). `si`: +16 taban; `vmi`: +16 bayrak u32, +20 taban sayısı u32, +24'ten 16 baytlık (taban, ofset-bayrak) kayıtları.
- vtable = [tepeye uzaklık: düzeltme yeri olmayan, 0 ya da küçük negatif tam sayı] [typeinfo başvurusu] [kod göstericileri…]; typeinfo başvurusu başka bir typeinfo nesnesinin içindeyse vtable değildir. İçe aktarım yuvası (ör. saf sanal) atlanır ama sıra numarası ilerler.
- **Zayıf semboller:** dışa açık typeinfo ve ad dizgisine başvurular yeniden konumlama değil ada göre bağ olabilir; bağ adı aynı ikilide tanımlıysa yerel adrese çevir (x86_64 dilimde 19 typeinfo'nun 15'i böyle).

**Kalemler:**
1. Tarayıcı: typeinfo listesi (ad, tür, tabanlar, tekil mi), vtable listesi (adres, sınıf, tepeye uzaklık, yuvalar).
2. Ad çözme: `karadul/analyzers/cpp_rtti.py`'deki `batch_demangle` çağrılabilir (içe aktarım; dosya değişmez); çözülemeyen ad özgün hâliyle kalır.
3. Çıktı `rtti_classes`: `[{"name": çözülmüş ad, "mangled": …, "methods": [yuva adresleri (içe aktarım yuvası için 0)], "bases": […], "vtable": adres}]` — `_add_rtti`'nin beklediği biçim (`karadul/pipeline/steps/_feedback_naming_candidates.py:676`); `rtti_status = (durum, neden)` demeti.
4. Aynı işlev birden çok sınıfın vtable'ında görünüyorsa (devralınan yuva) en taban sınıfa bağla; taban ilişkisi yoksa `belirsiz` say ve o işlev için ad adayı verme.
5. ELF: aynı tarama P-ÜV0'ın ELF `gosterici()`'siyle; doğrulayıcı geliştirme setinden `pzstd` (Debian; `~/karadul_olcum/n1_debian13/`), GT ayrı dbgsym dosyasından (`scripts/measurement/ks1_olc.py` `gt_elf`).
6. Sağlamlık (P13b'nin koşulu): kesik vtable, döngülü taban, `vmi` taban sayısı > 64, yuva sayısı üst sınırı (`rtti_max_vtable_entries`, öntanım 64'ü oku; aşan vtable kesilir ve sayılır), 10 sn süre sınırı. Bulanık girdi testi: gerçek bir typeinfo bölgesinin 200 rastgele bayt bozulmuş kopyasında istisna ve zaman aşımı 0.
7. Üretici adım `rtti_recovery`: `produces=["rtti_classes", "rtti_status", "rtti_classes_path"]`; çıktı `static/rtti_classes.json`.

**Kabul ölçütü.** Sayılar `$V/rtti/<ad>.json` ile aynı: btop 42 typeinfo / 36 vtable / 84 işlev; iTerm2 arm64 18 / 10 / 64; llama-server arm64 1 994 / 1 317 / 7 053; Ollama arm64 ve x86_64 19 / 8 / 68. Sembollü ikililerde: typeinfo adı 2 028 / 2 028, vtable 1 328 / 1 328 sembolle aynı; yuva işlevinin sembolü sınıfın ya da tabanının adını taşıyor ≥ 7 098 / 7 119 (Wilson alt sınırı ≥ 0,99). ELF `pzstd`: bulunan sınıf adlarının dbgsym'deki `_ZTI` sembolleriyle eşleşmesi ≥ %99 (sayı ön kayıtta ölçümden önce yok: ilk ölçüm).

**Ön kayıt metni:**
> H1: 5 Mach-O hedefinde üç sayı başvuruyla aynı. H2: sembollü ikililerde typeinfo adı 2 028 / 2 028, vtable 1 328 / 1 328. H3: Ollama arm64 ve x86_64 dilimleri aynı sayıyı verir (19 / 8 / 68); zayıf bağ çözümünü kaldıran mutant x86_64'te ≤ 4 typeinfo bulur. H4: bulanık girdide istisna 0, süre aşımı 0. H5: ELF `pzstd`'de en az 1 vtable bulunur ve sınıf adı eşleşmesi ≥ %99 (ilk ölçüm; tutmazsa ELF yolu `desteklenmiyor` kalır). H6 (beklenen sınır): yuvadan yöntem adı çıkmaz; aday `Sınıf_vfunc_N` biçimindedir ve doğruluğu "tam eşitlik" ölçüsünde 0'dır → bu adaylar ad olarak değil kanıt satırı olarak yazılmalıdır (karar P-ÜV6).

**Sınama ve mutasyon.** Sentetik: 3 sınıf (taban, tekli kalıtım, çoklu kalıtım), birincil + ikincil vtable, saf sanal bağ, zayıf bağlı typeinfo. En az 14 test. Mutantlar (≥ 8): en üst bit maskelenmez; typeinfo içindeki başvuru vtable sayılır; tepeye uzaklık pozitif kabul edilir; içe aktarım yuvası sıra numarasını ilerletmez; zayıf bağ çözülmez; `vmi` taban adımı 16 yerine 8; yuva üst sınırı uygulanmaz; belirsiz işlev ilk sınıfa bağlanır.

**Ürüne nasıl girer.** Adım bayrağı var olan `enable_rtti_recovery` (öntanım kapalı; bağlanınca `INERT_SETTINGS` kaydı P-ÜV6'da kaldırılır). Ad kanalı bayrağı var olan `enable_rtti_naming` (öntanım kapalı).

---

## P-ÜV5 — Mach-O `main`

**Amaç.** Mach-O çalıştırılabilirinde `LC_MAIN` girişine `main` adını vermek. Bugün `_recover_main_from_entry` yalnız `__libc_start_main(FUN_…` kalıbını arıyor ve Mach-O'da 8 / 8 ikilide bulamıyor.

**Dokunacağı dosyalar:**
- `karadul/stages.py` — yalnız `_recover_main_from_entry` (satır 1816 civarı) ve onun yardımcıları; adım listeleri ve başka yöntemler **değişmez**.
- yeni `tests/test_puv5_macho_main.py`
- yeni `scripts/measurement/mutation_specs_puv5.json`
- `on_kayit_PUV5.md`, `P-UV5.md`

**Dokunmayacağı:** `karadul/core/naming_labels.py`, `karadul/reconstruction/tarif/baglama.py`, `config.py` (bayrak P-ÜV6'da; bu pakette `getattr(…, "enable_macho_entry_main", False) is True`), `karadul/analyzers/ustveri/` (P-ÜV0 ile aynı dalgada; ona bağımlı olma). Giriş adresi ürünün kendi yapıtından okunur: `static/load_commands.txt` içinde `cmd LC_MAIN` bloğunun `entryoff` satırı (htop koşusunda `entryoff 6016` = 0x1780; doğrulandı, 2026-11-19) + Ghidra görüntü tabanı (`static/ghidra_combined_results.json` → `program_info.image_base`, htop'ta `100000000`) = Ghidra adresi (0x100001780, Ghidra'da `entry`). `LC_UNIXTHREAD` aynı dosyada `cmd LC_UNIXTHREAD` olarak görünür.

**Kalemler:**
1. Göster (önce): 8 Mach-O ürün koşusunda (`scripts/arge/ustveri/macho_main.py gt`) giriş = GT `_main` 8 / 8, ürünün `main` verdiği 0 / 8. Aynı betiği taban olarak yeniden koş.
2. Kural: hedef Mach-O `MH_EXECUTE`, `LC_MAIN` var, Ghidra'nın fonksiyon listesinde giriş adresinde `entry` adlı (ya da adsız) fonksiyon var → `extracted_names[<o anahtar>] = "main"`, `stats["main_recovered"]`, künye türü var olan `KIND_MAIN` (`main_giris`). Ghidra görüntü tabanı farkı için `GhidraFunctionIndex` / `load_ghidra_index` mantığını (içe aktararak) kullan.
3. İstisnalar: (a) ikilide Go `pclntab` varsa ve girişin `pclntab` adı `main` değilse (`_rt0_arm64_darwin`: iç bağlayıcılı Go) ad yazma; (b) `LC_MAIN` yok, `LC_UNIXTHREAD` var (eski düzen: giriş `start`'tır, `main` değil) → ad yazma, kanıt satırı; (c) giriş adresinde Ghidra zaten jenerik olmayan bir ad taşıyorsa (sembol) dokunma.
4. Thunk: htop'ta giriş 4 baytlık atlama; GT `_main` da aynı adres. Thunk'a `main` yazılır; hedefine yazılmaz.
5. ELF yolu değişmez: `__libc_start_main` kalıbı önce denenir; Mach-O kuralı yalnız Mach-O hedefte ve kalıp bulunamadığında.
6. `usage` gelenek kanalının (P-S3b kalem 2) Mac'te `main` görünce ne yaptığını ölç: 8 ikilide yeni adlar, GT'ye karşı doğru / yanlış.
7. Ürün koşusu: 8 Mach-O (htop, tmux: `scripts/measurement/urun_kos.py` Mac kolu; kabul seti 6 ikili: `~/karadul_olcum/runs/onarim-2026-11-18/P-S3b/kos_mac.sh` düzeni) bayrak açık / kapalı.

**Kabul ölçütü.** Bayrak açıkken 8 / 8 ikilide `main` adı giriş fonksiyonuna verilir ve GT'ye göre doğrudur (8 / 8); yanlış `main` 0. Bayrak kapalıyken 8 ikilinin ad haritası tabanla bayt bayt aynı. Geliştirme setinin Debian kolundan 5 ikilide (cat, expr, ls, tree, pzstd) bayrak açıkken ad haritası değişmez (ELF etkilenmez). `usage` kanalından gelen yeni adlar: yanlış 0 (doğru sayısı ilk ölçüm).

**Ön kayıt metni:**
> H1: bayrak açıkken Mach-O 8 / 8'de giriş fonksiyonu `main` adını alır; GT'ye göre 8 / 8 doğru. H2: bayrak kapalıyken ad haritası 8 / 8'de tabanla aynı. H3: 5 ELF ikilisinde bayrak açıkken değişen ad 0. H4: iç bağlayıcılı Go ikilisinde (`gh`; yalnız kural birim testi ve giriş adı okuması, Ghidra koşusu yok) `main` yazılmaz. H5: `main` üstünden çalışan gelenek kanalının Mac'teki yeni adlarında yanlış 0; sayı ilk ölçüm. H6: nüfus etkisi: htop'ta `main` thunk olduğu için ad bekleyen nüfusa girmez; doğru ad kapsamı yalnız 7 ikilide 1'er artar. Tutmayan hüküm silinmez.

**Sınama ve mutasyon.** Birim testleri sahte `static` dizini ve sahte Ghidra fonksiyon listesiyle: Mach-O + `LC_MAIN`; Mach-O + `LC_UNIXTHREAD`; ELF kalıbı; Go iç bağlayıcı; giriş adında sembol; görüntü tabanı farkı. En az 10 test. Mutantlar (≥ 6): Go istisnası kaldırılır; `LC_UNIXTHREAD` de `main` sayılır; adlı girişin üstüne yazılır; ELF'te Mach-O kuralı da koşar; bayrak denetimi kaldırılır; görüntü tabanı farkı uygulanmaz.

**Ürüne nasıl girer.** `binary_reconstruction.enable_macho_entry_main` (öntanım **kapalı**; P-ÜV6 `config.py`'ye ekler). Kanal anahtarı köken kaydında `on_ad:main_giris` (var olan); ölçülmüş kesinlik satırı P-ÜV6'da Mach-O ölçümüyle güncellenir.

---

## P-ÜV7 — Go tutarlılık denetimi (I4)

**Amaç.** `pclntab` adını çalışma için zorunlu ikinci bir yapıyla karşılaştırmak; fonksiyon başına "çift kaynaklı / tek kaynaklı / tutarsız" damgası ve ikili düzeyinde özet. Denetim adın gerçekliğini kanıtlamaz (BULGULAR §6.2: tutarlı sahtecilik 0 / 86, 0 / 451); ucuz tahrifatı ve bozuk üst veriyi yakalar.

**Dokunacağı dosyalar (hepsi yeni):** `karadul/analyzers/ustveri/go_tip.py`; `karadul/analyzers/ustveri/tutarlilik.py`; `scripts/measurement/ustveri_bozma.py`; `tests/test_puv7_tutarlilik.py`; `scripts/measurement/mutation_specs_puv7.json`; `on_kayit_PUV7.md`, `P-UV7.md`.

**Dokunmayacağı:** P-ÜV1'in dosyaları (okuyucuyu içe aktar; değiştirme. Eksik bir alan gerekiyorsa ana oturuma yaz), `stages.py`, `config.py`.

**Biçim (kaynak Go `src/internal/abi/type.go`, `src/runtime/iface.go`; dal `release-branch.go1.27`, 2026-11-19):** `Type` 48 bayt (…, `TFlag` +20: bit 0 `Uncommon`, bit 1 `ExtraStar`; `Kind_` +23; `Str` +40; `PtrToThis` +44); `UncommonType` (paket yolu i32, yöntem sayısı u16, dışa açık u16, `Moff` u32, boş u32) türe özgü yapının ardında (yapı 80, gösterici 56, dilim 56, dizi 72, kanal 64, arayüz 80, öbürleri 48; eşlem ve fonksiyon türleri atlanır); `Method` 16 bayt (ad, tip, `Ifn`, `Tfn`; metin ofseti −1 / 0 = yok); `InterfaceType`: yöntem dilimi +56 (gösterici) / +64 (uzunluk), `Imethod` 8 bayt; ad kodlaması: bayrak baytı, değişken uzunluk, baytlar. itab: arayüz, tip, karma u32 (+ dolgu), `Fun[]` +24; boyut `24 + 8 × max(yöntem sayısı, 1)`. 1.27: itab'lar `types + itaboffset`, uzunluk `itabsize`; 1.26 ve öncesi: `__itablink` / `.itablink` bölümü (itab göstericileri), `__typelink` (tip ofsetleri).

**Kalemler:**
1. Tip verisi okuyucu: itab'lar, itab'lardan ulaşılan somut tipler (gösterici ise öğesi, `PtrToThis`; 1.26'da `typelink` de), yöntem tabloları.
2. Denetimler: T1 itab yuvası ↔ arayüz yöntem adı (`runtime.unreachableMethod` hedefi dışlanır); T2 `Tfn` / `Ifn` ↔ yöntem adı (son bileşen: köşeli ayraç öbekleri atıldıktan ve `-fm` eki soyulduktan sonra) ve T2p paket yolu (`%2e` gibi kaçışlar çözülerek); T5 `funcID` çapası; T6 biçim. T3 (dosya ↔ paket) ve T4 (derleme birimi çoğunluğu) hesaplanır ama **zayıf işaret** olarak ayrı tutulur (T3 yanlış alarmı derleme düzenine bağlı: `gh` 153 / 31 483, `limactl` 2 365 / 32 532; T4 1 341 / 39 697).
3. Fonksiyon damgası: `cift_kaynak` (T1 ∪ T2 ∪ T5 kapsamında ve uyumlu), `tek_kaynak` (kapsam dışında), `tutarsiz` (kapsamda ve uyumsuz). İkili özeti: kapsanan / uyumsuz sayıları, P-ÜV1'in K denetimleri.
4. İkili düzeyi karar: güçlü işaretli (T1, T2, T2p, T5, T6) fonksiyon sayısı > 0 ise rapora uyarı; oranı > %1 ise ikili `ust_veri_supheli` (eşik ilk ölçümle ön kayıtlı: bozulmamış 11 dilimde bu oran ölçülür; `gh`'te 1 / 40 384 (tek T2p), `limactl`'de T2p 83).
5. Bozma deneyi betiği `scripts/measurement/ustveri_bozma.py`: araştırma betiğinin (A son bileşen, B paketler arası takas, C paket içi takas, D tutarlı sahtecilik, E komşu `_func` takası; tohum 20261119; tür başına 200) ürün okuyucusuna bağlanmış hâli; özgün dosya değişmez, bozuk kopya bellekte.
6. E türü için içerik denetimi araştırması (kod yazmadan önce ölçüm): `pcsp` tablosunun ilk sıfırdan farklı değeri ile giriş bölümündeki yığın ayarlama komutunun (arm64: `sub sp` / `stp …!`; `capstone` 5.0.7 kurulu) uyumu bozulmamış ikilide yüzde kaç tutuyor? ≥ %99 tutuyorsa K10 denetimi olarak ekle ve E'yi yeniden ölç; tutmuyorsa "neden olmadı" yaz, ekleme.
7. Üretici adım yok: `go_metadata_recovery` çıktısına damga eklemek P-ÜV6'da (`go_functions` satırına `dogrulama` alanı); bu paket yalnız kitaplık + ölçüm.

**Kabul ölçütü.** Bozulmamış ikilide sayılar `$V/dusman/<ad>_taban.json` ile aynı: `gh` T1 6 333 / 6 333, T2 26 258 / 26 258, T2p 26 236 / 26 238, T5 19 / 19, ikinci kaynaklı 13 188; `limactl` T1 8 426 / 8 426, T2 31 105 / 31 105, T5 20 / 20, ikinci kaynaklı 15 608. Bozma deneyi (aynı tohum) `$V/dusman/<ad>.deney.json` ile aynı sayılar: A 66 / 200 ve 84 / 200 (ikinci kaynaksızda 0); B 181 ve 192; C 73 ve 82; D 0 / 86 ve 0 / 451; E K4 160 ve 166. Bozulmayan fonksiyonlarda yeni güçlü işaret 0 (10 koşu). Ek ikililer (ilk ölçüm; ön kayıtta yalnız yön): Ollama arm64 (1.26.0), colima (1.26.4), docker-cli (1.24.4) bozulmamış hâlde T1 ve T2 uyumu ≥ %99,9.

**Ön kayıt metni:**
> H1: bozulmamış `gh` ve `limactl` sayıları başvuruyla aynı. H2: aynı tohumla A–E sonuçları başvuruyla aynı. H3: Go 1.26 (`__itablink` yolu) ve 1.24 ikililerinde T1 / T2 uyumu ≥ %99,9; tutmazsa okuyucu o sürüm için `desteklenmiyor` der. H4 (beklenen olumsuz, yinelenir): D türünde yakalanan 0. H5 (açık): K10 içerik denetimi bozulmamış ikilide ≥ %99 uyum verirse E'de yakalama ≥ %95'e çıkar; vermezse eklenmez. H6: T3'ün yanlış alarm oranı ikiliden ikiliye ≥ 10 kat değişir (153 / 31 483 ↔ 2 365 / 32 532); bu yüzden T3 kararı etkilemez.

**Sınama ve mutasyon.** Sentetik: 2 tip + 1 arayüz + 1 itab + yöntem tabloları (1.27 ve 1.26 yerleşimi ayrı), budanmış yöntem, tip parametreli alıcı, kaçışlı paket yolu. En az 14 test. Mutantlar (≥ 8): `unreachableMethod` dışlaması kalkar; köşeli ayraç soyulmaz; `Uncommon` ofseti yapı için 56 alınır; itab adımı `24 + 8n` yerine `32 + 8n`; T3 güçlü işaret sayılır; `tutarsiz` damgası `tek_kaynak` diye döner; metin ofseti −1 adres sayılır; kaçış çözülmez.

**Ürüne nasıl girer.** Kitaplık; damga P-ÜV6'da köken kaydına ve rapora bağlanır. Bayrak: `enable_go_metadata_integrity` (öntanım kapalı; açıkken `go_metadata_recovery` adımı damgayı hesaplar — bağlama P-ÜV6'da).

---

## P-ÜV8 — Ölçüm birimi ve kabul ölçümü

**Amaç.** Üst veri kanalları için geliştirme setinden bağımsız, GT'li bir ölçüm birimi: sembollü ikilinin soyulmuş kopyasında kanalın verdiği ad ↔ özgün ikilinin sembol tablosu. Kanal düzeyi (Ghidra'sız) ve ürün düzeyi (Ghidra'lı, küçük hedefler) ayrı.

**Dokunacağı dosyalar (hepsi yeni):** `scripts/measurement/ustveri_set.py` (set hazırlığı), `scripts/measurement/ustveri_olc.py` (kanal düzeyi ölçüm + tablolar), `scripts/measurement/ustveri_urun.py` (ürün düzeyi), `docs/arge/2026-11-19_mythos/ustveri/olcum/` (ön kayıt, sonuç), `tests/test_puv8_olcum.py` (ölçü işlevlerinin birim testi).

**Dokunmayacağı:** `scripts/measurement/urun_olc.py`, `ks1_olc.py` (içe aktarılabilir; `oran`, `wilson`), `karadul/`.

**Kalemler:**
1. Set hazırlığı (`ustveri_set.py`): §9'daki sembollü ikililerin (docker-cli, docker-compose, iTerm2 arm64 dilimi, llama-server arm64 dilimi, terminal-notifier) kopyasını veri köküne al (`~/karadul_olcum/ustveri_set/<ad>/{orig,bin,gt}`), `/usr/bin/strip` ile soy (conda `strip` değil; `workspaces/olcum_mac/corpus/manifest.json` düzenindeki gibi sha256 ve sürüm kaydıyla), GT'yi özgün ikilinin sembol tablosundan çıkar (adres → ad kümesi). Bölme önceden yazılır: **keşif** = terminal-notifier, docker-cli; **sınama** = docker-compose, iTerm2, llama-server. Kanal okuyucuları keşifte hata ayıklanır; sınama sayıları okuyucu dondurulduktan sonra bir kez alınır.
2. Ad eşitliği tanımı (özgün ad üstünden; `c_identifier` uygulanmadan): Go: birebir + `.abi0` eki + orta nokta yazımı; ObjC: birebir + sembolde kategori adı; Swift: `xcrun swift-demangle` çıktısı; C++ sınıf adı: `__ZTI` / `__ZTV` soneki birebir. Kurallar betikte tek yerde, testli.
3. Soyulmuş kopyada kanal düzeyi ölçüm (`ustveri_olc.py kanal`): kanal başına ad verilen, doğru, yanlış, GT'siz; Wilson %95; karar A-2 satırı (alt sınır ≥ 0,909).
4. Bütçe tablosu (`ustveri_olc.py butce`): hedef başına fonksiyon, kesin, yuva, sembol, kalan (araştırma `butce.py` ile aynı tanımlar); `$V/butce.json` ile karşılaştırma.
5. Ürün düzeyi (`ustveri_urun.py`; P-ÜV6'dan sonra): küçük hedeflerde bayraklar açık / kapalı ürün koşusu — terminal-notifier (ObjC, 92 fonksiyon), colima (Go 1.26.4, 13 121 fonksiyon), Rectangle arm64 (Swift, 2 401 fonksiyon), btop (C++, 1 952 fonksiyon), Ollama arm64 (gösteri hedefi; koşu süresi uzun: tek başına, makine boşken). Koşu komutu: `GHIDRA_INSTALL_DIR=… PYTHONHASHSEED=0 PYTHONDONTWRITEBYTECODE=1 KARADUL_CACHE_DIR=<koşuya özel> python -m karadul analyze <ikili> --config <bayrak yaml'ı> --skip-dynamic --output-dir <ws> --output <out>`. Sayılacaklar: `stats["naming_channels"]` (kanal başına `aday`, `tuttu`, `ghidra_adli`, `ghidra_fonksiyonu_yok`, `gecersiz_ad`), ad haritasında üst veri kaynaklı ad sayısı, bayrak kapalı kolla fark.
6. Ghidra karşılaştırması: bayrak kapalı kolda Ghidra'nın kendi adlandırdığı (jenerik olmayan) fonksiyonlar ∩ üst veri adları; ad aynı / farklı / yalnız Ghidra / yalnız üst veri. Ollama için gösteri koşusunun çıktısı (`~/karadul_olcum/runs/gosteri-2026-11-19/ollama/ws`, `CIKIS` oluşmuşsa) yeniden koşmadan kullanılır.
7. Sonuç belgesi: kanal başına kabul tablosu, BULGULAR §7'deki "Ghidra'nın zaten adlandırdığı" ve "Karadul'un bugün adlandırdığı" sütunlarının doldurulmuş hâli.

**Kabul ölçütü.** Kanal düzeyi (sınama ikilileri, soyulmuş kopya): Go ad doğruluğu Wilson alt sınırı ≥ 0,999 (beklenen 90 077 / 90 077); ObjC ≥ 0,999 (beklenen 33 611 / 33 611); C++ sınıf adı ≥ 0,99 (1 994 / 1 994); Swift erişim fonksiyonu adı P-ÜV3 eşiği. Soyma, üst veriyi değiştirmemeli: soyulmuş ve özgün kopyada kanal çıktısı aynı (fark 0). Ürün düzeyi: bayrak kapalı kolun ad haritası tabanla aynı; bayrak açık kolda üst veri kaynaklı her ad GT'li hedeflerde doğru (yanlış 0), `ghidra_fonksiyonu_yok` sayısı raporlanır (eşik yok: ilk ölçüm).

**Ön kayıt metni:**
> H1: `/usr/bin/strip` sonrası Go / ObjC / Swift / RTTI kanal çıktıları özgünle aynı (4 kanal × 5 ikili, fark 0). H2: sınama ikililerinde kanal kesinlikleri yukarıdaki eşikleri tutar. H3: ürün düzeyinde bayrak kapalıyken ad haritası değişmez (5 / 5 hedef). H4: Ollama arm64'te Go kanalının `tuttu` sayısı ≥ 9 540 (10 600 adın en az %90'ında Ghidra o adreste adsız bir fonksiyon açmıştır); tutmazsa neden `ghidra_fonksiyonu_yok` / `ghidra_adli` kırılımıyla yazılır. H5 (açık, yön bildirilmez): Ghidra'nın ObjC çözümleyicisi Ollama'daki 151 yöntemin kaçını zaten adlandırıyor.

**Sınama ve mutasyon.** Ölçü işlevleri (ad eşitliği kuralları, Wilson, bütçe kümeleri) için birim testi ≥ 10; mutant ≥ 5 (`.abi0` kuralı her eki soyar; kategori kuralı sınıfı da soyar; payda GT'siz adresleri sayar; kesin ∪ sembol yerine toplam; Wilson'da n yerine k).

**Ürüne nasıl girer.** Ölçüm altyapısı; ürün kodu değil.

---

## P-ÜV6 — Kanal bağlama, bayraklar, etiket ve güven kuralı

**Amaç.** P-ÜV1–5 ve 7'nin çıktısını ürün akışına bağlamak: üretici adımlar Faz 1 listesine, ad kanalları birleştiriciye, bayraklar `config.py`'ye, etiket ve güven köken kaydına ve rapora. **Tek ajan; ortak dosyalara yalnız bu paket dokunur.**

**Dokunacağı dosyalar:**
- `karadul/config.py` (yeni bayraklar; `INERT_SETTINGS`'ten `enable_rtti_recovery` kaydının kaldırılması)
- `karadul/stages.py` (yalnız Faz 1 adım listesi: satır 2505–2530 civarı)
- `karadul/pipeline/steps/_feedback_naming_candidates.py` (`K4_CHANNEL_FLAGS`, yeni `_add_go_pclntab`, `_add_objc_methods`, `_add_swift_types`; `_add_rtti` kararı)
- `karadul/pipeline/steps/_feedback_naming_merger.py` (`k4_inputs`: yeni yapıtlar)
- `karadul/core/naming_labels.py` (etiket ve ölçülmüş kesinlik tablosu)
- etiketi okuyan yerler: `karadul/reporting/report_data.py`, `karadul/reconstruction/tarif/baglama.py`, `karadul/reconstruction/tarif/alt_kanal.py`, `karadul/reconstruction/c_namer.py`, `karadul/lm/guard.py`, `karadul/lm/tools/__init__.py`, `scripts/measurement/alt_kanal.py`, `scripts/measurement/alt_kanal_olc.py`, `scripts/measurement/urun_olc.py` (yalnız yeni etiket değeri gerekiyorsa; `grep -rn "LABEL_CERTAIN\|NAME_LABELS\|GUVEN_ETIKETLERI"` ile tam liste çıkar)
- yeni `tests/test_puv6_baglama.py`, `scripts/measurement/mutation_specs_puv6.json`, `on_kayit_PUV6.md`, `P-UV6.md`

**Dokunmayacağı:** P-ÜV0–5, 7'nin modülleri (yalnız içe aktar); `karadul/analyzers/go_binary.py`, `cpp_rtti.py`, `swift_binary.py` (emeklilik ayrı karar).

**Kalemler:**
1. Bayraklar (`binary_reconstruction`, hepsi öntanım **`False`**): `enable_go_metadata_recovery`, `enable_objc_metadata_recovery`, `enable_swift_metadata_recovery` (üretici adımlar; `enable_rtti_recovery` var), `enable_go_pclntab_naming`, `enable_objc_metadata_naming`, `enable_swift_metadata_naming` (ad kanalları; `enable_rtti_naming` var), `enable_macho_entry_main`, `enable_go_metadata_integrity`. `tests/test_p15a_etkisiz.py` yeni alanları okunan saymalı (okuyan kod bu pakette).
2. Faz 1 listesine dört üretici adım (`go_metadata_recovery`, `objc_metadata_recovery`, `swift_metadata_recovery`, `rtti_recovery`) `binaryninja_analysis`'ten sonra, `type_recovery_consumer`'dan önce. Bayrak kapalıyken adım `kapali` durumu yazar ve iş yapmaz; koşu süresine etkisi ölçülür (≤ 0,1 sn).
3. Ad kanalları: P13b'nin kuralı korunur — aday **yalnız** Ghidra'nın o adreste adsız bıraktığı fonksiyona; anahtar Ghidra'nın adı; sayaçlar `stats["naming_channels"]`. Kaynak adları: `go_pclntab`, `objc_method`, `swift_type_accessor`, `rtti`.
4. Özgün ad korunur: Go ve ObjC adları C tanımlayıcısı değildir. Köken kaydına `ozgun_ad` alanı yazılır (`runtime.mapaccess1`, `-[AppDelegate applicationDidFinishLaunching:]`); koda yazılan tanımlayıcı `c_identifier` çıktısıdır; rapor ve arayüz `ozgun_ad`'ı gösterir. Ölçüm eşitliği `ozgun_ad` üstünden (P-ÜV8 kalem 2).
5. **Etiket kuralı (öneri; ana oturum onaylar).** Bozma deneyi üst veri adının doğrulanamadığını gösterdi (BULGULAR §6.2). Bu yüzden üst veri kanallarının adı `kesin` etiketi **almaz**; yeni bir etiket değeri eklenir: `üst veriden` (`LABEL_METADATA`). Anlamı: "ad ikilinin dil üst verisinden okundu; derleyicinin yazdığı hâliyle ölçülmüş kesinlik ≥ %95; ad metni değiştirilebilir." Köken kaydına `ust_veri_dogrulama`: `cift_kaynak` / `tek_kaynak` / `tutarsiz` / `olculmedi` (ObjC, Swift, RTTI için bugün `olculmedi`). `tutarsiz` damgalı fonksiyonun adı yazılmaz; kanıt satırı olur. İkili `ust_veri_supheli` ise bütün üst veri adları kanıt satırına iner ve rapora uyarı girer. Etiket sözlüğü `scripts/measurement/alt_kanal.py` `GUVEN_ETIKETLERI` ile eşit kalmalı (test kilitli): ikisi birlikte güncellenir.
6. Güven: `UNMEASURED_SOURCES`'tan çıkan kanallar için `MEASURED_PRE_NAME_PRECISION` benzeri tablo (`MEASURED_METADATA_PRECISION`): (doğru, ad verilen, Wilson alt sınırı) — değerler P-ÜV8'in **sınama** ikililerindeki kanal düzeyi ölçümünden (bu belgedeki sayılardan değil). Karar A-2: alt sınır ≥ 0,909 ise ad, değilse kanıt satırı. RTTI yuva adayı (`Sınıf_vfunc_N`) tam eşitlik ölçüsünde doğru ad değildir → **kanıt satırı** olarak yazılır, ad olarak değil (K-2: ölçülmüş kuralı olmayan kanal ad yerine kanıt satırı yazar); `_add_rtti` buna göre değiştirilir. Swift yuvaları da kanıt satırı.
7. Eski Go kanalı: `go_demangler` (nm) kanalı kalır (sembollü ikilide çalışıyor) ama `go_pclntab` açıkken aynı adrese ikinci aday üretmez. `GoBinaryAnalyzer._extract_gopclntab`'ın `strings` + düzenli ifade yolu adres vermediği ve %20,9–%30,2 yanlış "ad" ürettiği için rapora "fonksiyon adı" diye yazılmamalı: bu paket yalnız bulguyu `P-UV6.md`'ye yazar ve ayrı onarım paketi önerir (kapsam küçültülmez kuralı: silme değil, `go_metadata_recovery` çıktısına bağlama).
8. Birleşik ölçüm: (a) geliştirme setinin 119 ikilisinde bütün bayraklar açıkken ad haritası değişmez (beklenti: fark 0; set düz C, Mac kolunda yalnız `main`); (b) P-ÜV8 kalem 5'in ürün düzeyi koşuları.

**Kabul ölçütü.** Öntanımda (bütün bayraklar kapalı) 119 ikilinin ad haritası ve `out/src` tabanla bayt bayt aynı (5 ikilik örnekte tam; 119'da ana oturumun birleşik ölçümünde). Bayraklar açıkken: 119 ikilide değişen ad yalnız Mac kolundaki `main` (≤ 2 ikili: htop, tmux; htop'ta thunk); üst veri kanallarının yazdığı ad 0 (set düz C). Ürün düzeyi hedeflerde üst veri kaynaklı adların tamamı köken kaydında `label = üst veriden`, `ozgun_ad` dolu, güven tablodan; `tutarsiz` damgalı ad 0. Tam takım yeşil; `test_p15a_etkisiz` yeşil.

**Ön kayıt metni:**
> H1: öntanımda ad haritası ve kod 5 / 5 ikilide tabanla aynı. H2: bütün bayraklar açıkken geliştirme setinden 5 ELF ikilisinde (cat, expr, ls, tree, pzstd) değişen ad 0 ya da yalnız `pzstd`'de RTTI **kanıt satırı** (ad değil). H3: colima'da `go_pclntab` kanalının `tuttu` sayısı ≥ 11 773 (13 081 adın %90'ı), yazılan adların GT'siz olduğu için doğruluğu yapısal denetimle; docker-cli soyulmuş kopyasında yazılan adların ≥ %99,9'u GT ile aynı (`ozgun_ad` üstünden). H4: terminal-notifier soyulmuş kopyasında ObjC kanalı 32 yöntemin Ghidra'nın adsız bıraktıklarına ad yazar; yanlış 0. H5: üst veri kaynaklı hiçbir ad `kesin` etiketi taşımaz. H6: P-ÜV7'nin A türü bozuk `gh` kopyasında (Ghidra'sız kanal sınaması) ikinci kaynaklı 66 fonksiyon `tutarsiz` damgası alır ve adları yazılmaz; ikinci kaynaksız 134 fonksiyonun bozuk adı **yazılır** (beklenen sınır; kayda geçer).

**Sınama ve mutasyon.** Birim testleri sahte yapıtlarla (P13b `tests/test_p13b_kanallar.py` düzeni): kanal kapalı / açık; Ghidra adlı fonksiyona aday yok; `tutarsiz` ad yazılmaz; `ust_veri_supheli` ikilide hepsi kanıt satırı; `ozgun_ad` korunur; RTTI yuvası kanıt satırı; etiket sözlüğü eşitliği. En az 16 test. Mutantlar (≥ 10): bayrak öntanımı `True`; adlı fonksiyona da aday; `tutarsiz` süzgeci kalkar; etiket `kesin` yazılır; `ozgun_ad` yerine tanımlayıcı; güven sabit 0,95; RTTI yuvası ad adayı olur; şüpheli ikilide adlar yazılır; iki Go kanalı aynı adrese iki aday; adım listesinde üretici tüketiciden sonra.

**Ürüne nasıl girer.** Yukarıdaki dokuz bayrak, öntanım kapalı. Öntanımda açma kararı P-ÜV8'in sonuç belgesinden sonra ana oturumda (K-4).

---

## P-ÜV9 — Açık ölçümler

**Amaç.** Bu turda veri ya da araç olmadığı için kalan ölçümler. Kod yazmadan önce sayım; her biri kendi ön kaydıyla.

**Dokunacağı dosyalar:** `scripts/arge/ustveri/` altına yeni betikler; `docs/arge/2026-11-19_mythos/ustveri/acik_olcum/`. Ürün koduna dokunmaz.

**Kalemler:**
1. **Ghidra ↔ üst veri (Ollama).** Gösteri koşusunun `ws/` çıktısından (salt okur): Ghidra'nın fonksiyon sayısı ↔ `LC_FUNCTION_STARTS` (12 952); Ghidra'nın jenerik olmayan adlandırdığı fonksiyonlar; bunların üst veri adlarıyla kesişimi ve ad eşitliği; Ghidra'nın Go 1.26 uyarısından sonra Go fonksiyonlarına verdiği ad sayısı (beklenen 0'a yakın; yön ön kayıtta).
2. **Başlangıç tablosu olmayan Go ikilisi (`gh`).** Ghidra kaç fonksiyon açıyor (40 384 girişe karşı)? Açmadıklarında kanal `ghidra_fonksiyonu_yok` sayar ve ad yazamaz. Bu sayı büyükse (> %10) "üst veri fonksiyon başlangıçlarını Ghidra'ya analizden önce tohumla" paketi önerilir (Ghidra betiği; ayrı plan).
3. **Go ≥ 1.26 için sembollü doğrulama.** §9'daki indirme onaylanırsa: aynı kaynağın soyulmamış ve `-ldflags="-s -w"` derlemesi; kanal çıktısı ↔ sembol tablosu.
4. **ELF ve PE Go.** Aynı araç zinciriyle `GOOS=linux` (amd64, arm64) ve `GOOS=windows` derlemeleri: `.gopclntab` bölümü, `moduledata` bulma (ELF'te `R_*_RELATIVE`), PE'de bölüm adı olmadan imza taraması. Kabul: P-ÜV1 ölçütleri.
5. **Satır içi gömülmüş fonksiyonlar.** `FUNCDATA_InlTree` (ağaç kaydı: `funcID` u8, 3 dolgu, `nameOff` i32, `parentPc` i32, `startLine` i32; kaynak `src/runtime/symtabinl.go` — okumadan önce doğrula) → "bu gövdeye şu fonksiyonlar gömüldü" kanıt satırı. Sayım: fonksiyon başına gömülü ad sayısı dağılımı.
6. **ObjC / Swift / C++ bozma deneyi.** Seçici dizgisi, sınıf adı, typeinfo adı için P-ÜV7 düzeninde deney ve ikinci kaynak adayları: (a) benimsenen protokolün yöntem listesi (iTerm2'de 6 315 / 41 305 kayıt); (b) içe aktarılan üst sınıfın yöntemleri (SDK başlıklarından belirlenimci tablo); (c) seçici başvurusu olan yöntemler.
7. **`main`'den yayılan kanallar.** P-ÜV5'ten sonra Mac'te `usage` ve çağrı grafiğinden yayılan kanalların farkı (I2'nin ikinci yarısı).
8. **Garble / ad karıştırılmış Go.** Adları karıştırılmış bir Go ikilisinde (indirme onayıyla) denetimlerin verdiği sinyal: paket yolu / dosya yolu boş ya da karma mı; `__go_buildinfo` bağımlılık listesi duruyor mu (KİMLİK hattına veri).

**Kabul / durma.** Her kalem bir sayı tablosu ve "pakete dönüşür / dönüşmez" hükmüyle kapanır. Kalem 2'de oran ≤ %10 ise tohumlama paketi açılmaz.

---

## 9. Gerekli veri ve araç

**Makinede hazır (indirme yok):**

| Ne | Yol | Lisans / kaynak | Kullanım |
|---|---|---|---|
| Ollama 0.40.3 uygulama ikilisi (evrensel) | `~/karadul_olcum/runs/gosteri-2026-11-19/ollama/girdi/Ollama` | MIT | Go 1.26 + ObjC + C++; gösteri hedefi |
| `ollama` komut satırı, `llama-server` | `/Applications/Ollama.app/Contents/Resources/` | MIT | Go 1.26 + C++; `llama-server` sembollü (RTTI GT) |
| `gh` 2.105.0, `limactl` 2.3.0, `colima` 0.10.3, `docker` 29.10.0, `arduino-cli` 1.6.0 | `/opt/homebrew/Cellar/<paket>/<sürüm>/bin/` | MIT, Apache-2.0, MIT, Apache-2.0, GPL-3.0 | Go 1.26.4 – 1.27.4, soyulmuş |
| docker-cli, docker-compose | `/Applications/Docker.app/Contents/Resources/bin/docker`, `…/cli-plugins/docker-compose` | Apache-2.0 (açık kaynak projelerin derlemesi; paketin kapalı parçalarına dokunma) | Go 1.24.4 / 1.23.8, **sembollü** (Go GT) |
| iTerm2 3.7.7 | `~/Applications/iTerm.app/Contents/MacOS/iTerm2` | GPL-2.0 | ObjC + Swift + C++, **sembollü** (GT) |
| Rectangle 0.94 | `/Applications/Rectangle.app/Contents/MacOS/Rectangle` | MIT | Swift, soyulmuş |
| terminal-notifier 3.1.0 | `/opt/homebrew/Cellar/terminal-notifier/3.1.0/terminal-notifier.app/Contents/MacOS/terminal-notifier` | MIT | ObjC, sembollü, küçük |
| btop 1.4.8 | `/opt/homebrew/Cellar/btop/1.4.8/bin/btop` | Apache-2.0 | C++, kısmen soyulmuş |
| Geliştirme setinin Mac ikilileri ve GT'si | `workspaces/olcum_mac/corpus/{htop,tmux}`; kabul seti `~/karadul_olcum/runs/onarim-2026-11-18/P-S3b/mac_kabul/corpus/` | — | `main` |
| `pzstd` (C++ ELF) ve dbgsym | `~/karadul_olcum/n1_debian13/` | — | ELF RTTI |
| Araçlar | `/usr/bin/{otool,nm,lipo,strip,c++filt}`, `xcrun swift-demangle`, Python `lief` 0.17.6, `capstone` 5.0.7, `pyelftools` | — | — |

Araştırma kopyaları `$V/hedef/` altında duruyor (824 MB; silme ana oturumun / Berke'nin onayına bağlı).

**İndirme listesi (Berke onayı gerekir; bu turda indirilmedi):**

| Ad | Kaynak | Boyut | Neden |
|---|---|---|---|
| `go1.26.11.darwin-arm64.tar.gz` | https://go.dev/dl/ (resmî; sha256 `e3a42e67…cdff57`, dizinden doğrulanır) | 64 730 001 bayt | Go 1.26 için sembollü + soyulmuş derleme çifti (P-ÜV9 kalem 3, 4) |
| `go1.27.4.darwin-arm64.tar.gz` | https://go.dev/dl/ (sha256 `91a44a2b…bd0bb4`) | 68 231 011 bayt | Go 1.27 için aynı |

- Boyut ve özetler go.dev/dl JSON dizininden, 2026-11-19. Toplam 132 961 012 bayt.
- **Karar gerektiren nokta:** bu arşivler derleyicidir; kullanmak indirilen dosyayı **çalıştırmak** demektir (A-4 onayı "hiçbir indirilen dosya çalıştırılmaz" koşuluyla verilmişti). Derlenecek kaynak arşivin kendi içindedir (`cmd/gofmt`, `cmd/vet`, `cmd/go`): başka indirme gerekmez; ağ erişimi kapalı (`GOFLAGS=-mod=vendor`, `GOPROXY=off`) derlenir. Onay verilmezse Go ≥ 1.26 için bire bir ad doğrulaması açık kalır; yapısal denetimler yeterli sayılıp sayılmayacağına ana oturum karar verir.
- Ad karıştırılmış Go örneği (P-ÜV9 kalem 8) için ayrıca kaynak gerekmez: aynı araç zinciriyle derlenmiş ikili üstünde P-ÜV7'nin D türü bozması zaten bu durumu modelliyor; gerçek `garble` çıktısı istenirse ayrı liste yazılır.

## 10. Riskler ve bilinmeyenler

1. **Sürüm kayması.** Go her altı ayda yerleşimi değiştirebiliyor (1.26 `textStart`, 1.27 tip verisi). Okuyucu bilmediği imzada / sürümde ad üretmemeli; yapı denetimleri (K1–K9) sürümden bağımsız emniyet ağıdır. Yeni sürüm desteği = resmî kaynaktan okuma + bir sembollü derleme çifti.
2. **Doğrulayıcı tek kaynaklı.** Bütün kesinlik sayıları sembol tablosuna karşı; sembol tablosu da aynı derleyicinin çıktısı. "Ad geliştiricinin yazdığı ad" anlamında doğru; "ad işlevi doğru anlatıyor" anlamında bir şey söylemiyor.
3. **Ghidra'nın fonksiyon bulması.** Kanal yalnız Ghidra'nın açtığı fonksiyona ad yazabiliyor; `gh` gibi başlangıç tablosu olmayan ikilide bu oran bilinmiyor (P-ÜV9 kalem 2).
4. **Etiket kararı.** `üst veriden` etiketi yeni bir değer; arayüz, rapor, KaradulLM ve ölçüm betikleri etiket sözlüğünü paylaşıyor. Onaylanmazsa seçenek: `doğrulanmadı` etiketi + `ust_veri_dogrulama` alanı (anlam kaybı: ölçülmüş %100 kesinlik "ölçülmedi" gibi görünür).
5. **ObjC / Swift / C++ için bozma deneyi yok.** Bu dillerde alan sınıflaması kaynak okumasına dayanıyor; P-ÜV9 kalem 6'ya kadar yön gösterici.
6. **Kitaplık ağırlığı.** Go adlarının %72,3–%93,6'sı kitaplık. "Adlandırılan fonksiyon oranı" analiste değeri olduğundan yüksek gösterebilir; rapor "programın kendi paketleri" sayısını ayrı vermeli (Ollama uygulaması: 1 257 Go + 151 ObjC).
7. **Lisans ve kaynak.** docker-cli / docker-compose kopyaları kapalı kaynak bir paketin içinden; ikililer açık kaynak. Depoya ikili ya da ad listesi girmez; ölçüm çıktıları yalnız sayıdır.
8. **Evrensel ikili.** Ürün arm64 dilimini seçiyor; okuyucular aynı ince dosyayı almalı (yanlış dilimde adresler tutmaz, kanal `ghidra_fonksiyonu_yok` sayar).
