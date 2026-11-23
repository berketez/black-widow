# Uygulama oturumu 2 — durum (2026-11-23)

Yaşayan kayıt: hangi paket kimde, ne main'e girdi, hangi karar verildi. Oturum yarıda kalırsa buradan sürdürülür. Önceki oturumun kaydı `docs/arge/2026-11-20_dalga0/DURUM.md`; plan `docs/arge/2026-11-19_mythos/SONRAKI_OTURUM.md` §8.

## Kurallar (bu oturum)

- Berke (08:0x): "planlamalar Mythos'ta olacak, kodu yazanların hepsi Opus olacak; max 4 ajan yollayabilirsin, max 1 tane Mythos."
- Ana oturum Mythos 5.2: plan, gönderim metni, birleştirme, bağımsız doğrulama. Kod yazmaz.
- Ajanlar: Opus 5.5 xhigh, kendi worktree'si; Mythos ajanı yalnız tasarım belgesi (ÖL-10; A-24).
- **İlk dilim 8 ajan** (aynı anda en çok 4): PUV6a, P16e, PUV3, OL10 (08:1x'te gönderildi); yer açıldıkça PUV5, OL1, PUV4, PUV7. Takılan ajanın yerine açılan sayıya dahildir. Dilim bitince sonraki dilim ayrıca ilan edilir (CLAUDE.md §26).
- Ortak brif `ORTAK_D1.md`; gönderim metinleri `gonderim/`; yamalar `yamalar/`; koşu kökü `~/karadul_olcum/runs/dalga1-2026-11-23/`.

## Sıra mantığı: üç zincir + serbest paketler

Aynı dosyaya yazan paketler sıralı gider (`karsi/CAKISMA.md` §1). Kalan işin kritik yolu iki uzun zincirdir; her zincire bir yuva ayrıldı, öbür yuvalar yalnız yeni dosya yazan paketlere.

| Zincir | Ortak dosya | Sıra |
|---|---|---|
| Ad bağlama | `_feedback_naming_*.py`, `naming_labels.py`, `stages.py`, `baglama.py` | **PUV6a** → PUV5 (`stages.py`) → PK-1 → PK-5 → PK-4 → PK-7 → P-ÜV6b (Swift, RTTI, Go tutarlılık damgası, `main` bayrağı) |
| Ghidra köprüsü | `karadul/ghidra/headless.py` (+ `bsim.py`) | **P16e** → ÖL-1 → ÖL-2 → HZ-2 → ÖL-3 + HZ-4a → HZ-3 → ÖL-6 → ÖL-10 alt paketleri |
| `c_namer` | `karadul/reconstruction/c_namer.py` | P12d → ÖK-1 (aynı ajan; A-20) → ÖK-2 (R1 %79,8 ile yeniden ele alınacak; A-29) |
| Serbest (yalnız yeni dosya ya da ayrık dosya) | — | **PUV3**, PUV4, PUV7, OKUMA, MUTBAKIM-2, ÖL-4, D1, D4, P24, P18, PK-2 → PK-3, P03b / P08b / P10b, ÖL-5a, D2 → ÖL-3b → HZ-6, HZ-7a |

P-ÜV6 ikiye bölündü (ana oturum kararı): plan P-ÜV6'yı altı okuyucu main'deyken tek paket sayıyordu; bugün yalnız Go ve ObjC okuyucuları main'de ve gerçek uygulamadaki en büyük kazanç onlarda (Ollama 10 600 + 151 ad). PUV6a onları bağlar ve ortak altyapıyı kurar; P-ÜV6b kalan kanalları aynı kalıpla ekler.

## Ana oturum

| Saat | İş | Sonuç |
|---|---|---|
| 08:00–08:10 | Durum doğrulaması | main = origin/main = `9c9b2d4`, ağaç temiz; yük 3,3; boş alan 191,8 GB (kullanılan 774,3 GB); Ghidra kuyruğu boş; açık başka oturum: karadelik (ayrı proje) |
| 08:10 | Bu dalganın belgeleri | `ORTAK_D1.md`, `gonderim/{PUV6a,P16e,PUV3,OL10}.md`, bu dosya (`f2b0db5`) |
| 08:11 | İlk dört ajan gönderildi; bekçi kuruldu | `bekci_d0.py` (Monitor, 30 dk'da bir yeniden); OL10 için "model düşmesi" satırı beklenen (Mythos ajanı) |
| 08:2x | Sıradaki dört paketin metni | `gonderim/{OL1,PUV4,PUV5,PUV7}.md` |

## Paketler

| Paket | Ajan | Model | Durum | Not |
|---|---|---|---|---|
| PUV6a | a42e3d495be90379d | Opus | çalışıyor (08:11) | sert son 11:45; ilerleme `docs/arge/2026-11-19_mythos/ustveri/P-UV6a.md` |
| P16e | a55c97e3a05c70d6f | Opus | **bitti 09:14; main'de** (`…627d30f`, 14 commit) | `headless.py`'de `caller_sort_key` + üç listede tek `sort` (+20 satır): çağıran sırasından gelen ham fark 8 / 8 ikilide 0; 2 020 `.c`'de `// Callers:` artık en küçük adresli 5 çağıran. Envanter 15 nokta, 3'ü onarıldı. **Ön kayıt: H1 7 / 8, H2 7 / 8 TUTMADI** (Ghidra decompiler'ı zstd `FUN_001063c0`'da 6 koşunun 1'inde iki geçici değişkeni yer değiştirdi; `out/naming_map.json` 8 / 8 eşit); **H3 TUTMADI** (gönderim metnindeki koşu sırası BSim deposunu farklı doldurdu — ana oturumun hatası; taban sırasıyla ek koşu `sonra_3`'te fark 8 / 8'de 0); H4 yük altında, hükümsüz (mikro ölçüm: sıralama döküm süresinin %0,014'ü). 22 test, mutant 13 / 13; ajanın tam takımı 10 778 / 0. **Bağımsız doğrulama (main `e2c079d`, `dogrulama-d1`): 4 test dosyası 70 / 0; mutasyon p16e 13 / 13, hz1 13 / 13, p16a 33 / 33, p13a 22 / 22; S8 taban ↔ `sonra_3` sıra-normal fark 8 / 8'de 0; `sonra_2` ↔ `sonra_3` ham: `.c` 0, ad haritası 0, JSON farkı yalnız `ghidra_bsim.json` (koşu sırası).** Koşu kökü 3,5 GB (`~/karadul_olcum/runs/dalga1-2026-11-23/P16e/`; `s8_sonra_3` OL1'in tabanı, silinmez) |
| PUV3 | a14ae2562cbc29126 | Opus | **bitti 09:04; main'de** (`f518836..7e65127`, 12 commit + yama `a750673`) | `karadul/analyzers/ustveri/swift.py` + `swift_metadata_recovery` adımı (bayrak kapalı; Faz 1'e P-ÜV6b'de). **iTerm2 (SINAMA, bir kez): 2 627 / 3 659 tipe ad, yanlış 0** (Wilson alt 0,9985); H3 sayı şartı (≥ 3 477) TUTMADI: adsız kalan 1 032 tipin 1 030'u `private` tip, ayracı öntanımlı derlemede ikilide yok (Swift çalışma zamanı da `(unknown context at $…)` diyor). Rectangle 186 tip okundu, 180'ine ad (GT yok). H0, H1, H2, H4, H5 tuttu. Keşif verisi yerelde derlenen Swift örnekleri (3 derleme biçimi). 45 test, mutant 18 / 18; ajanın tam takımı (yamasız) 10 800 / 1 beklenen kırmızı. **Bağımsız doğrulama (main `a750673`, `dogrulama-d1`): 4 test dosyası 267 / 0 (3 atlandı); mutasyon 18 / 18; gerçek dosyada iTerm2 `ad_yazilabilir` 2 627, Rectangle 180, H1 iki ikilide tuttu.** Dürüstlük notu (ajan): dondurmadan önce iTerm2'nin GT'siz alt küme sayılarını gördü; okuyucuyu ona göre değiştirmedi. A-14 için GT'li 2. ve 3. Swift programı gerekiyor |
| OL10 | a8420740e5db17ed4 | Mythos | **bitti 08:55; main'de** (`2cc31dc..15013bb`, 8 commit, yalnız belge) | `olcek/OL10_TASARIM.md` 896 satır: üç katman (K0 Ghidra'sız, K1 çözümleme, K2 seçilenlerin decompile'ı), seçim kuralı, ad kanalı sözleşmesi, 10 alt paket (OL10-A … J). Ollama'da kendiliğinden seçilebilen küme 4 619 / 13 160; gösterinin 17 adının 17'si ilk 4 028'de; xref dökümü K1'in iki dosyasından türetilebiliyor (13 559 / 13 559 aynı). **Bağımsız denetim (ana oturum):** tam yollu 39 atıfta dosya yok 0, satır aşımı 0; 8 işlev adı çapası 8 / 8 tuttu. Kararlar A-33 |
| PUV5 | — | Opus | sırada (PUV6a main'e girince; `stages.py`) | metin hazır: `gonderim/PUV5.md` |
| OL1 | a3162396aa0075ecd | Opus | çalışıyor (09:18) | sert son 12:15; ilerleme `docs/arge/2026-11-19_mythos/olcek/OL1.md`; ölçüm koşularında eşik yaml ile (yamasız ağaçta öntanım 0) |
| PUV4 | a515cf9fb1be48c2d | Opus | **bitti 09:42; main'de** (11 commit + iki yama `68255c3`) | `karadul/analyzers/ustveri/cpp_rtti_tara.py` + `rtti_recovery` adımı (bayrak kapalı; Faz 1'e P-ÜV6b'de). **llama-server (SINAMA, bir kez): typeinfo adı 1 994 / 1 994, vtable 1 317 / 1 317 sembolle aynı; yuva → sınıf bağı 7 032 / 7 053** (ürün bağı 6 990 / 7 011, 42 belirsiz). Üç sembollü programın havuzu: ad 2 028 / 2 028 (Wilson alt 0,9981), vtable 1 328 / 1 328, yuva 7 098 / 7 119 (0,9955). Ollama iki dilim 19 / 8 / 68 (bugünkü `cpp_rtti.py` 0 vtable buluyordu); ELF pzstd 13 / 13 ad, 3 / 3 vtable (örneklem küçük). H1–H6 tuttu; H0'ın vtable maddesi tutmadı (sanal kalıtımlı 3 sınıfta kayıt `_ZTV`'den 8 bayt sonra; ad doğru). H6: `Sınıf_vfunc_N` tam eşitliği 0 → yuva kanıt satırıdır. 44 test, mutant 16 / 16; ajanın tam takımı (yamasız) 10 799 / 1 beklenen kırmızı. **Bağımsız doğrulama (main `68255c3`, `dogrulama-d2`): 4 test dosyası 223 / 0 (5 atlandı); mutasyon 16 / 16; gerçek dosyada beş hedefin üç sayısı beklenenle AYNI (Ollama ×2, llama-server, btop, iTerm2).** Dondurmadan önce sınama ikililerine bakılmadı (ajan beyanı). Koşu kökü 516 KB |
| PUV7 | ade3c0e98c5bfe6e0 | Opus | çalışıyor (08:57) | sert son 11:30; ilerleme `docs/arge/2026-11-19_mythos/ustveri/P-UV7.md` |
| PK1 | — | Opus | sırada (PUV6a main'e girince; ikinci dilim) | metin hazır: `gonderim/PK1.md` |
| OK1 | — | Opus | sırada (PUV6a main'e girince; `alt_kanal.py`; ikinci dilim) | metin hazır: `gonderim/OK1.md` (P12d + ÖK-1) |
| OL10A | — | Opus | sırada (yer açılınca; yalnız yeni dosya; ikinci dilim) | metin hazır: `gonderim/OL10A.md` |

## Berke (09:2x): "bu tüm ajanlar bitince bir duralım, mola vermek istiyorum"

- Yeni ajan gönderilmez. Çalışan dördü (PUV6a, PUV7, PUV4, OL1) bitince doğrulanıp main'e alınır, sonra durulur.
- Gönderilmeyen, metni hazır paketler (sonraki oturum / mola sonrası): PUV5, PK1, OK1 (üçü de PUV6a main'e girince; dosya kümeleri ayrık), OL10A (yalnız yeni dosya).

## P16e'den çıkan işler

- **Decompiler belirlenimsizliği (yeni kusur):** zstd `FUN_001063c0`, 6 koşunun 1'inde geçici değişken takası. Sıklığı ve nedeni ölçülmedi → küçük ölçüm paketi (P16f: aynı ikili N kez, tek iş parçacığı ↔ çok iş parçacığı kolu; ürün kodu değişmez). O ölçüme kadar "çıktı eşit" denetimlerinde tek seferlik `.c` farkı bir kez daha koşularak ayrılır.
- **S8 kıyası kuralı:** "sonra" kökü tabanla aynı ikili sırasıyla ve tek kökte koşulur (BSim deposu kökte birikiyor).
- `karadul/ghidra/scripts/{call_graph,xref_analysis,decompile_all}.py` (CLI yedek betikleri) aynı sırasız yinelemeyi kullanıyor; ürün öntanımı pyghidra yolu. P16f'ye ek kalem.
- `binary_name_extractor._get_caller_class_hint` artık en küçük adresli adlı çağıranı seçiyor; S8'de bu yoldan gelen ad 0; 119'daki etkisi bir sonraki birleşik ölçümde görülecek.
- `call_site` (ilk görülen başvuru) olduğu gibi bırakıldı (ana oturum kararı: ölçülen 5 koşuda değişmedi; değiştirmek tabandaki 35 kaydı oynatır).

## Açık kararlar ve bekleyenler

- **Üst veri bayraklarının öntanımda açılması (K-4):** A-14 kanal başına en az 3 bağımsız program ister; bugün Go'da 2, ObjC'de 2 GT'li program var. Üçüncü programlar: Go için P-ÜV9 kalem 3 (Go derleyicisiyle sembollü + soyulmuş derleme çifti; A-23 izni var), ObjC için hedef setine üçüncü sembollü ObjC ikilisi. PUV6a main'e girince küçük bir "açılış ölçümü" paketiyle kapatılacak; o zamana kadar adlar yalnız bayrak açıkken yazılır.
- Ollama'nın uçtan uca ürün koşusu (bayraklar açık): PUV6a main'e girince ana oturum kuyruğa koyar (2 saatten uzun).
- Gece koşusu (HZ-0 + ÖLÇ-1; A-26) ve KIMLIK'in kalan 35 çifti: Berke'nin izniyle.
- Push: oturum sonunda sorulur.
- **Disk temizliği (08:15–08:40; Berke: "100 GB kadarını sil" → liste sunuldu → "onları sil, gerisi kalsın şimdilik"):** kullanılan alan 774,2 → **698,4 GB** (75,8 GB açıldı; boş 267,7 GB). Ölçüm `diskutil` + `~/.claude/scripts/disk/tara.py`. 13 Ekim'den beri büyüme: `~/karadul_olcum` +103 GB (her onarım paketi 119 ikilinin çalışma alanlarını saklamış), `~/HRMA-wt` +69, `~/HRMA-calisma` +43, `~/Library` +51.
  - Silinen (Berke'nin onayıyla): **A** `~/karadul_olcum/runs/onarim-2026-11-18/{P-S3,P12a,P12b,P13a,P13b,P15b,P15c,P16a,P16b,P16c,P07,P-S1,P-S2}` ve `onarim-2026-11-19/{P12c,P-S4,P16d}` (main'e girmiş paketlerin koşu çıktıları; sayıları raporlarda); **C** 72 eski ajan / doğrulama worktree'si (77 dalın hepsi duruyor; kalan ağaçlar: bugünkü dört ajan + P12d `agent-a733cb2eb8bc2b9fd`); **D** HRMA `v307/` altı onarım ağacı; **E** HRMA `v306-bakim` + `yayin/3.0.7-paket` (dallar ve `v3.0.7` etiketi duruyor); **H** Homebrew indirme önbelleği.
  - Kalan, karar bekleyen: **B** `~/karadul_olcum/ozkod_nufus/runs` 8,7 GB (kör nüfus önbelleği); **F** HRMA harita indirilenleri 10,4 GB; **G** HRMA eski çalışma dizinleri 15,7 GB; **I** Claude masaüstü `vm_bundles` 12,2 GB.
  - Saklananlar (bekleyen işler okuyor): `onarim-2026-11-18/{P-S3b,P10,P00,ana,…}`, `onarim-2026-11-19/{P12d,P18,OLCUM}`, `urun-onarim-a62f15e`, `urun-yeni2-f30ac9a`, `urun-yeni-93a2956` (yerleşim betikleri), `dalga0-2026-11-20`, `arge-2026-11-19`, `gosteri-2026-11-19`.
  - Doğrulama ağaçları (`dogrulama-d0`, `-d0b`, `-aksam`) silindi; bağımsız doğrulama için yenisi açılacak.
  - Ders: koşu çıktısı üreten paketin metnine "main'e girince çalışma alanlarını sil, yalnız ölçüm özetini sakla" satırı yazılacak.
