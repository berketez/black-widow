# P-ÜV0 — ikili görüntü okuyucu (`Goruntu`) — ilerleme

- Paket metni: `docs/arge/2026-11-20_dalga0/gonderim/PUV0.md`; plan: `docs/arge/2026-11-19_mythos/ustveri/PLAN.md` "P-ÜV0".
- Taban: main `3eb32df` (ileri sarıldı, 2026-11-20 10:46). `karadul.__file__` worktree yolunu gösteriyor.
- Geçici dosyalar: `~/karadul_olcum/runs/dalga0-2026-11-20/PUV0/`.
- Sert son: 15:15.

## Durum

| Kalem | Durum | Commit |
|---|---|---|
| Ön kayıt | yazıldı | `6dab07b` |
| 1 Arayüz (`Goruntu`, `Bag`) | **bitti** (P-ÜV1 / P-ÜV2 buna yaslanır) | `b049837` |
| 2 Mach-O 64 | **bitti** | `f97054c` |
| 3 Evrensel dosya | **bitti** | `f97054c` |
| 4 ELF 64 | **bitti** | `d3a940a` |
| 5 PE iskeleti | **bitti** | `0a3a122` |
| 6 Sağlamlık | **bitti** | `6e7f0d8` (+ `adec5c5`) |
| 7 `python -m … goruntu` özeti | **bitti** | `f97054c` |
| Kabul / test / mutasyon / tam takım | H1–H4 tuttu; 41 test; 17 / 17 mutant; tam takım: 7 kalan, hepsi worktree'de olmayan çalışma verisinden (bağla 7 / 7 geçti) | `fd7ccd3`, `5a0041f`, son commit |

## Arayüz (kalem 1) — `b049837`

**ARAYÜZ COMMIT'İ: `b049837`** (dal `worktree-agent-ad5317ce5403117ed`; okumak için `git show b049837:karadul/analyzers/ustveri/goruntu.py`).

- `from karadul.analyzers.ustveri.goruntu import Goruntu, Bag, Bolum, Sembol, BellekGoruntu, ac, baytlardan, GoruntuHatasi`.
- `Goruntu` (soyut): `oku(adres, n) -> bytes | None`, `u8/u16/u32/i32/u64(adres) -> int | None`, `sozcuk(adres)` (gösterici boyutunda ham), `cstr(adres, azami=4096) -> str | None`, `gosterici(adres) -> int | Bag | None`, `bolumler` (özellik; `Bolum(ad, adres, boyut, kod, bolut, dosya_ofseti)`), `bolum_adli(ad)` (`"__objc_classlist"` ya da `"__DATA_CONST,__objc_classlist"`), `bolumler_adli(ad)`, `kod_bolumleri`, `adres_bolumu(adres)`, `kod_mu(adres)`, `bolum_baytlari(bolum)`, `fonksiyon_baslangiclari() -> list[int] | None`, `semboller() -> list[Sembol(ad, adres, tur, disa_acik, boyut, tablo)]`, `giris_adresi`, `mimari`, `gosterici_boyutu`, `bicim` (`macho` / `elf` / `pe`), `durum` (kısım → `{"durum", "neden"}`), `ozet()`.
- `Bag(ad, ek=0)` donmuş veri sınıfı (eşitlik `ad` + `ek`). Mach-O'da `ad` baştaki `_` ile (`_OBJC_CLASS_$_NSObject`).
- `gosterici`: düzeltme yeri yeniden konumlamaysa hedef `int` (Mach-O biçim 6'da görüntü tabanı eklenmiş, `high8` 56. bite konmuş), bağsa `Bag`, düzeltme yeri değilse ham sözcük; 0 ya da okunamaz → `None`.
- Sentetik test için: `BellekGoruntu([(ad, adres, veri, kod, bolut), …], yeniden_konumlamalar={adres: hedef}, baglar={adres: Bag(..)}, semboller=[…], fonksiyon_baslangiclari=[…], giris_adresi=…, mimari=…, gosterici_boyutu=8, bicim="macho")`.
- `ac(yol, dilim=None)` / `baytlardan(veri, dilim=None)`: evrensel dosyada `dilim` zorunlu; tanınmayan biçim `GoruntuHatasi(durum="desteklenmiyor")`. (Biçim uygulamaları kalem 2–5 commit'lerinde.)

## Kalem 2, 3, 7 — Mach-O 64, evrensel dosya, özet girdisi — `f97054c`

- `MachO64Goruntu` (`karadul/analyzers/ustveri/goruntu.py`): yük komutları (sınır denetimli; kesikte durur, `durum.baslik = hata`), bölüt / bölüm (kod = `S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS`; sıfır dolgulu bölümde `dosya_ofseti = None`), `LC_SYMTAB` (stab dahil bütün girdiler; tür `kod` / `veri` / `tanimsiz` / `mutlak` / `hata_ayiklama` / `diger`), `LC_MAIN` (yoksa `LC_UNIXTHREAD` pc; tür denetimli), `LC_FUNCTION_STARTS`, `LC_DYLD_CHAINED_FIXUPS` (biçim 2 / 6; ilk istekte kurulur; adım sınırı bölüt boyu / 4), `LC_DYLD_INFO` bağ / zayıf bağ / tembel bağ işlem kodları (`gosterici` bunları da `Bag` olarak verir; Rectangle'da P-ÜV2 kalem 6 için).
- arm64e (biçim 1) ve çok başlangıçlı sayfa: istisna yok; `durum.duzeltme = desteklenmiyor` + neden; o aralıktaki adreste `gosterici` `None` (ham sözcük kodlu olduğundan yanıltırdı).
- Evrensel dosya: `ac(yol, dilim)`; dilim yoksa `GoruntuHatasi`. Dilim adı ürünün `karadul.analyzers.macho._fat_arch_name`'i (ürünün `raw/<ad>_<mimari>` adıyla aynı); `urun_dilimi(veri)` ürünün `select_fat_slice` seçimini verir.
- Özet: `PYTHONDONTWRITEBYTECODE=1 python -m karadul.analyzers.ustveri.goruntu <ikili> [--dilim arm64]` (evrensel dosyada `--dilim` verilmezse her dilim).

### Kabul (ölçüm: `~/karadul_olcum/runs/dalga0-2026-11-20/PUV0/kabul_macho.py` → `kabul_macho.json`)

**H1: 19 / 19 dilimde altı alan (`LC_FUNCTION_STARTS`, `sembol`, `duzeltme_yeri`, `yeniden_konumlama`, `ice_aktarim`, `giris`) başvuruyla aynı → TUTTU** (ön kayıt notu 1: plan 18 diyordu, envanterde 19 dilim var; 19'u da sayıldı). Dilim başına süre 0,00–1,95 sn (yük altında; iTerm2 x86_64 en uzun).

| İkili | Dilim | Başlangıç | Sembol | Düzeltme | Yeniden konumlama | İçe aktarım | Giriş |
|---|---|---|---|---|---|---|---|
| Ollama | arm64 | 12 952 | 899 | 54 161 | 53 480 | 352 | 0x100081fb0 |
| limactl | arm64 | 40 917 | 812 | 176 519 | 176 034 | 368 | 0x10008cd90 |
| iTerm2 | arm64 | 109 608 | 815 811 | 297 272 | 228 652 | 4 539 | 0x10013df74 |
| gh | arm64 | yok | 147 | 0 (zincirli değil) | 0 | 0 | 0x100089440 |

(19 dilimin tamamı `kabul_macho.json`'da; hepsinde fark 0.)

**H2 → TUTTU.** Ollama arm64: `__DATA_CONST,__objc_classlist`'in ilk girdisi için `gosterici()` = `0x1018d6598`, `__DATA,__objc_data` bölümünde (yerel adres); `__DATA_CONST,__got` 293 girdinin 293'ü `Bag` (ilk üçü `___objc_personality_v0`, `_class_addMethod`, `_class_addProtocol`).

Ek (ön kayıtta yoktu, bilgi): Rectangle (`LC_DYLD_INFO`) bağ işlem kodlarından arm64 2 911, x86_64 2 739 bağ yeri; `__got` 161 / 251 girdinin 123 / 200'ü `Bag`. Bağımsız sayımla karşılaştırılmadı (P-ÜV2 kalem 6 doğrular).

## Kalem 4 — ELF 64 — `d3a940a`

- `ElfGoruntu`: `PT_LOAD` eşlemesi (adres okuma yalnız yüklenen baytlardan), bölüm başlıkları (`e_shnum = 0` / `SHN_XINDEX` genişletilmiş numaralama), `SHF_ALLOC` olmayan bölüm `Bolum.bellekte = False` (adres içermez; `bolum_baytlari` dosyadaki yerinden okur), `.symtab` + `.dynsym` (0. boş girdi hariç), giriş `e_entry`, mimari `arm64` / `x86_64` (Mach-O adlarıyla aynı).
- Yeniden konumlama `gosterici()` içinde: yüklenen `SHT_RELA` / `SHT_REL` / `SHT_RELR`; `R_*_RELATIVE` → RELA'da ek alanı (dosyadaki sözcük değil), REL / RELR'de dosyadaki sözcük; `GLOB_DAT` / `JUMP_SLOT` / `ABS64` → sembol tanımsızsa `Bag(ad, ek)`, tanımlıysa `S + A`; `IRELATIVE` ve bilinmeyen tür → `None` (statik çözülemez; sayaçta).
- Fonksiyon başlangıcı: `.eh_frame` FDE `pc_begin` (CIE `zR` kodlaması; `pcrel` / mutlak; dolaylı, `datarel` vb. → durum `hata` + neden); `.eh_frame` yoksa `None`.

### Kabul (H3; ölçüm: `~/karadul_olcum/runs/dalga0-2026-11-20/PUV0/kabul_elf.py` → `kabul_elf.json`)

**H3: 5 / 5 ELF'te bölüm başlığı sayısı, bölüm adları (sırasıyla) ve sembol sayısı `pyelftools` bağımsız sayımıyla aynı → TUTTU.** `R_*_RELATIVE` sayıları da 5 / 5 aynı (hiçbirinde `SHT_RELR` yok). Ek bilgi (ön kayıtta yoktu): FDE başlangıç sayısı `pyelftools` `EH_CFI_entries` ile 5 / 5 aynı.

| İkili | sha256 | Bölüm başlığı (biz / pyelftools) | Sembol | R_*_RELATIVE | FDE başlangıcı | Bağ (tanımsız sembol) | Fark |
|---|---|---|---|---|---|---|---|
| coreutils/cat | `0d5a5dd543ed` | 29 / 29 | 80 / 80 | 45 / 45 | 107 / 107 | 73 | aynı |
| coreutils/expr | `56ae85a0c61b` | 29 / 29 | 84 / 84 | 34 / 34 | 112 / 112 | 77 | aynı |
| coreutils/ls | `0c062cc32ec1` | 29 / 29 | 139 / 139 | 218 / 218 | 318 / 318 | 133 | aynı |
| tree/tree | `62810aca2954` | 28 / 28 | 72 / 72 | 422 / 422 | 116 / 116 | 72 | aynı |
| zstd/pzstd | `77866a8bf262` | 31 / 31 | 113 / 113 | 111 / 111 | 858 / 858 | 129 | aynı |

## Kalem 5 — PE iskeleti — `0a3a122`

- `PeGoruntu`: DOS / COFF / isteğe bağlı başlık (PE32 ve PE32+), bölüm tablosu (uzun ad COFF dizgi tablosundan), başlık + bölüm eşlemesi, `gosterici`: IAT yuvası → `Bag(ad)` (sıra numarasıyla aktarımda `kitaplık#n`), öbür yerde mutlak sözcük (görüntü tabanı dosyada yazılı; taban yeniden konumlaması uygulanmaz: tercih edilen taban); `.pdata` başlangıçları (x86_64 12, arm64 8 baytlık kayıt); COFF sembolleri; tanımlayıcı / thunk üst sınırı 100 000.
- Yerel denetim (kabul değil; depoya girmez): anaconda'daki 6 distlib başlatıcısında (`t32/t64/t64-arm/w32/w64/w64-arm.exe`) bölüm adları + adresleri, giriş, IAT bağları `pefile` ile 6 / 6 aynı (85–94 bağ); x86_64 `.pdata` 240 / 240 ve 235 / 235 aynı; arm64 `.pdata` `pefile` okumadığı için karşılaştırılmadı. Çıktı `~/karadul_olcum/runs/dalga0-2026-11-20/PUV0/pe_yerel.json`.
- Go PE ve MSVC RTTI kabulü P-ÜV9'da (planda öyle).

## Kalem 6 — sağlamlık — `6e7f0d8`, `adec5c5`

- Bütün yük komutu / bölüm / sembol / tablo okumaları sınır denetimli; kesik ya da bozuk kısım `None` / boş + `durum[kısım] = hata` + neden; istisna yalnız görüntü kurulamazsa `GoruntuHatasi` (tanınmayan imza, evrensel dosyada dilim yok).
- Sonsuz döngü koruması: zincir yürüyüşü bölüt başına adım sınırı (bölüt boyu / 4); `LC_DYLD_INFO` bağ yeri sınırı min(2^22, bölüt boyları / 8); PE thunk / tanımlayıcı sınırı; `.eh_frame` kaydı her adımda ilerler.
- Bozuk zincirli düzeltme ya da bozuk bağ işlem kodu: yarım sözlük atılır; zincirli görüntüde `gosterici` hep `None` (dosyadaki sözcükler kodlu, ham değer yanıltır).
- Bellek: dosya tek `bytes`; zincirli düzeltme sözlüğü, semboller, fonksiyon başlangıçları, yeniden konumlamalar ilk istekte kurulur.

### H4 (ölçüm: `kabul_kesik.py` → `kabul_kesik.json`)

**H4: 24 kesik girdide (19 Mach-O dilimi + 5 ELF, her birinin ilk 4 096 baytı) istisna 0 → TUTTU.** Bütün girdilerde görüntü kuruldu; kısımların durumu `hata` / `veri_yok` (ör. Ollama arm64: başlık `hata`, sembol `hata`, düzeltme `hata`, fonksiyon başlangıcı `veri_yok`).

## Testler ve mutasyon — `adec5c5`, `fead983`, `0a3a122`, `6e7f0d8`, `fd7ccd3`

- `tests/test_puv0_goruntu.py`: **40 test** (hepsi sentetik `struct.pack`; gerçek ikiliye bağlı test yok): arayüz (soyut sınıf, `Bag` eşitliği, `BellekGoruntu`, `cstr`, ULEB/SLEB), Mach-O (tek zincir: iki yeniden konumlama + bir bağ; biçim 2 / 6; arm64e ve çok başlangıçlı sayfa `desteklenmiyor`; ULEB fonksiyon başlangıcı; semboller; `LC_DYLD_INFO` bağı ve sayaç sınırı; dosya dışına taşan zincir), evrensel dosya (dilim zorunlu, ürün dilimi, ince dosyada yanlış dilim, `ac` + CLI), ELF (`R_AARCH64_RELATIVE` ek alanından, `GLOB_DAT` → `Bag`, REL / RELR örtük ek, semboller, `.eh_frame`, 32 bit desteklenmiyor), PE (iskelet, mutlak gösterici + IAT bağı, `.pdata`), sağlamlık (5 görüntü × 15 kesim noktası, 5 görüntü × 150 belirlenimci rastgele bozma, bozuk yük komutu, tanınmayan biçim). Sentetik ELF ve PE ayrıca `pyelftools` / `pefile` ile okunup kurgunun geçerli olduğu denetlendi.
- `scripts/measurement/mutation_specs_puv0.json`: **16 mutant, 16 öldü** (planın 6'sı: `high8` kaydırması, biçim 6 tabanı, sonraki × 8, ULEB devam biti, RELA ek alanı, bağ biti; ek 10: `LC_FUNCTION_STARTS` tabanı, içe aktarım ad kayması, desteklenmeyen aralıkta ham sözcük, bozuk zincirde ham sözcük, yüklenmeyen bölüm adres içerir, eh_frame pcrel, `GLOB_DAT` bağı, RELR bit kayması, PE ILT/IAT, evrensel dosyada dilim zorunluluğu). İlk koşuda RELR mutantı hayatta kaldı (RELR'de hedef = dosyadaki sözcük; yalnız değere bakan test yeri ayırt edemiyordu); teste yer kümesi eklendi, sonra öldü. Günlük: `~/karadul_olcum/runs/dalga0-2026-11-20/PUV0/mutasyon.log`; koşum sonrası `git diff` temiz.

## Arayüz eklemeleri (b049837'den sonra; geriye uyumlu)

- `Bolum.bellekte: bool = True` (sona eklendi; ELF'te `SHF_ALLOC` olmayan bölüm `False`, adres içermez).
- Dosya görüntülerinde `bolum_baytlari(bolum)` bölümü dosyadaki yerinden okur (yüklenmeyen bölüm dahil).
- Biçime özgü yardımcılar: Mach-O `duzeltmeler()`, `ice_aktarimlar()`, `dyld_info_baglari()`, `goruntu_tabani`, `bolutler`, `bolut_adli()`, `kitapliklar`; ELF `yeniden_konumlamalar()`; PE `ice_aktarim_baglari()`, `goruntu_tabani`; modül düzeyinde `dilimler(veri)`, `urun_dilimi(veri)`, `uleb128`, `sleb128`, `ozet_cikar`.
- `karadul.analyzers.ustveri` paketi adları tembel yükler (`python -m …goruntu` runpy uyarısı vermesin diye); `from karadul.analyzers.ustveri import Goruntu, Bag` çalışır.

## Ek onarım — okunamayan ad uydurulmaz — `5a0041f`

- Zincirli içe aktarımın adı okunamazsa (ad ofseti tablo dışında, sıkıştırılmış sembol biçimi) önceki sürüm `Bag("#n")`, PE'de `"#i"` / `"kitaplık#?"` yer tutucusu veriyordu; yer tutucu sembol adı gibi aşağı akışa geçebilirdi. Artık ad `None`, `gosterici` o yerde `None`; PE'de adı okunamayan thunk bağ olarak yazılmaz. Sıkıştırılmış sembol biçiminin `desteklenmiyor` durumu zincir okumasının sonunda ezilmiyor.
- Gerçek 19 dilimde 12 274 içe aktarımın 0'ı adsız; bütün bağ yerleri `Bag` döndürüyor (değişiklik gerçek veride sonucu değiştirmedi). H1 19 / 19, H3 5 / 5, H4 istisna 0, PE yerel denetimi yeniden koşuldu: aynı.
- Test 41; mutant 17 (yeni: adı okunamayan içe aktarım yine `Bag` döner).

## Tam takım (yük altında; `uptime` 11:17 yük ortalaması 11,99 / 8,76 / 7,44)

`PYTHONDONTWRITEBYTECODE=1 python -m pytest -q -p no:cacheprovider` (worktree kökü; günlük `~/karadul_olcum/runs/dalga0-2026-11-20/PUV0/tam_takim.log`): **7 kaldı / 10 494 geçti / 81 atlandı / 152 seçilmedi, 368,9 sn.**

- 7 kalanın hepsi worktree'de olmayan, git'in izlemediği çalışma verisinden: `scripts/node_modules` (`@babel/parser` yok: `test_deobfuscator` ×2, `test_pipeline::test_identify_and_static`, `test_project_reconstructor::test_reconstruct_with_explicit_modules_dir`) ve `vendor/gnulib-ref` (`test_ps3b_full_write`, `test_ps3b_gnulib_varlik`, `test_ps3b_ic_ad`). İki bağ (`vendor`, `scripts/node_modules` → ana ağaç) kurulup bu 7 test yeniden koşuldu: **7 / 7 geçti**; bağlar sonra kaldırıldı (commit'lenmedi). Bu paketin değişikliğiyle ilgisiz: paket yalnız yeni dosya ekliyor; `karadul/` ve `tests/` altında `karadul.analyzers.ustveri`'yi kendi testi dışında içe aktaran dosya yok.
- Tam takım `5a0041f`'ten (ad uydurma onarımı) önce başladı; o commit yalnız `goruntu.py` + `tests/test_puv0_goruntu.py`'yi değiştirdi, ikincisi sonra ayrıca koşuldu (41 geçti).
- Mutasyon (tam takım bittikten sonra, tek koşu): **17 / 17 öldü**, `git diff` temiz.

## Riskler / açık noktalar

- Plan "18 dilim" diyor; `envanter.json`'da 19 dilim var (ön kayıt notu 1). 19'u da aynı.
- `LC_DYLD_INFO` bağları (Rectangle, gh, docker-cli, docker-compose) bağımsız bir sayımla karşılaştırılmadı; P-ÜV2 kalem 6 Rectangle'da doğrulayacak.
- PE: Go PE ve MSVC RTTI kabulü P-ÜV9'da; arm64 `.pdata` `pefile` okumadığı için karşılaştırılmadı. PE'de taban yeniden konumlaması (`.reloc`) uygulanmaz (tercih edilen taban varsayılır; dosyadaki mutlak değer zaten o tabana göre).
- ELF: `IRELATIVE` ve tanımadığı yeniden konumlama türleri `gosterici`'de `None` (sayaçta); `.eh_frame`'de `datarel` / dolaylı kodlama `hata` durumu verir (5 Debian ELF'te görülmedi). Yalnız 64 bit ELF ve 64 bit Mach-O (32 bit: `desteklenmiyor`).
- Evrensel dosyada `ac()` bütün dosyayı belleğe okur, sonra dilimi kopyalar (iTerm2 140 MB). Ürün ince dilimi (`raw/<ad>_<mimari>`) kullandığından ürün yolunda bu olmaz.
- Süreler yük altında ölçüldü (dilim başına 0,00–1,95 sn); boş makine ölçümü yapılmadı.

## PAKET BİTTİ
