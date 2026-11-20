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
| 5 PE iskeleti | bekliyor | — |
| 6 Sağlamlık | bekliyor | — |
| 7 `python -m … goruntu` özeti | **bitti** | `f97054c` |
| Kabul / test / mutasyon / tam takım | bekliyor | — |

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
