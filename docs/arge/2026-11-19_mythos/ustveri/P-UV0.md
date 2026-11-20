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
| 2 Mach-O 64 | bekliyor | — |
| 3 Evrensel dosya | bekliyor | — |
| 4 ELF 64 | bekliyor | — |
| 5 PE iskeleti | bekliyor | — |
| 6 Sağlamlık | bekliyor | — |
| 7 `python -m … goruntu` özeti | bekliyor | — |
| Kabul / test / mutasyon / tam takım | bekliyor | — |

## Arayüz (kalem 1) — `b049837`

**ARAYÜZ COMMIT'İ: `b049837`** (dal `worktree-agent-ad5317ce5403117ed`; okumak için `git show b049837:karadul/analyzers/ustveri/goruntu.py`).

- `from karadul.analyzers.ustveri.goruntu import Goruntu, Bag, Bolum, Sembol, BellekGoruntu, ac, baytlardan, GoruntuHatasi`.
- `Goruntu` (soyut): `oku(adres, n) -> bytes | None`, `u8/u16/u32/i32/u64(adres) -> int | None`, `sozcuk(adres)` (gösterici boyutunda ham), `cstr(adres, azami=4096) -> str | None`, `gosterici(adres) -> int | Bag | None`, `bolumler` (özellik; `Bolum(ad, adres, boyut, kod, bolut, dosya_ofseti)`), `bolum_adli(ad)` (`"__objc_classlist"` ya da `"__DATA_CONST,__objc_classlist"`), `bolumler_adli(ad)`, `kod_bolumleri`, `adres_bolumu(adres)`, `kod_mu(adres)`, `bolum_baytlari(bolum)`, `fonksiyon_baslangiclari() -> list[int] | None`, `semboller() -> list[Sembol(ad, adres, tur, disa_acik, boyut, tablo)]`, `giris_adresi`, `mimari`, `gosterici_boyutu`, `bicim` (`macho` / `elf` / `pe`), `durum` (kısım → `{"durum", "neden"}`), `ozet()`.
- `Bag(ad, ek=0)` donmuş veri sınıfı (eşitlik `ad` + `ek`). Mach-O'da `ad` baştaki `_` ile (`_OBJC_CLASS_$_NSObject`).
- `gosterici`: düzeltme yeri yeniden konumlamaysa hedef `int` (Mach-O biçim 6'da görüntü tabanı eklenmiş, `high8` 56. bite konmuş), bağsa `Bag`, düzeltme yeri değilse ham sözcük; 0 ya da okunamaz → `None`.
- Sentetik test için: `BellekGoruntu([(ad, adres, veri, kod, bolut), …], yeniden_konumlamalar={adres: hedef}, baglar={adres: Bag(..)}, semboller=[…], fonksiyon_baslangiclari=[…], giris_adresi=…, mimari=…, gosterici_boyutu=8, bicim="macho")`.
- `ac(yol, dilim=None)` / `baytlardan(veri, dilim=None)`: evrensel dosyada `dilim` zorunlu; tanınmayan biçim `GoruntuHatasi(durum="desteklenmiyor")`. (Biçim uygulamaları kalem 2–5 commit'lerinde.)
